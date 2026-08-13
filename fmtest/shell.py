"""Interactive shell wrapper for FortiManager CLI sessions.

FortiManager has no usable non-interactive ``exec`` channel: commands must be
typed into an interactive shell and the response read back until the prompt
returns. This module implements that pattern on top of an abstract transport,
so the same logic drives a real asyncssh session and the offline mock device.

Design notes:

* A background pump task continuously drains the transport into a queue. That
  keeps reads cancellation-safe, avoids losing output when a command times out,
  and gives Phase 2 a place to attach continuous stream consumers for the
  sniffer and debug sessions.
* The prompt is *learned* at connect time by sending a bare newline and taking
  the trailing line, which is far more reliable than guessing the shape of
  ``FMGVM01 #`` versus ``FMGVM01 (global) #``. The configured
  ``prompt_pattern`` regex is the fallback.
* CLI paging (``--More--``) would otherwise corrupt long output, so the reader
  answers pagers automatically while it waits for the prompt.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, List, Optional, Protocol

# ANSI escape sequences emitted by a vt100 session.
_ANSI_CSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_ANSI_OSC = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_ANSI_OTHER = re.compile(r"\x1b[@-Z\\-_]")

# Pager prompts seen on FortiOS / FortiManager consoles.
_PAGER_PATTERNS = (
    "--More--",
    "--more--",
    "(END)",
    "-- More --",
)


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences and normalise carriage returns."""
    text = _ANSI_OSC.sub("", text)
    text = _ANSI_CSI.sub("", text)
    text = _ANSI_OTHER.sub("", text)
    text = text.replace("\x00", "")
    # Some devices redraw lines with a bare CR; keep the final rendering.
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text


class ShellClosedError(Exception):
    """Raised when the underlying shell transport is gone."""


class ShellTransport(Protocol):
    """Minimal duplex character transport used by :class:`InteractiveShell`."""

    async def read(self) -> str:
        """Return the next chunk of output, or ``''`` at end of stream."""
        ...

    async def write(self, data: str) -> None: ...

    async def close(self) -> None: ...

    @property
    def closed(self) -> bool: ...


@dataclass
class CommandResult:
    """Outcome of one command executed in an interactive shell."""

    command: str
    output: str
    started_at: datetime
    finished_at: datetime
    timed_out: bool = False
    error: Optional[str] = None
    raw: str = field(default="", repr=False)

    @property
    def duration_ms(self) -> float:
        return round((self.finished_at - self.started_at).total_seconds() * 1000.0, 3)

    @property
    def ok(self) -> bool:
        return not self.timed_out and self.error is None

    def contains(self, needle: str, *, regex: bool = False) -> bool:
        if regex:
            return re.search(needle, self.output, re.IGNORECASE) is not None
        return needle.lower() in self.output.lower()


class InteractiveShell:
    """Send commands to an interactive CLI and read responses back."""

    def __init__(
        self,
        transport: ShellTransport,
        name: str = "shell",
        prompt_pattern: str = r"[\r\n][^\r\n]{0,80}?[#$]\s*$",
        read_chunk_timeout: float = 0.35,
        handle_pager: bool = True,
    ) -> None:
        self._transport = transport
        self.name = name
        self._prompt_regex = re.compile(prompt_pattern)
        self._read_chunk_timeout = read_chunk_timeout
        self._handle_pager = handle_pager

        self._queue: "asyncio.Queue[Optional[str]]" = asyncio.Queue()
        self._pump: Optional[asyncio.Task] = None
        self._eof = False
        self._pump_error: Optional[str] = None
        self._learned_prompt: Optional[str] = None
        self._lock = asyncio.Lock()
        self._stream_consumers: List[Callable[[str], None]] = []

    # -- lifecycle ----------------------------------------------------------

    def start(self) -> None:
        """Begin draining the transport in the background."""
        if self._pump is None or self._pump.done():
            self._pump = asyncio.get_running_loop().create_task(
                self._pump_loop(), name=f"shell-pump-{self.name}"
            )

    async def _pump_loop(self) -> None:
        try:
            while True:
                chunk = await self._transport.read()
                if chunk == "":
                    self._eof = True
                    await self._queue.put(None)
                    return
                await self._queue.put(chunk)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # transport-specific failures
            self._pump_error = f"{type(exc).__name__}: {exc}"
            self._eof = True
            await self._queue.put(None)

    async def aclose(self) -> None:
        if self._pump is not None:
            self._pump.cancel()
            try:
                await self._pump
            except (asyncio.CancelledError, Exception):
                pass
            self._pump = None
        try:
            await self._transport.close()
        except Exception:
            pass

    @property
    def closed(self) -> bool:
        return self._eof or self._transport.closed

    @property
    def error(self) -> Optional[str]:
        return self._pump_error

    @property
    def lock(self) -> asyncio.Lock:
        """Serialises command execution when several producers share a shell."""
        return self._lock

    @property
    def prompt(self) -> Optional[str]:
        return self._learned_prompt

    # -- streaming ----------------------------------------------------------

    def add_stream_consumer(self, callback: Callable[[str], None]) -> None:
        """Register a callback fed with every chunk read from the device.

        Used by the Phase 2 sniffer and debug collectors, which consume a
        continuous stream rather than discrete command responses.
        """
        self._stream_consumers.append(callback)

    def _publish(self, chunk: str) -> None:
        for consumer in self._stream_consumers:
            try:
                consumer(chunk)
            except Exception:
                # A misbehaving consumer must not break the shell.
                pass

    # -- low level reads ----------------------------------------------------

    async def _next_chunk(self, timeout: float) -> Optional[str]:
        try:
            chunk = await asyncio.wait_for(self._queue.get(), timeout)
        except asyncio.TimeoutError:
            return None
        if chunk is None:
            self._eof = True
            return None
        self._publish(chunk)
        return chunk

    async def drain(self, settle_seconds: float = 0.2) -> str:
        """Consume and return any output already buffered."""
        collected: List[str] = []
        while True:
            chunk = await self._next_chunk(settle_seconds)
            if chunk is None:
                break
            collected.append(chunk)
        return "".join(collected)

    async def write_raw(self, data: str) -> None:
        if self.closed:
            raise ShellClosedError(f"shell {self.name} is closed")
        await self._transport.write(data)

    async def send_line(self, line: str) -> None:
        await self.write_raw(line + "\n")

    async def stream(
        self,
        on_chunk: Callable[[str], None],
        on_idle: Optional[Callable[[], None]] = None,
        idle_timeout: float = 0.3,
    ) -> None:
        """Continuously deliver device output until the shell closes.

        Used by the sniffer and debug collectors, which consume an open-ended
        stream rather than discrete command responses. ``on_idle`` fires every
        ``idle_timeout`` seconds with no output, which is how the sniffer parser
        knows a packet block has finished.
        """
        while not self.closed:
            chunk = await self._next_chunk(idle_timeout)
            if chunk is None:
                if self.closed:
                    return
                if on_idle is not None:
                    on_idle()
                continue
            on_chunk(chunk)

    async def send_interrupt(self) -> None:
        """Send Ctrl+C, which is how FortiOS stops a running sniffer."""
        await self.write_raw("\x03")

    # -- prompt handling ----------------------------------------------------

    def _looks_like_prompt(self, text: str) -> bool:
        tail = text.rstrip()
        if not tail:
            return False
        if self._learned_prompt and tail.endswith(self._learned_prompt):
            return True
        return self._prompt_regex.search(text) is not None

    @staticmethod
    def _ends_with_pager(text: str) -> bool:
        tail = text.rstrip()
        return any(tail.endswith(marker) for marker in _PAGER_PATTERNS)

    async def learn_prompt(self, timeout: float = 10.0) -> Optional[str]:
        """Discover the device prompt by pressing Enter and reading the echo."""
        await self.drain(settle_seconds=1.0)
        await self.write_raw("\n")
        deadline = asyncio.get_running_loop().time() + timeout
        buffer = ""
        while asyncio.get_running_loop().time() < deadline:
            chunk = await self._next_chunk(self._read_chunk_timeout)
            if chunk is None:
                if buffer.strip():
                    break
                if self.closed:
                    break
                continue
            buffer += chunk
            if self._prompt_regex.search(strip_ansi(buffer)):
                # Give the device a moment in case more of the prompt follows.
                extra = await self.drain(settle_seconds=0.2)
                buffer += extra
                break

        cleaned = strip_ansi(buffer)
        lines = [line.rstrip() for line in cleaned.split("\n") if line.strip()]
        if lines:
            candidate = lines[-1].strip()
            # A plausible prompt is short and ends with a shell sigil.
            if candidate and len(candidate) <= 100 and candidate[-1] in "#$>":
                self._learned_prompt = candidate
        return self._learned_prompt

    # -- command execution --------------------------------------------------

    async def run(
        self,
        command: str,
        timeout: float,
        *,
        started_at: Optional[datetime] = None,
    ) -> CommandResult:
        """Execute ``command`` and read output until the prompt returns.

        ``started_at`` lets the caller stamp the moment immediately before the
        command was issued, which is what the test event timeline needs.
        """
        if self.closed:
            now = datetime.now()
            return CommandResult(
                command=command,
                output="",
                started_at=started_at or now,
                finished_at=now,
                error=self._pump_error or "shell is closed",
            )

        # Discard anything left over from a previous timed-out command so it
        # cannot be misattributed to this one.
        leftover = await self.drain(settle_seconds=0.05)
        if leftover:
            self._publish("")  # no-op, keeps consumer contract simple

        begin = started_at or datetime.now()
        try:
            await self.send_line(command)
        except Exception as exc:
            now = datetime.now()
            return CommandResult(
                command=command,
                output="",
                started_at=begin,
                finished_at=now,
                error=f"write failed: {type(exc).__name__}: {exc}",
            )

        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        buffer = ""
        timed_out = False
        error: Optional[str] = None

        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                timed_out = True
                break
            chunk = await self._next_chunk(min(self._read_chunk_timeout, remaining))
            if chunk is None:
                if self.closed:
                    error = self._pump_error or "shell closed while awaiting response"
                    break
                # Idle tick: check whether what we have already ends at a prompt.
                if buffer and self._looks_like_prompt(strip_ansi(buffer)):
                    break
                continue
            buffer += chunk
            cleaned = buffer
            if self._handle_pager and self._ends_with_pager(strip_ansi(cleaned)):
                try:
                    await self.write_raw(" ")
                except Exception as exc:
                    error = f"pager handling failed: {type(exc).__name__}: {exc}"
                    break
                continue
            if self._looks_like_prompt(strip_ansi(buffer)):
                break

        finished = datetime.now()
        output = self._clean_output(buffer, command)
        return CommandResult(
            command=command,
            output=output,
            started_at=begin,
            finished_at=finished,
            timed_out=timed_out,
            error=error,
            raw=buffer,
        )

    def _clean_output(self, raw: str, command: str) -> str:
        """Strip escapes, the echoed command and the trailing prompt line."""
        text = strip_ansi(raw)
        lines = text.split("\n")

        # Drop the echoed command (possibly preceded by prompt text).
        while lines:
            first = lines[0].strip()
            if not first:
                lines.pop(0)
                continue
            if first == command or first.endswith(command):
                lines.pop(0)
                continue
            break

        # Drop the trailing prompt.
        while lines:
            last = lines[-1].strip()
            if not last:
                lines.pop()
                continue
            if self._learned_prompt and last == self._learned_prompt:
                lines.pop()
                continue
            if self._learned_prompt is None and self._prompt_regex.search("\n" + last):
                lines.pop()
                continue
            break

        # Remove pager artefacts left inside the body.
        cleaned_lines = []
        for line in lines:
            stripped = line.strip()
            if stripped in _PAGER_PATTERNS:
                continue
            cleaned_lines.append(line.rstrip())

        return "\n".join(cleaned_lines).strip("\n")
