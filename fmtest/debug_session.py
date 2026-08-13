"""Optional logd / miglogd debug collector.

This is **supplemental diagnostic evidence only**. Debug output is never treated
as proof that FortiManager transmitted a packet, and a test can succeed with no
debug evidence at all: the collector records DEBUG observations into their own
queue, and the correlator keeps them strictly separate from the sniffer verdict.

The session runs concurrently for the whole test. ``debug.cleanup_commands``
always run at shutdown so device-side debugging is never left enabled, even if
the run ends badly.
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime
from typing import List, Optional

from .config import CorrelationConfig, DebugConfig
from .events import EventTracker, Source
from .logbus import LogBus
from .shell import strip_ansi


class DebugCollector:
    """Runs a dedicated debug session and records matching debug lines."""

    def __init__(
        self,
        config: DebugConfig,
        correlation: CorrelationConfig,
        tracker: EventTracker,
        logbus: LogBus,
        gateway,
        command_timeout: float = 15.0,
        diagnostics=None,
    ) -> None:
        self._config = config
        self._tracker = tracker
        self._log = logbus
        self._gateway = gateway
        self._diagnostics = diagnostics
        self._session_name = config.session_name
        self._command_timeout = command_timeout
        self._session = None
        self._line_buffer = ""

        # Default to the expected event message when no patterns are configured,
        # so the debug stream is still searched for something meaningful.
        patterns = config.match_patterns or [correlation.expected_message]
        self._patterns = [p for p in patterns if p]
        if correlation.pattern_is_regex:
            self._regexes: List[re.Pattern[str]] = [
                re.compile(p, re.IGNORECASE) for p in self._patterns
            ]
        else:
            self._regexes = []
        self._needles = [p.lower() for p in self._patterns]

        self.healthy = False
        self.started = False
        self.lines_seen = 0
        self.matches = 0
        self.last_error: Optional[str] = None

    @property
    def session_name(self) -> str:
        return self._session_name

    # -- lifecycle ----------------------------------------------------------

    async def start(self) -> bool:
        try:
            self._session = await self._gateway.open_session(self._session_name)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
            self._log.log(
                Source.DEBUG,
                f"could not open debug session: {self.last_error}. "
                f"The test continues; debug evidence is optional.",
            )
            return False

        shell = self._session.shell
        for command in self._config.setup_commands:
            self._log.log(Source.DEBUG, f"setup: {command}")
            try:
                result = await shell.run(command, timeout=self._command_timeout)
            except Exception as exc:
                self.last_error = f"{type(exc).__name__}: {exc}"
                self._log.log(Source.DEBUG, f"setup failed on {command!r}: {self.last_error}")
                return False
            if result.output.strip():
                self._log.log_block(Source.DEBUG, result.output, prefix="| ")
            if result.timed_out:
                # "diagnose debug enable" starts streaming immediately, so the
                # prompt may never come back. That is expected, not an error.
                self._log.log(
                    Source.DEBUG,
                    f"no prompt after {command!r}; assuming the debug stream has started",
                )
                break

        self.healthy = True
        self.started = True
        return True

    async def run(self) -> None:
        if self._session is None:
            return
        try:
            await self._session.shell.stream(
                on_chunk=self._on_chunk, on_idle=None, idle_timeout=0.5
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
            self._log.log(Source.DEBUG, f"stream error: {self.last_error}")
        finally:
            self._flush_partial()
            if self.healthy and self._session is not None and self._session.shell.closed:
                self.healthy = False
                self._log.log(Source.DEBUG, "debug session closed")

    async def stop(self) -> None:
        """Always turn device-side debugging off again, then close the session."""
        if self._session is None:
            return
        shell = self._session.shell
        self._flush_partial()

        if not shell.closed:
            try:
                # Interrupt the debug stream so the CLI accepts commands again.
                await asyncio.wait_for(shell.send_interrupt(), timeout=3.0)
                await asyncio.sleep(0.3)
                await shell.drain(settle_seconds=0.3)
            except (asyncio.TimeoutError, Exception):
                pass

            for command in self._config.cleanup_commands:
                self._log.log(Source.DEBUG, f"cleanup: {command}")
                try:
                    result = await asyncio.wait_for(
                        shell.run(command, timeout=self._command_timeout),
                        timeout=self._command_timeout + 5.0,
                    )
                except (asyncio.TimeoutError, Exception) as exc:
                    self._log.log(
                        Source.DEBUG,
                        f"cleanup command {command!r} failed "
                        f"({type(exc).__name__}: {exc}); "
                        f"CHECK THE DEVICE: debugging may still be enabled",
                    )
                    continue
                if result.timed_out:
                    self._log.log(
                        Source.DEBUG,
                        f"cleanup command {command!r} did not return a prompt; "
                        f"CHECK THE DEVICE: debugging may still be enabled",
                    )
                elif result.output.strip():
                    self._log.log_block(Source.DEBUG, result.output, prefix="| ")

        try:
            await asyncio.wait_for(self._session.close(), timeout=8.0)
        except (asyncio.TimeoutError, Exception):
            pass
        self.healthy = False
        self._log.log(
            Source.DEBUG,
            f"stopped after {self.lines_seen} line(s), {self.matches} match(es)",
        )

    # -- stream handling ----------------------------------------------------

    def _on_chunk(self, chunk: str) -> None:
        self._line_buffer += strip_ansi(chunk)
        while "\n" in self._line_buffer:
            line, _, self._line_buffer = self._line_buffer.partition("\n")
            self._handle_line(line.rstrip())

    def _flush_partial(self) -> None:
        if self._line_buffer.strip():
            self._handle_line(self._line_buffer.rstrip())
        self._line_buffer = ""

    def _matches(self, line: str) -> bool:
        if self._regexes:
            return any(r.search(line) for r in self._regexes)
        lowered = line.lower()
        return any(needle in lowered for needle in self._needles)

    def _handle_line(self, line: str) -> None:
        if not line.strip():
            return
        self.lines_seen += 1
        observed_at = datetime.now()

        if self._config.echo_to_log:
            self._log.log(Source.DEBUG, line, raw=True, timestamp=observed_at)

        matched = self._matches(line)
        if matched:
            self.matches += 1
            self._tracker.record(
                Source.DEBUG, observed_at, line, fields={"matched": True}
            )

        if self._diagnostics is not None:
            from .diagnostics import Candidate, Reason

            self._diagnostics.add_candidate(
                Candidate(
                    source=Source.DEBUG,
                    observed_at=observed_at,
                    summary=line[:160],
                    matched=matched,
                    code=Reason.MATCHED if matched else Reason.PATTERN_ABSENT,
                    detail=(
                        ""
                        if matched
                        else f"line does not contain any of {self._patterns!r}"
                    ),
                    excerpt=line[:300],
                    raw=line,
                )
            )
