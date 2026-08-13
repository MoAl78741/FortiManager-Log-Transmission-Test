"""In-process fake FortiManager, used by ``--mock``.

This exists so the whole pipeline -- config, concurrent sessions, command
groups, test event IDs, CLI detection, sniffer payload reassembly, debug
capture, correlation, tee logging, shutdown, reporting -- can be exercised end
to end without touching a production device, and so the tool can be smoke
tested before it is pointed at real hardware.

It implements the same :class:`~fmtest.shell.ShellTransport` protocol as the
asyncssh adapter, so nothing above the transport layer knows the difference.

The mock models the *device*, not just a session: a shared
:class:`MockDeviceState` links the sessions together, so running the test
command on the CLI session causes debug lines to appear on the debug session
and a packet to appear on the sniffer session -- exactly the coupling the
correlator is designed to test.

Failure injection:

    --mock-fail-rate 0.25    one in four test commands returns no success line
    --mock-hang-rate 0.10    one in ten test commands never responds
    --mock-drop-rate 0.20    one in five events is generated but never
                             transmitted (no packet reaches the sniffer)
"""

from __future__ import annotations

import asyncio
import random
import threading
from datetime import datetime
from typing import Callable, Dict, List, Optional

from .config import FortiManagerConfig
from .logbus import LogBus
from .shell import InteractiveShell

# A plausible IPv4 + UDP header for the synthetic syslog packet.
_FAKE_IP_UDP_HEADER = bytes.fromhex(
    "4500009100004000401100000a000a0a0a000add"
    "02020202007d0000"
)


def _hex_dump(payload: bytes) -> List[str]:
    """Render bytes the way the FortiOS sniffer does at verbosity 6.

    Sixteen bytes per line as eight 2-byte groups, a tab, then the ASCII
    column with non-printables shown as dots. The expected message therefore
    lands split across several lines and truncated in the ASCII column, which
    is precisely the case the parser has to survive.
    """
    lines: List[str] = []
    for offset in range(0, len(payload), 16):
        chunk = payload[offset : offset + 16]
        groups = [chunk[i : i + 2].hex() for i in range(0, len(chunk), 2)]
        hex_part = " ".join(groups)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"0x{offset:04x}\t {hex_part}\t{ascii_part}")
    return lines


class MockDeviceState:
    """Shared device state linking the CLI, sniffer and debug sessions."""

    def __init__(
        self,
        hostname: str,
        expected_message: str,
        drop_rate: float = 0.0,
        headers_only: bool = False,
        graylog_ingest_url: Optional[str] = None,
        rng: Optional[random.Random] = None,
    ) -> None:
        self.hostname = hostname
        self.expected_message = expected_message
        self.drop_rate = drop_rate
        self.headers_only = headers_only
        self.graylog_ingest_url = graylog_ingest_url
        self._rng = rng or random.Random()
        self._sniffer_sinks: List[Callable[[str], None]] = []
        self._debug_sinks: List[Callable[[str], None]] = []
        self.sequence = 0
        self.packets_emitted = 0
        self.packets_dropped = 0

    # -- subscriptions ------------------------------------------------------

    def attach_sniffer(self, sink: Callable[[str], None]) -> None:
        self._sniffer_sinks.append(sink)

    def attach_debug(self, sink: Callable[[str], None]) -> None:
        self._debug_sinks.append(sink)

    def detach(self, sink: Callable[[str], None]) -> None:
        for collection in (self._sniffer_sinks, self._debug_sinks):
            if sink in collection:
                collection.remove(sink)

    # -- event generation ---------------------------------------------------

    def _syslog_payload(self) -> bytes:
        now = datetime.now()
        text = (
            f'<134>date={now:%Y-%m-%d} time={now:%H:%M:%S} '
            f'devname="{self.hostname}" devid="FMVMELTM25001041" '
            f'logid="0100032003" type="event" subtype="system" level="notice" '
            f'seq={self.sequence} msg="{self.expected_message}"'
        )
        return text.encode("utf-8")

    def emit_event(self) -> None:
        """Called when the CLI test command runs: fan out debug and packet."""
        self.sequence += 1
        sequence = self.sequence

        for sink in list(self._debug_sinks):
            sink(f"logd: received local event log, seq={sequence}, len=214\n")
            sink(f'logd: msg="{self.expected_message}"\n')
            sink("logd: forwarding to syslog server 10.0.10.221:514\n")

        if not self._sniffer_sinks:
            return
        if self._rng.random() < self.drop_rate:
            # Generated but never transmitted: the exact fault being hunted.
            self.packets_dropped += 1
            for sink in list(self._debug_sinks):
                sink("logd: send failed, queue full\n")
            return

        self.packets_emitted += 1
        self._ingest_to_graylog(sequence)
        payload = _FAKE_IP_UDP_HEADER + self._syslog_payload()
        sequence_offset = self.sequence * 291
        now = datetime.now()
        header = (
            f"{now:%Y-%m-%d %H:%M:%S}.{now.microsecond:06d} port1 out "
            f"10.0.10.10.514 -> 10.0.10.221.514: udp {len(payload) - 28}"
        )
        if self.headers_only:
            # Reproduces a sniffer verbosity that prints packet headers but no
            # packet data, and no interface name.
            header = (
                f"{now:%Y-%m-%d %H:%M:%S}.{now.microsecond:06d} "
                f"192.168.1.170.44500 -> 10.0.10.221.514: psh "
                f"{1447941161 + sequence_offset} ack 3937626241"
            )
            block = header + "\n"
        else:
            block = header + "\n" + "\n".join(_hex_dump(payload)) + "\n\n"
        for sink in list(self._sniffer_sinks):
            sink(block)


    def _ingest_to_graylog(self, sequence: int) -> None:
        """Deliver the event to a fake Graylog, mirroring real log forwarding.

        Only used by the offline test harness; a transmitted packet is what
        makes a record appear downstream, which is exactly the coupling the
        correlator has to get right.
        """
        if not self.graylog_ingest_url:
            return
        import json as _json
        import urllib.request

        body = _json.dumps(
            {
                "source": self.hostname,
                "message": (
                    f'devid="FMVMELTM25001041" logid="0100032003" type="event" '
                    f'subtype="system" level="notice" seq={sequence} '
                    f'msg="{self.expected_message}"'
                ),
                "facility": "local7",
                "devid": "FMVMELTM25001041",
                "seq": sequence,
            }
        ).encode()

        def _send() -> None:
            try:
                request = urllib.request.Request(
                    self.graylog_ingest_url,
                    data=body,
                    headers={"Content-Type": "application/json"},
                )
                urllib.request.urlopen(request, timeout=3).read()
            except Exception:
                pass

        threading.Thread(target=_send, daemon=True).start()


class MockTransport:
    """A scripted FortiManager CLI that speaks the shell transport protocol."""

    def __init__(
        self,
        state: MockDeviceState,
        session_name: str,
        success_line: str,
        fail_rate: float = 0.0,
        hang_rate: float = 0.0,
        response_delay: float = 0.05,
        rng: Optional[random.Random] = None,
    ) -> None:
        self.state = state
        self.session_name = session_name
        self.success_line = success_line
        self.fail_rate = fail_rate
        self.hang_rate = hang_rate
        self.response_delay = response_delay
        self._rng = rng or random.Random()

        self.prompt = f"{state.hostname} # "
        self._out: "asyncio.Queue[str]" = asyncio.Queue()
        self._pending = ""
        self._closed = False
        self._banner_sent = False
        self._streaming = False
        self.command_log: List[str] = []
        self._sink = self._push

    # -- transport protocol -------------------------------------------------

    async def read(self) -> str:
        if self._closed:
            return ""
        if not self._banner_sent:
            self._banner_sent = True
            return self.prompt
        chunk = await self._out.get()
        if chunk == "":
            self._closed = True
        return chunk

    async def write(self, data: str) -> None:
        if self._closed:
            raise ConnectionResetError("mock device session is closed")
        if "\x03" in data:
            # Ctrl+C stops a streaming command and returns to the prompt.
            data = data.replace("\x03", "")
            if self._streaming:
                self._streaming = False
                self.state.detach(self._sink)
                self._push("^C\n")
                self._push(self.prompt)
        self._pending += data
        while "\n" in self._pending:
            line, _, self._pending = self._pending.partition("\n")
            asyncio.get_running_loop().create_task(self._handle(line.strip()))

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.state.detach(self._sink)
        await self._out.put("")

    @property
    def closed(self) -> bool:
        return self._closed

    # -- behaviour ----------------------------------------------------------

    def _push(self, text: str) -> None:
        if not self._closed:
            self._out.put_nowait(text)

    async def _emit(self, text: str) -> None:
        self._push(text)

    async def _handle(self, command: str) -> None:
        await asyncio.sleep(self.response_delay)
        if self._closed:
            return
        self.command_log.append(command)

        if command == "":
            await self._emit(self.prompt)
            return
        if command in ("exit", "quit"):
            await self._emit("\n")
            await self.close()
            return

        lowered = command.lower()

        if "sniffer packet" in lowered:
            # The sniffer streams until interrupted: no prompt is returned.
            await self._emit(f"{command}\ninterfaces=[any]\nfilters=[configured]\n")
            self.state.attach_sniffer(self._sink)
            self._streaming = True
            return

        if lowered.startswith("diagnose debug enable") or lowered.startswith("diag debug enable"):
            await self._emit(f"{command}\n{self.prompt}")
            self.state.attach_debug(self._sink)
            self._streaming = True
            return

        body = self._response_for(command)
        if body is None:
            # Simulated hang: no response at all, forcing the UNKNOWN path.
            return
        await self._emit(f"{command}\n{body}{self.prompt}")

    def _response_for(self, command: str) -> Optional[str]:
        lowered = command.lower()

        if "test application miglogd" in lowered:
            if self._rng.random() < self.hang_rate:
                return None
            if self._rng.random() < self.fail_rate:
                return "Command fail. Return code -3\n"
            # The device generates the event: debug lines and, unless dropped,
            # a packet on the wire.
            self.state.emit_event()
            return f"{self.success_line}.\n"

        if lowered.startswith("get system status"):
            return (
                f"Platform Type            : FMG-VM64\n"
                f"Platform Full Name       : FortiManager-VM64\n"
                f"Version                  : v7.4.3-build2601 250101 (GA)\n"
                f"Serial Number            : FMVMELTM25001041\n"
                f"Hostname                 : {self.state.hostname}\n"
                f"Current Time             : {datetime.now():%a %b %d %H:%M:%S %Y}\n"
            )

        if lowered.startswith("diagnose sys top-summary"):
            return (
                "CPU [|||             ] 18.4%   Mem [||||||          ] 41.2%\n"
                "  PID      RSS   CPU%   MEM%  FDS   TIME+   NAME\n"
                "  178   142.1M    3.1    4.0   64  02:13.4  miglogd\n"
                "  184    98.7M    1.2    2.7   41  00:58.1  logd\n"
            )

        if lowered.startswith(("config ", "set ", "end", "diagnose debug", "diag debug")):
            return ""

        return "Unknown action 0\n"


class MockSession:
    """Mirror of :class:`~fmtest.ssh_manager.DeviceSession` for the mock."""

    def __init__(self, name: str, shell: InteractiveShell, transport: MockTransport) -> None:
        self.name = name
        self.shell = shell
        self.transport = transport
        self._closed = False

    @property
    def connected(self) -> bool:
        return not self._closed and not self.shell.closed

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self.shell.aclose()


class MockGateway:
    """Drop-in replacement for :class:`~fmtest.ssh_manager.SSHGateway`."""

    def __init__(
        self,
        config: FortiManagerConfig,
        logbus: LogBus,
        success_line: str,
        expected_message: str,
        fail_rate: float = 0.0,
        hang_rate: float = 0.0,
        drop_rate: float = 0.0,
        headers_only: bool = False,
        graylog_ingest_url: Optional[str] = None,
        seed: Optional[int] = None,
    ) -> None:
        self._config = config
        self._log = logbus
        self._success_line = success_line
        self._fail_rate = fail_rate
        self._hang_rate = hang_rate
        self._rng = random.Random(seed)
        self._sessions: Dict[str, MockSession] = {}
        self.state = MockDeviceState(
            hostname=config.device_name or "fmgvm01",
            expected_message=expected_message,
            drop_rate=drop_rate,
            headers_only=headers_only,
            graylog_ingest_url=graylog_ingest_url,
            rng=self._rng,
        )

    @property
    def description(self) -> str:
        return f"MOCK {self._config.display_name} (no network traffic is generated)"

    async def open_session(self, name: str) -> MockSession:
        transport = MockTransport(
            state=self.state,
            session_name=name,
            success_line=self._success_line,
            fail_rate=self._fail_rate,
            hang_rate=self._hang_rate,
            rng=self._rng,
        )
        shell = InteractiveShell(
            transport,
            name=name,
            prompt_pattern=self._config.prompt_pattern,
        )
        shell.start()
        await shell.learn_prompt(timeout=3.0)
        self._log.system(f"session '{name}': connected to mock device (prompt {shell.prompt!r})")

        for command in self._config.session_init_commands:
            await shell.run(command, timeout=5.0)

        session = MockSession(name, shell, transport)
        self._sessions[name] = session
        return session

    async def reconnect(self, name: str) -> Optional[MockSession]:
        old = self._sessions.pop(name, None)
        if old is not None:
            await old.close()
        return await self.open_session(name)

    def get(self, name: str) -> Optional[MockSession]:
        return self._sessions.get(name)

    @property
    def session_names(self) -> List[str]:
        return list(self._sessions)

    async def close_all(self) -> None:
        sessions = list(self._sessions.items())
        self._sessions.clear()
        for name, session in sessions:
            await session.close()
            self._log.system(f"session '{name}': closed")
