"""Packet sniffer collector: the primary evidence that an event was transmitted.

The complete sniffer command comes from ``sniffer.command`` in config.yaml. The
tool never constructs it.

Why this is not line-by-line string matching
--------------------------------------------

FortiManager verbose sniffer output prints a packet as a header line followed by
a hex/ASCII dump, so the expected message is almost always split across several
lines and interleaved with hex::

    2026-08-11 15:32:01.224661 port1 out 10.0.10.10.514 -> 10.0.10.221.514: udp 96
    0x0000   4500 007c 1c46 4000 4011 ...        E..|.F@.@.......
    0x0010   0a00 0a0a 0a00 0add 0202 ...        ................
    0x0020   3c31 3334 3e50 6f77 6572 ...        <134>Power 1 go
    0x0030   6573 2074 6f20 6f6e 6c69 ...        es to online...

Searching each terminal line independently would never find
``Power 1 goes to online``: it is split between offsets 0x20 and 0x30, and the
ASCII column truncates it besides.

So :class:`SnifferParser` buffers each packet block, rebuilds the packet bytes
from the hex columns by offset, and searches the reconstructed payload. Three
search surfaces are used, in order of reliability:

1. the reassembled payload bytes (handles any split, any verbosity)
2. the concatenated ASCII columns (handles a truncated hex column)
3. the raw block text (handles low verbosity levels that print text directly)

Timestamps
----------

The observation timestamp is the *local* time the block's first line arrived,
not the device-reported timestamp and not the time the block was completed.
FortiManager, this computer and Graylog are not assumed to share a clock, so
correlation is anchored on local time; and using completion time would add
``block_idle_seconds`` to every CLI-to-packet measurement, because a trailing
block is only finished once the device goes quiet. The device's own timestamp
is preserved in ``fields['device_timestamp']`` as raw evidence.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from .config import CorrelationConfig, SnifferConfig
from .events import EventTracker, Source
from .identity import FlowConstraint, IdentityExtractor
from .logbus import LogBus
from .shell import strip_ansi

# Header line: an absolute timestamp ("a" option) or relative seconds, then
# OPTIONALLY an interface name, OPTIONALLY a direction, then the flow.
#
# Both of these shapes occur in the field, depending on verbosity and platform:
#   2026-08-11 21:42:39.301186 port1 out 10.0.10.10.514 -> 10.0.10.221.514: udp 96
#   2026-08-11 21:42:39.301186 192.168.1.170.44500 -> 10.0.10.221.514: psh 1 ack 2
# so the interface cannot be assumed present.
_HEADER_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}\.\d+|\d+\.\d{6})\s+(?P<rest>.+)$"
)

# The flow part begins with an address, optionally .port, then an arrow.
_FLOW_START_RE = re.compile(r"^[0-9a-fA-F:.]+(?:\.\d+)?\s*->")

_DIRECTIONS = ("in", "out", "--")

# TCP flag words FortiOS prints in place of a protocol name.
_TCP_FLAGS = ("syn", "ack", "psh", "fin", "rst", "urg")

# "10.0.10.10.514 -> 10.0.10.221.514: udp 96"
_FLOW_PORTS_RE = re.compile(
    r"^(?P<src>[0-9a-fA-F:.]+)\.(?P<sport>\d+)\s*->\s*"
    r"(?P<dst>[0-9a-fA-F:.]+)\.(?P<dport>\d+):\s*(?P<detail>.*)$"
)

# "10.0.10.10 -> 10.0.10.221: icmp: echo request"
_FLOW_PLAIN_RE = re.compile(
    r"^(?P<src>[0-9a-fA-F:.]+)\s*->\s*(?P<dst>[0-9a-fA-F:.]+):\s*(?P<detail>.*)$"
)

_DETAIL_RE = re.compile(r"^(?P<proto>[a-zA-Z][\w-]*)?\s*(?P<length>\d+)?")

# "0x0010   0a00 0a0a 0a00 0add   ................"
_HEX_PREFIX_RE = re.compile(r"^0x([0-9a-fA-F]{2,8})\s+(.*)$")
# Hex column followed by a tab or two-plus spaces, then the ASCII column.
_HEX_SPLIT_RE = re.compile(
    r"^((?:[0-9a-fA-F]{2,4}[ ]+)*[0-9a-fA-F]{2,4})(?:\t+|[ ]{2,})(.*)$"
)
_HEX_GROUP_RE = re.compile(r"\b[0-9a-fA-F]{2,4}\b")

# Lines the sniffer prints that are not packet data.
_NOISE_PREFIXES = (
    "interfaces=",
    "filters=",
    "pcap_lookupnet",
    "pcap_compile",
    "Segmentation",
)


@dataclass
class PacketBlock:
    """One packet as printed by the FortiManager sniffer."""

    header: str = ""
    lines: List[str] = field(default_factory=list)
    payload: bytearray = field(default_factory=bytearray)
    ascii_columns: List[str] = field(default_factory=list)
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    fields: Dict[str, Any] = field(default_factory=dict)

    @property
    def raw_text(self) -> str:
        return "\n".join(self.lines)

    @property
    def payload_text(self) -> str:
        """The reassembled packet bytes as latin-1 text.

        latin-1 is used deliberately: it maps every byte to a character without
        raising, so a binary payload cannot break the search, and ASCII content
        is preserved exactly.
        """
        return self.payload.decode("latin-1", errors="replace")

    @property
    def ascii_text(self) -> str:
        return "".join(self.ascii_columns)

    @property
    def has_payload(self) -> bool:
        return bool(self.payload)

    @property
    def has_any_data(self) -> bool:
        """True when the capture included packet contents, not just a header."""
        return bool(self.payload) or bool(self.ascii_columns)

    def printable_preview(self, limit: int = 300) -> str:
        """Readable rendering of the captured bytes, for diagnostics."""
        source = self.payload_text if self.payload else self.ascii_text
        if not source:
            return ""
        rendered = "".join(ch if 32 <= ord(ch) < 127 else "." for ch in source)
        if len(rendered) > limit:
            rendered = rendered[:limit] + f"... ({len(source)} chars total)"
        return rendered

    def looks_like_tls(self) -> bool:
        """Detect a TLS record header at the start of the TCP/UDP payload.

        Content matching cannot work against an encrypted log stream, and that
        is worth saying explicitly rather than reporting an unexplained MISS.
        """
        data = bytes(self.payload)
        if len(data) < 6:
            return False
        # The TLS record can start after any combination of Ethernet, IP and
        # TCP headers (and options), so scan the plausible header region rather
        # than assuming fixed offsets: handshake byte 0x16, version 0x03 0x00-04,
        # then a record length that fits inside a TLS record.
        limit = min(len(data) - 5, 96)
        for offset in range(0, limit + 1):
            if data[offset] != 0x16 or data[offset + 1] != 0x03:
                continue
            if data[offset + 2] > 0x04:
                continue
            record_length = (data[offset + 3] << 8) | data[offset + 4]
            if 0 < record_length <= 16384:
                return True
        return False

    def is_mostly_binary(self) -> bool:
        data = bytes(self.payload)
        if len(data) < 16:
            return False
        # Ignore the leading network headers, which are always binary.
        body = data[28:] if len(data) > 40 else data
        if not body:
            return False
        printable = sum(1 for b in body if 32 <= b < 127 or b in (9, 10, 13))
        return (printable / len(body)) < 0.6

    def search_surfaces(self) -> List[tuple]:
        """(label, text) pairs to search, most reliable first."""
        surfaces = []
        if self.payload:
            surfaces.append(("payload", self.payload_text))
        if self.ascii_columns:
            surfaces.append(("ascii_column", self.ascii_text))
        surfaces.append(("raw", self.raw_text))
        return surfaces

    def summary(self) -> str:
        src = self.fields.get("src_ip")
        dst = self.fields.get("dst_ip")
        if src and dst:
            sport = self.fields.get("src_port")
            dport = self.fields.get("dst_port")
            left = f"{src}:{sport}" if sport else str(src)
            right = f"{dst}:{dport}" if dport else str(dst)
            proto = self.fields.get("protocol", "")
            length = self.fields.get("length")
            tail = f" {proto}" if proto else ""
            tail += f" len={length}" if length else ""
            return f"{left} -> {right}{tail} ({len(self.payload)} bytes captured)"
        return self.header or "<packet>"


class SnifferParser:
    """Turns a character stream of sniffer output into packet blocks."""

    def __init__(self, decode_hex_payload: bool = True) -> None:
        self._line_buffer = ""
        self._current: Optional[PacketBlock] = None
        self._last_line_at: Optional[datetime] = None
        self._decode_hex = decode_hex_payload
        self.noise_lines: List[str] = []

    # -- feeding ------------------------------------------------------------

    def feed(self, chunk: str) -> List[PacketBlock]:
        """Consume output; return any packet blocks that are now complete."""
        self._line_buffer += strip_ansi(chunk)
        completed: List[PacketBlock] = []

        while "\n" in self._line_buffer:
            line, _, self._line_buffer = self._line_buffer.partition("\n")
            block = self._consume_line(line.rstrip())
            if block is not None:
                completed.append(block)
        return completed

    def _consume_line(self, line: str) -> Optional[PacketBlock]:
        stripped = line.strip()
        if not stripped:
            return None

        self._last_line_at = datetime.now()

        header_match = _HEADER_RE.match(stripped) if _is_header(stripped) else None
        if header_match is not None:
            finished = self._finish_current()
            self._current = PacketBlock(header=stripped, started_at=datetime.now())
            self._current.lines.append(line)
            self._current.fields.update(_parse_header(header_match))
            return finished

        if any(stripped.startswith(prefix) for prefix in _NOISE_PREFIXES):
            self.noise_lines.append(stripped)
            return None

        if self._current is None:
            # Output before the first header (banner, echoed command, prompt).
            self.noise_lines.append(stripped)
            return None

        self._current.lines.append(line)
        self._absorb_hex(stripped)
        return None

    def _absorb_hex(self, line: str) -> None:
        if not self._decode_hex:
            # Payload reassembly disabled: matching falls back to the ASCII
            # column and the raw block text.
            prefix_match = _HEX_PREFIX_RE.match(line)
            if prefix_match is not None and self._current is not None:
                split = _HEX_SPLIT_RE.match(prefix_match.group(2))
                if split is not None:
                    self._current.ascii_columns.append(split.group(2))
            return

        prefix_match = _HEX_PREFIX_RE.match(line)
        if prefix_match is None:
            return
        assert self._current is not None

        offset = int(prefix_match.group(1), 16)
        remainder = prefix_match.group(2)

        split = _HEX_SPLIT_RE.match(remainder)
        if split is not None:
            hex_part, ascii_part = split.group(1), split.group(2)
        else:
            # No detectable ASCII column: the whole remainder is hex.
            hex_part, ascii_part = remainder, ""

        data = bytearray()
        for group in _HEX_GROUP_RE.findall(hex_part):
            if len(group) % 2:
                # Malformed group; a partial line is better than losing the packet.
                group = group[:-1]
                if not group:
                    continue
            try:
                data.extend(bytes.fromhex(group))
            except ValueError:
                continue

        if data:
            block = self._current
            end = offset + len(data)
            if len(block.payload) < end:
                block.payload.extend(b"\x00" * (end - len(block.payload)))
            block.payload[offset:end] = data
        if ascii_part:
            self._current.ascii_columns.append(ascii_part)

    # -- completion ---------------------------------------------------------

    def _finish_current(self) -> Optional[PacketBlock]:
        block = self._current
        self._current = None
        if block is None:
            return None
        block.completed_at = datetime.now()
        return block

    def flush_if_idle(self, idle_seconds: float) -> Optional[PacketBlock]:
        """Complete the in-progress block if nothing has arrived recently.

        A packet block has no terminator: it ends when the next header arrives
        or when the device goes quiet. This is the quiet case.
        """
        if self._current is None or self._last_line_at is None:
            return None
        if (datetime.now() - self._last_line_at).total_seconds() < idle_seconds:
            return None
        return self._finish_current()

    def flush(self) -> Optional[PacketBlock]:
        """Complete whatever is in progress, used at shutdown."""
        if self._line_buffer.strip():
            self._consume_line(self._line_buffer.rstrip())
            self._line_buffer = ""
        return self._finish_current()


def _is_header(line: str) -> bool:
    """A header starts with a timestamp and describes a flow.

    Requiring the arrow (or an explicit direction word) keeps stray timestamped
    device output from being mistaken for the start of a new packet.
    """
    match = _HEADER_RE.match(line)
    if match is None:
        return False
    rest = match.group("rest")
    if "->" in rest:
        return True
    parts = rest.split(None, 1)
    return len(parts) == 2 and parts[0] in _DIRECTIONS


def _parse_header(match: "re.Match[str]") -> Dict[str, Any]:
    fields: Dict[str, Any] = {"device_timestamp": match.group("ts")}
    remainder = match.group("rest").strip()

    # Optional interface name: present only when the remainder does not already
    # begin with the flow.
    if not _FLOW_START_RE.match(remainder):
        parts = remainder.split(None, 1)
        if len(parts) == 2:
            fields["interface"] = parts[0]
            remainder = parts[1].strip()

    # Optional direction.
    parts = remainder.split(None, 1)
    if len(parts) == 2 and parts[0] in _DIRECTIONS:
        if parts[0] != "--":
            fields["direction"] = parts[0]
        remainder = parts[1].strip()

    flow = remainder
    flow_match = _FLOW_PORTS_RE.match(flow)
    if flow_match is not None:
        fields["src_ip"] = flow_match.group("src")
        fields["src_port"] = int(flow_match.group("sport"))
        fields["dst_ip"] = flow_match.group("dst")
        fields["dst_port"] = int(flow_match.group("dport"))
        detail = flow_match.group("detail")
    else:
        flow_match = _FLOW_PLAIN_RE.match(flow)
        if flow_match is not None:
            fields["src_ip"] = flow_match.group("src")
            fields["dst_ip"] = flow_match.group("dst")
            detail = flow_match.group("detail")
        else:
            detail = flow

    detail = detail.strip()
    if detail:
        fields["detail"] = detail
        detail_match = _DETAIL_RE.match(detail)
        if detail_match is not None:
            proto = detail_match.group("proto")
            if proto:
                if proto.lower() in _TCP_FLAGS:
                    # "psh 1447941161 ack 3937626241" is a TCP segment, not a
                    # protocol named "psh".
                    fields["protocol"] = "tcp"
                    fields["tcp_flags"] = " ".join(
                        word for word in detail.split() if word.lower() in _TCP_FLAGS
                    )
                else:
                    fields["protocol"] = proto
                    if detail_match.group("length"):
                        fields["length"] = int(detail_match.group("length"))
    return fields


class SnifferCollector:
    """Runs the configured sniffer command and records matching packets.

    This collector only observes. It records a SNIFFER observation for every
    packet whose reconstructed payload contains the expected message and leaves
    the decision about which test event that packet belongs to entirely to the
    correlator.
    """

    def __init__(
        self,
        config: SnifferConfig,
        correlation: CorrelationConfig,
        tracker: EventTracker,
        logbus: LogBus,
        gateway,
        session_name: str = "sniffer",
        diagnostics=None,
    ) -> None:
        self._config = config
        self._correlation = correlation
        self._tracker = tracker
        self._log = logbus
        self._gateway = gateway
        self._diagnostics = diagnostics
        self._session_name = session_name
        self._parser = SnifferParser(decode_hex_payload=config.decode_hex_payload)
        self._session = None
        self._pattern = correlation.sniffer_match_pattern
        self._regex: Optional[re.Pattern[str]] = (
            re.compile(self._pattern, re.IGNORECASE) if correlation.pattern_is_regex else None
        )
        self._needle = self._pattern.lower()
        self._identity = IdentityExtractor(
            [(f) for f in correlation.identity.fields],
            enabled=correlation.identity.enabled,
        )
        flow = correlation.sniffer_flow
        self._flow = FlowConstraint(
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            direction=flow.direction,
        )

        self.flow_rejects = 0
        self.healthy = False
        self.started = False
        self.packets_seen = 0
        self.packets_without_payload = 0
        self.matches = 0
        self.bytes_captured = 0
        self.last_error: Optional[str] = None
        self._on_match: Optional[Callable[[PacketBlock], None]] = None

    @property
    def session_name(self) -> str:
        return self._session_name

    # -- lifecycle ----------------------------------------------------------

    async def start(self) -> bool:
        """Open the dedicated session and launch the sniffer command."""
        try:
            self._session = await self._gateway.open_session(self._session_name)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
            self._log.log(
                Source.SNIFFER,
                f"could not open sniffer session: {self.last_error}. "
                f"Transmission evidence will be reported UNKNOWN, not MISS.",
            )
            return False

        command = self._config.command
        self._log.log(Source.SNIFFER, f"starting: {command}")
        try:
            # The sniffer never returns to a prompt, so the command is written
            # directly rather than executed through the request/response path.
            await self._session.shell.send_line(command)
        except Exception as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
            self._log.log(Source.SNIFFER, f"could not start sniffer: {self.last_error}")
            return False

        self.healthy = True
        self.started = True
        return True

    async def run(self) -> None:
        """Consume sniffer output until the session ends."""
        if self._session is None:
            return
        try:
            await self._session.shell.stream(
                on_chunk=self._on_chunk,
                on_idle=self._on_idle,
                idle_timeout=min(self._config.block_idle_seconds, 0.5),
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
            self._log.log(Source.SNIFFER, f"stream error: {self.last_error}")
        finally:
            self._drain_parser()
            if self.healthy and self._session is not None and self._session.shell.closed:
                self.healthy = False
                self._log.log(
                    Source.SNIFFER,
                    "sniffer session closed; further packets cannot be observed",
                )

    async def stop(self) -> None:
        """Stop the sniffer on the device and close its session."""
        if self._session is None:
            return
        self._log.log(Source.SNIFFER, "stopping sniffer")
        try:
            if not self._session.shell.closed:
                await asyncio.wait_for(
                    self._session.shell.write_raw(self._config.stop_key), timeout=3.0
                )
                await asyncio.sleep(0.4)
        except (asyncio.TimeoutError, Exception):
            pass
        self._drain_parser()
        try:
            await asyncio.wait_for(self._session.close(), timeout=8.0)
        except (asyncio.TimeoutError, Exception):
            pass
        self.healthy = False
        self._log.log(
            Source.SNIFFER,
            f"stopped after {self.packets_seen} packet(s), {self.matches} match(es)",
        )

    # -- stream handling ----------------------------------------------------

    def _on_chunk(self, chunk: str) -> None:
        if self._config.echo_to_log:
            for line in strip_ansi(chunk).splitlines():
                if line.strip():
                    self._log.log(Source.SNIFFER, line.rstrip(), raw=True)
        for block in self._parser.feed(chunk):
            self._handle_block(block)

    def _on_idle(self) -> None:
        block = self._parser.flush_if_idle(self._config.block_idle_seconds)
        if block is not None:
            self._handle_block(block)

    def _drain_parser(self) -> None:
        block = self._parser.flush()
        if block is not None:
            self._handle_block(block)

    # -- matching -----------------------------------------------------------

    def _find(self, text: str) -> bool:
        if self._regex is not None:
            return self._regex.search(text) is not None
        return self._needle in text.lower()

    def _handle_block(self, block: PacketBlock) -> None:
        self.packets_seen += 1
        self.bytes_captured += len(block.payload)
        if not block.has_any_data:
            self.packets_without_payload += 1

        matched_on: Optional[str] = None
        for label, text in block.search_surfaces():
            if text and self._find(text):
                matched_on = label
                break

        if matched_on is None:
            self._record_candidate(block, matched_on=None)
            return

        # The payload says the right thing, but is it the right flow? A copy of
        # the same message going somewhere else is not the event under test.
        flow_problem = self._flow.check(block.fields) if self._flow.active else None
        if flow_problem is not None:
            self.flow_rejects += 1
            self._record_candidate(block, matched_on=None, flow_problem=flow_problem)
            return

        self._record_candidate(block, matched_on=matched_on)

        self.matches += 1
        # The block's FIRST line is when the packet actually arrived. Using
        # completed_at instead would add block_idle_seconds to every
        # measurement, because a trailing block is only finished once the
        # device has gone quiet -- a systematic bias in every CLI->packet delta.
        observed_at = block.started_at
        fields = dict(block.fields)
        fields["matched_on"] = matched_on
        fields["payload_bytes"] = len(block.payload)
        payload_text = block.payload_text
        identity = self._identity.extract(payload_text, block.ascii_text, block.raw_text)
        if identity:
            fields["identity"] = identity
        if block.completed_at is not None:
            fields["block_completed_at"] = block.completed_at.isoformat(
                timespec="milliseconds"
            )

        self._tracker.record(Source.SNIFFER, observed_at, block.raw_text, fields=fields)
        self._log.log(
            Source.SNIFFER,
            f"MATCH #{self.matches} on {matched_on}: {block.summary()}",
        )
        if self._on_match is not None:
            try:
                self._on_match(block)
            except Exception:
                pass

    def set_match_callback(self, callback: Callable[[PacketBlock], None]) -> None:
        self._on_match = callback

    # -- diagnostics --------------------------------------------------------

    def _record_candidate(
        self,
        block: PacketBlock,
        matched_on: Optional[str],
        flow_problem: Optional[str] = None,
    ) -> None:
        """Record why this packet did or did not match, for debug mode."""
        if self._diagnostics is None:
            return
        from .diagnostics import Candidate, Reason  # local import avoids a cycle

        preview_limit = getattr(self._diagnostics._config, "payload_preview_chars", 300)

        if matched_on is not None:
            code = Reason.MATCHED
            detail = f"expected message found in the {matched_on} surface"
        elif flow_problem is not None:
            code = Reason.FLOW_MISMATCH
            detail = (
                f"payload contains the expected message, but the flow was rejected: "
                f"{flow_problem} (correlation.sniffer_flow)"
            )
        elif not block.has_any_data:
            code = Reason.NO_PAYLOAD
            detail = (
                "the capture printed a packet header but no packet data, so there "
                "was nothing to search"
            )
        elif block.looks_like_tls():
            code = Reason.TLS_PAYLOAD
            detail = "payload begins with a TLS record header"
        elif block.is_mostly_binary():
            code = Reason.BINARY_PAYLOAD
            detail = (
                f"{len(block.payload)} payload bytes captured, but the content is "
                f"not readable text"
            )
        else:
            code = Reason.PATTERN_ABSENT
            detail = (
                f"{len(block.payload)} payload bytes searched; "
                f"{self._pattern!r} is not present"
            )

        self._diagnostics.add_candidate(
            Candidate(
                source=Source.SNIFFER,
                observed_at=block.started_at,
                summary=block.summary(),
                matched=matched_on is not None,
                code=code,
                detail=detail,
                excerpt=block.printable_preview(preview_limit),
                raw=block.raw_text,
                fields=dict(block.fields),
            )
        )
