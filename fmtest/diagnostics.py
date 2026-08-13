"""Debug mode: raw evidence capture and per-event match explanation.

Normal operation records only *matching* observations, because that is all the
correlator needs. When a run produces unexpected MISSes that is exactly the
wrong information: you need to see what the collectors actually saw and why
each piece of evidence was rejected.

Debug mode adds three things:

1. **Raw stream files.** Every byte received on each SSH session, verbatim,
   in its own file. Nothing is parsed, filtered or reformatted.
2. **Candidates.** Every packet block, debug line and Graylog record examined,
   matching or not, each carrying a machine-readable reason code explaining the
   outcome.
3. **A comparison report.** One block per test event showing the CLI, sniffer,
   debug and Graylog evidence side by side, the exact correlation window, and
   a plain-language verdict naming the reason for every non-match.

The aggregate reason-code tally at the end of the report usually identifies the
root cause on its own: forty packets rejected for ``no_payload_captured`` means
the sniffer verbosity is wrong, not that FortiManager stopped transmitting.
"""

from __future__ import annotations

import json
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, TextIO

from .config import AppConfig, DiagnosticsConfig
from .events import MatchState, Observation, Source, TestEvent

_RULE = "=" * 78
_SUB = "-" * 78


# Reason codes. Kept short and stable so they can be counted and grepped.
class Reason:
    MATCHED = "matched"
    NO_PAYLOAD = "no_payload_captured"
    PATTERN_ABSENT = "pattern_absent"
    FLOW_MISMATCH = "flow_mismatch"
    IDENTITY_CONFLICT = "identity_conflict"
    BINARY_PAYLOAD = "payload_not_text"
    TLS_PAYLOAD = "payload_looks_encrypted"
    NO_OBSERVATIONS = "no_matching_observations_at_all"
    OUTSIDE_WINDOW = "matches_exist_but_outside_window"
    ALREADY_CLAIMED = "matches_in_window_already_claimed_by_another_event"
    COLLECTOR_UNHEALTHY = "collector_not_running"
    NOT_ENABLED = "collector_not_enabled"
    UNEXPLAINED = "unexplained"


_REASON_HELP: Dict[str, str] = {
    Reason.NO_PAYLOAD: (
        "The capture contained packet headers but no packet data, so the expected "
        "message could not be searched for at all. Raise the sniffer verbosity "
        "until the output includes 0x0000-style hex dump lines."
    ),
    Reason.PATTERN_ABSENT: (
        "Content was captured and searched, but it does not contain the expected "
        "message. Check correlation.expected_message against what the device "
        "actually emits, and for the sniffer, check the filter is catching the "
        "right flow."
    ),
    Reason.FLOW_MISMATCH: (
        "A packet carrying the expected message was rejected because it did not "
        "match correlation.sniffer_flow. Loosen or remove the flow constraint if "
        "the traffic legitimately takes a different path."
    ),
    Reason.IDENTITY_CONFLICT: (
        "Evidence was found in the window, but its identity keys (sequence number, "
        "log id, device id) disagree with the evidence already claimed for this "
        "event, so it belongs to a different execution."
    ),
    Reason.BINARY_PAYLOAD: (
        "Packet data was captured but is not readable text. The log stream may be "
        "compressed or in a binary protocol rather than plain syslog."
    ),
    Reason.TLS_PAYLOAD: (
        "Packet data looks like a TLS record. If log forwarding is encrypted, the "
        "message will never appear in plaintext on the wire and content matching "
        "cannot work; correlate on the flow (addresses, ports, timing) instead."
    ),
    Reason.NO_OBSERVATIONS: (
        "This collector recorded no matching evidence at any point during the run, "
        "so the failure is not specific to this test event."
    ),
    Reason.OUTSIDE_WINDOW: (
        "Matching evidence exists but fell outside this event's correlation "
        "window. Check clock skew and raise correlation.timeout_seconds or "
        "timestamp_tolerance_seconds."
    ),
    Reason.ALREADY_CLAIMED: (
        "Matching evidence inside the window had already been claimed by an "
        "earlier test event. If real latency exceeds the test interval, raise "
        "interval_seconds or review correlation.bound_window_by_next_event."
    ),
    Reason.COLLECTOR_UNHEALTHY: (
        "The collector was not running during this window, so absence of evidence "
        "proves nothing. This is reported UNKNOWN rather than MISS."
    ),
}


@dataclass
class Candidate:
    """One piece of evidence examined by a collector, matching or not."""

    source: Source
    observed_at: datetime
    summary: str
    matched: bool
    code: str
    detail: str = ""
    excerpt: str = ""
    raw: str = ""
    fields: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self, include_raw: bool = False) -> Dict[str, Any]:
        record = {
            "source": self.source.value,
            "observed_at": self.observed_at.isoformat(timespec="milliseconds"),
            "summary": self.summary,
            "matched": self.matched,
            "reason_code": self.code,
            "detail": self.detail,
            "excerpt": self.excerpt,
            "fields": dict(self.fields),
        }
        if include_raw and self.raw:
            record["raw"] = self.raw
        return record


@dataclass
class SourceVerdict:
    """Per-source outcome for one test event, with the reason."""

    source: Source
    state: MatchState
    code: str
    reason: str
    claimed: Optional[Observation] = None
    candidates: List[Candidate] = field(default_factory=list)
    candidates_outside_window: int = 0
    nearest_outside_delta: Optional[float] = None

    def to_dict(self, include_raw: bool = False) -> Dict[str, Any]:
        return {
            "source": self.source.value,
            "state": self.state.value,
            "reason_code": self.code,
            "reason": self.reason,
            "claimed": self.claimed.to_dict() if self.claimed else None,
            "candidates_in_window": [c.to_dict(include_raw) for c in self.candidates],
            "candidates_outside_window": self.candidates_outside_window,
            "nearest_outside_delta_seconds": self.nearest_outside_delta,
        }


class DiagnosticRecorder:
    """Owns the debug-mode artefacts for one run."""

    def __init__(
        self,
        config: DiagnosticsConfig,
        app_config: AppConfig,
        run_stamp: str,
    ) -> None:
        self._config = config
        self._app_config = app_config
        self._run_stamp = run_stamp
        self._directory = config.resolve_directory(app_config.logging.directory)
        self._directory.mkdir(parents=True, exist_ok=True)

        self._raw_files: Dict[str, TextIO] = {}
        self._comparison: Optional[TextIO] = None
        self._candidates: Dict[Source, Deque[Candidate]] = {
            source: deque(maxlen=config.max_candidates)
            for source in (Source.SNIFFER, Source.DEBUG, Source.GRAYLOG)
        }
        self._event_records: List[Dict[str, Any]] = []
        self._reason_counts: Counter = Counter()
        self._examined: Counter = Counter()
        self._paths: Dict[str, Path] = {}
        self._closed = False

    # -- files --------------------------------------------------------------

    @property
    def directory(self) -> Path:
        return self._directory

    @property
    def paths(self) -> Dict[str, Path]:
        return dict(self._paths)

    def _path(self, name: str) -> Path:
        return self._directory / name

    def _open(self, key: str, filename: str, header: str = "") -> Optional[TextIO]:
        if self._closed:
            return None
        handle = self._raw_files.get(key)
        if handle is not None:
            return handle
        path = self._path(filename)
        try:
            handle = path.open("w", encoding="utf-8", errors="replace")
        except OSError:
            return None
        if header:
            handle.write(header)
            handle.flush()
        self._raw_files[key] = handle
        self._paths[key] = path
        return handle

    def raw_writer(self, session_name: str, description: str):
        """Return a callback that writes a session's bytes verbatim to disk.

        Registered as a stream consumer on the shell, so it sees everything the
        device sends on that session, before any parsing.
        """
        if not self._config.raw_streams:
            return None

        key = f"raw_{session_name}"
        filename = f"raw_{session_name}_{self._run_stamp}.log"
        header = (
            f"# Verbatim output of SSH session '{session_name}' ({description})\n"
            f"# Run {self._run_stamp}. Nothing below is parsed or filtered.\n"
            f"# Local receive timestamps are shown in [] when a chunk begins a new line.\n\n"
        )
        handle = self._open(key, filename, header)
        if handle is None:
            return None

        state = {"at_line_start": True}

        def write(chunk: str) -> None:
            if not chunk or self._closed:
                return
            try:
                now = datetime.now()
                stamp = f"[{now:%H:%M:%S}.{now.microsecond // 1000:03d}] "
                text = chunk
                if state["at_line_start"]:
                    text = stamp + text
                text = text.replace("\n", "\n" + stamp)
                # Undo a trailing stamp on a chunk that ends with a newline.
                if text.endswith(stamp):
                    text = text[: -len(stamp)]
                    state["at_line_start"] = True
                else:
                    state["at_line_start"] = chunk.endswith("\n")
                handle.write(text)
                handle.flush()
            except (OSError, ValueError):
                pass

        return write

    def record_graylog_exchange(self, request: Any, response: Any) -> None:
        """Append one Graylog API exchange (Phase 3 hook)."""
        handle = self._open(
            "raw_graylog",
            f"raw_graylog_{self._run_stamp}.jsonl",
            "",
        )
        if handle is None:
            return
        try:
            handle.write(
                json.dumps(
                    {
                        "at": datetime.now().isoformat(timespec="milliseconds"),
                        "request": request,
                        "response": response,
                    },
                    default=str,
                )
                + "\n"
            )
            handle.flush()
        except (OSError, ValueError, TypeError):
            pass

    # -- candidates ---------------------------------------------------------

    def add_candidate(self, candidate: Candidate) -> None:
        if not self._config.capture_all_candidates and not candidate.matched:
            return
        queue = self._candidates.get(candidate.source)
        if queue is None:
            return
        queue.append(candidate)
        self._examined[candidate.source.value] += 1
        self._reason_counts[f"{candidate.source.value}:{candidate.code}"] += 1

    def candidates_between(
        self, source: Source, start: datetime, end: datetime
    ) -> List[Candidate]:
        queue = self._candidates.get(source)
        if queue is None:
            return []
        return [c for c in queue if start <= c.observed_at <= end]

    def candidates_outside(
        self, source: Source, start: datetime, end: datetime
    ) -> List[Candidate]:
        queue = self._candidates.get(source)
        if queue is None:
            return []
        return [c for c in queue if c.observed_at < start or c.observed_at > end]

    def examined_count(self, source: Source) -> int:
        return self._examined.get(source.value, 0)

    # -- comparison report --------------------------------------------------

    def _comparison_handle(self) -> Optional[TextIO]:
        if not self._config.comparison_report:
            return None
        if self._comparison is not None:
            return self._comparison
        path = self._path(f"comparison_{self._run_stamp}.txt")
        try:
            handle = path.open("w", encoding="utf-8", errors="replace")
        except OSError:
            return None
        correlation = self._app_config.correlation
        handle.write(
            f"{_RULE}\n"
            f"FORTIMANAGER LOG TRANSMISSION TEST -- PER-EVENT EVIDENCE COMPARISON\n"
            f"{_RULE}\n\n"
            f"Run              : {self._run_stamp}\n"
            f"Target           : {self._app_config.fortimanager.display_name} "
            f"({self._app_config.fortimanager.host})\n"
            f"Expected message : {correlation.expected_message!r}\n"
            f"CLI success      : {correlation.cli_success_pattern!r}\n"
            f"Sniffer pattern  : {correlation.sniffer_match_pattern!r}\n"
            f"Graylog pattern  : {correlation.graylog_match_pattern!r}\n"
            f"Window           : -{correlation.timestamp_tolerance_seconds:g}s "
            f"to +{correlation.timeout_seconds:g}s around the CLI command\n"
            f"Sniffer command  : {self._app_config.sniffer.command or '<disabled>'}\n\n"
            f"One block per test event below. Every candidate the collectors examined\n"
            f"inside the window is listed, with the reason it did or did not match.\n\n"
        )
        handle.flush()
        self._comparison = handle
        self._paths["comparison"] = path
        return handle

    def write_event(self, event: TestEvent, verdicts: List[SourceVerdict], window: tuple) -> None:
        """Append one test event's side-by-side evidence block."""
        record = {
            "event": event.to_dict(include_raw=True),
            "window_start": window[0].isoformat(timespec="milliseconds"),
            "window_end": window[1].isoformat(timespec="milliseconds"),
            "sources": [v.to_dict(self._config.include_raw_blocks) for v in verdicts],
        }
        self._event_records.append(record)

        handle = self._comparison_handle()
        if handle is None:
            return
        try:
            handle.write(self._render_event(event, verdicts, window))
            handle.flush()
        except (OSError, ValueError):
            pass

    def _render_event(
        self, event: TestEvent, verdicts: List[SourceVerdict], window: tuple
    ) -> str:
        lines: List[str] = ["", _RULE, f"{event.event_id}", _RULE, ""]

        # --- CLI ---
        lines.append(f"CLI{'':<58}RESULT: {event.cli_state.value}")
        lines.append(f"  command        : {event.cli_command}")
        lines.append(f"  sent at        : {event.cli_start_timestamp:%H:%M:%S.%f}"[:-3])
        if event.cli_response_timestamp:
            lines.append(
                f"  responded at   : {event.cli_response_timestamp:%H:%M:%S.%f}"[:-3]
                + f"  (+{event.cli_response_ms:.0f} ms)"
            )
        lines.append(
            f"  looking for    : {self._app_config.correlation.cli_success_pattern!r}"
        )
        if event.cli_error:
            lines.append(f"  problem        : {event.cli_error}")
        if event.cli_response:
            lines.append("  device said    :")
            for raw_line in event.cli_response.splitlines()[:20]:
                lines.append(f"    | {raw_line}")
        else:
            lines.append("  device said    : <nothing>")
        lines.append("")

        lines.append(
            f"CORRELATION WINDOW: {window[0]:%H:%M:%S.%f}"[:-3]
            + f" .. {window[1]:%H:%M:%S.%f}"[:-3]
        )
        lines.append("")

        # --- other sources ---
        for verdict in verdicts:
            lines.append(
                f"{verdict.source.value:<61}RESULT: {verdict.state.value}"
            )
            lines.append(f"  why            : {verdict.reason}")
            help_text = _REASON_HELP.get(verdict.code)
            if help_text and verdict.state is not MatchState.HIT:
                for chunk in _wrap(help_text, 74):
                    lines.append(f"    {chunk}")

            if verdict.claimed is not None:
                observation = verdict.claimed
                delta = (
                    observation.observed_at - event.cli_start_timestamp
                ).total_seconds() * 1000.0
                lines.append(
                    f"  matched at     : {observation.observed_at:%H:%M:%S.%f}"[:-3]
                    + f"  (+{delta:.0f} ms after CLI)"
                )
                if observation.fields:
                    lines.append(f"  evidence       : {_compact(observation.fields)}")

            if verdict.candidates:
                lines.append(
                    f"  candidates in window: {len(verdict.candidates)}"
                    + (
                        f"  (+{verdict.candidates_outside_window} outside)"
                        if verdict.candidates_outside_window
                        else ""
                    )
                )
                shown = verdict.candidates[: self._config.max_candidates_per_event]
                for index, candidate in enumerate(shown, start=1):
                    delta = (
                        candidate.observed_at - event.cli_start_timestamp
                    ).total_seconds()
                    flag = "MATCH" if candidate.matched else "no match"
                    lines.append(
                        f"   [{index}] {candidate.observed_at:%H:%M:%S.%f}"[:-3]
                        + f" ({delta:+.3f}s)  {flag}"
                    )
                    lines.append(f"        {candidate.summary}")
                    lines.append(f"        reason: {candidate.code}")
                    if candidate.detail:
                        lines.append(f"        {candidate.detail}")
                    if candidate.excerpt:
                        lines.append(f"        content: {candidate.excerpt}")
                    if self._config.include_raw_blocks and candidate.raw:
                        for raw_line in candidate.raw.splitlines()[
                            : self._config.max_raw_block_lines
                        ]:
                            lines.append(f"        | {raw_line}")
                if len(verdict.candidates) > len(shown):
                    lines.append(
                        f"   ... {len(verdict.candidates) - len(shown)} more candidate(s) "
                        f"not shown (diagnostics.max_candidates_per_event)"
                    )
            elif verdict.state is not MatchState.NOT_ENABLED:
                detail = "  candidates in window: 0"
                if verdict.candidates_outside_window:
                    detail += (
                        f"  ({verdict.candidates_outside_window} examined outside the "
                        f"window"
                    )
                    if verdict.nearest_outside_delta is not None:
                        detail += f", nearest {verdict.nearest_outside_delta:+.3f}s"
                    detail += ")"
                lines.append(detail)
            lines.append("")

        lines.append(f"VERDICT: {event.final_status.description}")
        lines.append("")
        return "\n".join(lines) + "\n"

    # -- finalisation -------------------------------------------------------

    def _render_aggregate(self) -> str:
        lines: List[str] = ["", _RULE, "AGGREGATE: WHY EVIDENCE DID NOT MATCH", _RULE, ""]
        if not self._reason_counts:
            lines.append("No candidates were examined.")
            lines.append("")
            return "\n".join(lines)

        lines.append("Candidates examined per source:")
        for source, count in sorted(self._examined.items()):
            lines.append(f"  {source:<10} {count}")
        lines.append("")
        lines.append("Outcome tally (source:reason_code -> count):")
        for key, count in self._reason_counts.most_common():
            lines.append(f"  {count:>6}  {key}")
        lines.append("")

        lines.extend(self._render_findings())
        lines.append(_RULE)
        return "\n".join(lines)

    def _render_findings(self) -> List[str]:
        """Name the sources that produced no matches at all, and why.

        A source that matched sometimes is working; its non-matching candidates
        are ordinary background traffic and are not a finding. A source that
        never matched is the thing to investigate, and the sniffer matters most
        because it is the primary evidence of transmission.
        """
        lines: List[str] = ["FINDINGS", ""]
        found_any = False

        # Primary evidence first.
        for source in (Source.SNIFFER, Source.GRAYLOG, Source.DEBUG):
            examined = self._examined.get(source.value, 0)
            if not examined:
                continue
            matched = self._reason_counts.get(f"{source.value}:{Reason.MATCHED}", 0)
            if matched:
                lines.append(
                    f"  {source.value}: {matched} of {examined} candidate(s) matched "
                    f"- this collector is working."
                )
                continue

            found_any = True
            reasons = [
                (key.split(":", 1)[1], count)
                for key, count in self._reason_counts.most_common()
                if key.startswith(f"{source.value}:")
            ]
            code, count = reasons[0]
            role = (
                "PRIMARY EVIDENCE OF TRANSMISSION"
                if source is Source.SNIFFER
                else "supplemental"
                if source is Source.DEBUG
                else "delivery evidence"
            )
            lines.append(
                f"  {source.value} ({role}): examined {examined} candidate(s), "
                f"NONE matched."
            )
            lines.append(f"    dominant reason: {code} ({count} of {examined})")
            help_text = _REASON_HELP.get(code)
            if help_text:
                for chunk in _wrap(help_text, 70):
                    lines.append(f"      {chunk}")
            if source is Source.SNIFFER:
                lines.append(
                    "      Until this is resolved, every SNIFFER MISS in this run is"
                )
                lines.append(
                    "      INCONCLUSIVE: it does not show that FortiManager failed to"
                )
                lines.append("      transmit.")
            lines.append("")

        if not found_any:
            lines.append("  Every active collector matched at least once.")
        lines.append("")
        return lines

    def close(self, extra_notes: Optional[List[str]] = None) -> Dict[str, Path]:
        if self._closed:
            return dict(self._paths)

        handle = self._comparison_handle()
        if handle is not None:
            try:
                if extra_notes:
                    handle.write("\n" + _SUB + "\nNOTES\n" + _SUB + "\n")
                    for note in extra_notes:
                        for chunk in _wrap(note, 76):
                            handle.write(f"  {chunk}\n")
                    handle.write("\n")
                handle.write(self._render_aggregate() + "\n")
                handle.flush()
            except (OSError, ValueError):
                pass

        # Machine-readable twin of the comparison report.
        json_path = self._path(f"comparison_{self._run_stamp}.json")
        try:
            with json_path.open("w", encoding="utf-8") as out:
                json.dump(
                    {
                        "run": self._run_stamp,
                        "expected_message": self._app_config.correlation.expected_message,
                        "sniffer_command": self._app_config.sniffer.command,
                        "examined": dict(self._examined),
                        "reason_counts": dict(self._reason_counts),
                        "events": self._event_records,
                        "notes": extra_notes or [],
                    },
                    out,
                    indent=2,
                    default=str,
                )
                out.write("\n")
            self._paths["comparison_json"] = json_path
        except (OSError, TypeError, ValueError):
            pass

        self._closed = True
        for stream in list(self._raw_files.values()) + (
            [self._comparison] if self._comparison else []
        ):
            try:
                stream.flush()
                stream.close()
            except (OSError, ValueError):
                pass
        self._raw_files.clear()
        self._comparison = None
        return dict(self._paths)


def _wrap(text: str, width: int) -> List[str]:
    words = text.split()
    lines: List[str] = []
    current = ""
    for word in words:
        if current and len(current) + 1 + len(word) > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines


def _compact(fields: Dict[str, Any], limit: int = 6) -> str:
    items = list(fields.items())[:limit]
    return ", ".join(f"{k}={v}" for k, v in items)
