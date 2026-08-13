"""Final reports: human-readable summary plus machine-readable event records.

Three artefacts are produced at shutdown, regardless of the log file mode:

``summary_<timestamp>.txt``
    The operator-facing summary, identical to what is printed to the console.
``events_<timestamp>.json``
    Run metadata plus one record per test event, for later analysis.
``events_<timestamp>.csv``
    The same per-event records in a spreadsheet-friendly form.
"""

from __future__ import annotations

import csv
import json
import statistics
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import __version__
from .config import AppConfig
from .command_runner import GroupStats
from .events import EventTracker, FinalStatus, MatchState, TestEvent

_LINE = "=" * 60

# Columns for the CSV export, in order.
_CSV_FIELDS = [
    "event_id",
    "cli_start",
    "cli_response",
    "cli_state",
    "cli_generated",
    "debug_state",
    "sniffer_state",
    "sniffer_seen",
    "sniffer_timestamp",
    "graylog_state",
    "graylog_seen",
    "graylog_timestamp",
    "cli_response_ms",
    "cli_to_sniffer_ms",
    "sniffer_to_graylog_ms",
    "cli_to_graylog_ms",
    "result",
    "result_description",
    "identity",
    "cli_command",
    "cli_error",
]


@dataclass
class RunStatistics:
    """Aggregated counts derived from the test events."""

    total: int = 0
    cli_hit: int = 0
    cli_miss: int = 0
    cli_unknown: int = 0
    sniffer_hit: int = 0
    sniffer_miss: int = 0
    sniffer_unknown: int = 0
    sniffer_not_enabled: int = 0
    graylog_hit: int = 0
    graylog_miss: int = 0
    graylog_unknown: int = 0
    graylog_not_enabled: int = 0
    debug_hit: int = 0
    by_status: Dict[str, int] = field(default_factory=dict)
    failed_event_ids: List[str] = field(default_factory=list)
    cli_response_ms: List[float] = field(default_factory=list)
    cli_to_sniffer_ms: List[float] = field(default_factory=list)
    sniffer_to_graylog_ms: List[float] = field(default_factory=list)
    cli_to_graylog_ms: List[float] = field(default_factory=list)
    streaks: Dict[str, Any] = field(default_factory=dict)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    identity_matches: int = 0
    events_with_identity: int = 0

    @property
    def complete_success(self) -> int:
        return self.by_status.get(FinalStatus.SUCCESS.value, 0)

    @property
    def success_rate(self) -> float:
        if not self.total:
            return 0.0
        return (self.complete_success / self.total) * 100.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_test_events": self.total,
            "cli": {"hit": self.cli_hit, "miss": self.cli_miss, "unknown": self.cli_unknown},
            "sniffer": {
                "hit": self.sniffer_hit,
                "miss": self.sniffer_miss,
                "unknown": self.sniffer_unknown,
                "not_enabled": self.sniffer_not_enabled,
            },
            "graylog": {
                "hit": self.graylog_hit,
                "miss": self.graylog_miss,
                "unknown": self.graylog_unknown,
                "not_enabled": self.graylog_not_enabled,
            },
            "debug_hit": self.debug_hit,
            "by_result": dict(self.by_status),
            "complete_success": self.complete_success,
            "success_rate_percent": round(self.success_rate, 2),
            "failed_event_ids": list(self.failed_event_ids),
            "streaks": dict(self.streaks),
            "timeline": list(self.timeline),
            "identity": {
                "claims_matched_by_identity": self.identity_matches,
                "events_with_identity_key": self.events_with_identity,
            },
            "timings_ms": {
                "cli_response": _describe(self.cli_response_ms),
                "cli_to_sniffer": _describe(self.cli_to_sniffer_ms),
                "sniffer_to_graylog": _describe(self.sniffer_to_graylog_ms),
                "cli_to_graylog": _describe(self.cli_to_graylog_ms),
            },
        }


def _percentile(ordered: List[float], fraction: float) -> float:
    if not ordered:
        return 0.0
    index = min(int(round(fraction * (len(ordered) - 1))), len(ordered) - 1)
    return ordered[index]


def _describe(values: List[float]) -> Optional[Dict[str, float]]:
    if not values:
        return None
    ordered = sorted(values)
    return {
        "count": len(ordered),
        "min": round(ordered[0], 1),
        "avg": round(statistics.fmean(ordered), 1),
        "median": round(statistics.median(ordered), 1),
        "p95": round(_percentile(ordered, 0.95), 1),
        "max": round(ordered[-1], 1),
    }


def _streaks(events: List[TestEvent]) -> Dict[str, Any]:
    """Longest runs of consecutive success and failure.

    For an intermittent fault this separates "one in twenty, at random" from
    "fine for ten minutes, then eight in a row" -- very different problems.
    """
    longest_fail = longest_ok = current_fail = current_ok = 0
    first_failure = last_failure = None
    for event in events:
        if event.final_status is FinalStatus.SUCCESS:
            current_ok += 1
            current_fail = 0
            longest_ok = max(longest_ok, current_ok)
        else:
            current_fail += 1
            current_ok = 0
            longest_fail = max(longest_fail, current_fail)
            if first_failure is None:
                first_failure = event
            last_failure = event
    return {
        "longest_success_streak": longest_ok,
        "longest_failure_streak": longest_fail,
        "first_failure": first_failure.event_id if first_failure else None,
        "first_failure_at": (
            first_failure.cli_start_timestamp.isoformat(timespec="milliseconds")
            if first_failure
            else None
        ),
        "last_failure": last_failure.event_id if last_failure else None,
        "last_failure_at": (
            last_failure.cli_start_timestamp.isoformat(timespec="milliseconds")
            if last_failure
            else None
        ),
    }


def _timeline(events: List[TestEvent], buckets: int = 30) -> List[Dict[str, Any]]:
    """Failures per time bucket, for spotting clustering over the run."""
    if not events:
        return []
    start = events[0].cli_start_timestamp
    end = events[-1].cli_start_timestamp
    span = max((end - start).total_seconds(), 1e-6)
    size = span / buckets
    rows: List[Dict[str, Any]] = [
        {"index": i, "total": 0, "failed": 0} for i in range(buckets)
    ]
    for event in events:
        offset = (event.cli_start_timestamp - start).total_seconds()
        index = min(int(offset / size), buckets - 1) if size > 0 else 0
        rows[index]["total"] += 1
        if event.final_status is not FinalStatus.SUCCESS:
            rows[index]["failed"] += 1
    return rows


def render_timeline(rows: List[Dict[str, Any]]) -> str:
    """One-line picture of the run: . none, o some failures, X all failed."""
    if not rows:
        return ""
    out = []
    for row in rows:
        if not row["total"]:
            out.append(" ")
        elif not row["failed"]:
            out.append(".")
        elif row["failed"] == row["total"]:
            out.append("X")
        else:
            out.append("o")
    return "".join(out)


def _collect(value: Optional[float], target: List[float]) -> None:
    if value is not None:
        target.append(value)


def compute_statistics(events: List[TestEvent]) -> RunStatistics:
    stats = RunStatistics(total=len(events))
    for event in events:
        if event.cli_state is MatchState.HIT:
            stats.cli_hit += 1
        elif event.cli_state is MatchState.MISS:
            stats.cli_miss += 1
        else:
            stats.cli_unknown += 1

        for state, hit, miss, unknown, off in (
            (
                event.sniffer_state,
                "sniffer_hit",
                "sniffer_miss",
                "sniffer_unknown",
                "sniffer_not_enabled",
            ),
            (
                event.graylog_state,
                "graylog_hit",
                "graylog_miss",
                "graylog_unknown",
                "graylog_not_enabled",
            ),
        ):
            if state is MatchState.HIT:
                setattr(stats, hit, getattr(stats, hit) + 1)
            elif state is MatchState.MISS:
                setattr(stats, miss, getattr(stats, miss) + 1)
            elif state is MatchState.NOT_ENABLED:
                setattr(stats, off, getattr(stats, off) + 1)
            else:
                setattr(stats, unknown, getattr(stats, unknown) + 1)

        if event.debug_state is MatchState.HIT:
            stats.debug_hit += 1

        key = event.final_status.value
        stats.by_status[key] = stats.by_status.get(key, 0) + 1
        if event.final_status is not FinalStatus.SUCCESS:
            stats.failed_event_ids.append(event.event_id)

        _collect(event.cli_response_ms, stats.cli_response_ms)
        _collect(event.cli_to_sniffer_ms, stats.cli_to_sniffer_ms)
        _collect(event.sniffer_to_graylog_ms, stats.sniffer_to_graylog_ms)
        _collect(event.cli_to_graylog_ms, stats.cli_to_graylog_ms)
        if event.identity:
            stats.events_with_identity += 1

    stats.streaks = _streaks(events)
    stats.timeline = _timeline(events)
    return stats


def _clock(moment: Optional[datetime]) -> str:
    return f"{moment:%H:%M:%S.%f}"[:-3] if moment else "-"


def _format_duration(delta_seconds: float) -> str:
    total = int(round(delta_seconds))
    hours, remainder = divmod(total, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


def _timing_line(label: str, summary: Optional[Dict[str, float]]) -> Optional[str]:
    if not summary:
        return None
    return (
        f"  {label:<26}min {summary['min']:.0f} / med {summary['median']:.0f} / "
        f"p95 {summary['p95']:.0f} / max {summary['max']:.0f} ms  (n={summary['count']})"
    )


class ReportBuilder:
    """Builds and writes the end-of-run reports."""

    def __init__(
        self,
        config: AppConfig,
        tracker: EventTracker,
        started_at: datetime,
        run_stamp: str,
        group_stats: Optional[List[GroupStats]] = None,
        capabilities: Optional[Dict[str, bool]] = None,
        phase: int = 1,
        collector_detail: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._config = config
        self._tracker = tracker
        self._started_at = started_at
        self._run_stamp = run_stamp
        self._group_stats = group_stats or []
        self._capabilities = capabilities or {}
        self._phase = phase
        self._collector_detail = collector_detail or {}

    # -- text ---------------------------------------------------------------

    def render_summary(self, ended_at: datetime, stats: RunStatistics) -> str:
        cfg = self._config
        duration = (ended_at - self._started_at).total_seconds()
        sniffer_on = self._capabilities.get("sniffer", False)
        graylog_on = self._capabilities.get("graylog", False)
        debug_on = self._capabilities.get("debug", False)

        lines: List[str] = [
            _LINE,
            "FORTIMANAGER LOG TRANSMISSION TEST SUMMARY",
            _LINE,
            "",
            f"Target:                     {cfg.fortimanager.display_name} "
            f"({cfg.fortimanager.host}:{cfg.fortimanager.port})",
            f"Test started:               {self._started_at:%Y-%m-%d %H:%M:%S}",
            f"Test ended:                 {ended_at:%Y-%m-%d %H:%M:%S}",
            f"Test duration:              {_format_duration(duration)}",
            "",
            f"Test command executions:    {stats.total}",
            "",
            "CLI generated:",
            f"  HIT:                      {stats.cli_hit}",
            f"  MISS:                     {stats.cli_miss}",
            f"  UNKNOWN:                  {stats.cli_unknown}",
            "",
        ]

        if sniffer_on:
            lines += [
                "Sniffer (primary evidence of transmission):",
                f"  HIT:                      {stats.sniffer_hit}",
                f"  MISS:                     {stats.sniffer_miss}",
                f"  UNKNOWN:                  {stats.sniffer_unknown}",
            ]
            sniffer_detail = self._collector_detail.get("sniffer")
            if isinstance(sniffer_detail, dict):
                lines += [
                    f"  packets captured:         {sniffer_detail.get('packets_seen', 0)}",
                    f"  payload matches:          {sniffer_detail.get('payload_matches', 0)}",
                    f"  matches never claimed:    {sniffer_detail.get('unclaimed_matches', 0)}",
                ]
                if sniffer_detail.get("last_error"):
                    lines.append(f"  last error:               {sniffer_detail['last_error']}")
            lines.append("")
        else:
            lines += ["Sniffer:", "  NOT ENABLED", ""]

        if graylog_on:
            lines += [
                "Graylog (evidence the destination received and indexed it):",
                f"  HIT:                      {stats.graylog_hit}",
                f"  MISS:                     {stats.graylog_miss}",
                f"  UNKNOWN:                  {stats.graylog_unknown}",
            ]
            graylog_detail = self._collector_detail.get("graylog")
            if isinstance(graylog_detail, dict):
                lines += [
                    f"  polls:                    {graylog_detail.get('polls', 0)}"
                    + (
                        f" ({graylog_detail['failed_polls']} failed)"
                        if graylog_detail.get("failed_polls")
                        else ""
                    ),
                    f"  records examined:         {graylog_detail.get('records_examined', 0)}",
                    f"  content matches:          {graylog_detail.get('content_matches', 0)}",
                    f"  matches never claimed:    {graylog_detail.get('unclaimed_matches', 0)}",
                    f"  query:                    {graylog_detail.get('query', '')}",
                ]
                lag = graylog_detail.get("timestamp_lag_seconds")
                if isinstance(lag, dict):
                    lines.append(
                        f"  timestamp -> retrieval:   min {lag['min']:.1f}s / "
                        f"median {lag['median']:.1f}s / max {lag['max']:.1f}s"
                    )
                if graylog_detail.get("last_error"):
                    lines.append(f"  last error:               {graylog_detail['last_error']}")
                if graylog_detail.get("clock_warning"):
                    lines.append(f"  CLOCK WARNING:            {graylog_detail['clock_warning']}")
            lines.append("")
        else:
            lines += ["Graylog:", "  NOT ENABLED", ""]

        if debug_on:
            lines += [
                "Debug evidence (diagnostic only, never proof of transmission):",
                f"  HIT:                      {stats.debug_hit}",
            ]
            debug_detail = self._collector_detail.get("debug")
            if isinstance(debug_detail, dict):
                lines += [
                    f"  lines captured:           {debug_detail.get('lines_seen', 0)}",
                    f"  matching lines:           {debug_detail.get('matches', 0)}",
                ]
                if debug_detail.get("last_error"):
                    lines.append(f"  last error:               {debug_detail['last_error']}")
            lines.append("")

        if sniffer_on or graylog_on:
            chain = " -> ".join(
                ["CLI"] + (["Sniffer"] if sniffer_on else []) + (["Graylog"] if graylog_on else [])
            )
            lines += [
                "Complete success:",
                f"  {chain}: {stats.complete_success}",
                "",
            ]
            if sniffer_on:
                lines += [
                    "Generated but not transmitted:",
                    f"  {stats.by_status.get(FinalStatus.GENERATED_NOT_TRANSMITTED.value, 0)}",
                    "",
                ]
            if graylog_on:
                lines += [
                    "Transmitted but missing from Graylog:",
                    f"  {stats.by_status.get(FinalStatus.TRANSMITTED_NOT_IN_GRAYLOG.value, 0)}",
                    "",
                    "In Graylog with no matching packet:",
                    f"  {stats.by_status.get(FinalStatus.IN_GRAYLOG_WITHOUT_PACKET.value, 0)}",
                    "",
                ]
        else:
            lines += [
                "Complete success:",
                f"  {stats.complete_success}",
                "",
            ]

        lines += [
            "Success rate:",
            f"  {stats.success_rate:.2f}%",
            "",
        ]

        timing_lines = [
            line
            for line in (
                _timing_line("CLI response:", _describe(stats.cli_response_ms)),
                _timing_line("CLI -> packet:", _describe(stats.cli_to_sniffer_ms)),
                _timing_line("Packet -> Graylog:", _describe(stats.sniffer_to_graylog_ms)),
                _timing_line("CLI -> Graylog:", _describe(stats.cli_to_graylog_ms)),
            )
            if line
        ]
        if timing_lines:
            lines += ["Timings:"] + timing_lines + [""]

        if self._group_stats:
            lines.append("Command groups:")
            for group in self._group_stats:
                detail = (
                    f"  {group.name:<24} runs={group.executions} "
                    f"errors={group.command_errors} "
                    f"skipped={group.skipped_overruns} "
                    f"session_failures={group.session_failures}"
                )
                lines.append(detail)
            lines.append("")

        if stats.streaks and stats.total > 1:
            streaks = stats.streaks
            lines.append("Failure pattern:")
            lines.append(
                f"  longest run of consecutive successes: "
                f"{streaks.get('longest_success_streak', 0)}"
            )
            lines.append(
                f"  longest run of consecutive failures:  "
                f"{streaks.get('longest_failure_streak', 0)}"
            )
            if streaks.get("first_failure"):
                lines.append(
                    f"  first failure: {streaks['first_failure']} at "
                    f"{str(streaks.get('first_failure_at', ''))[11:23]}"
                )
                lines.append(
                    f"  last failure:  {streaks['last_failure']} at "
                    f"{str(streaks.get('last_failure_at', ''))[11:23]}"
                )
            timeline = render_timeline(stats.timeline)
            if timeline.strip():
                lines.append("")
                lines.append("  Run timeline (left = start, right = end):")
                lines.append(f"    [{timeline}]")
                lines.append("    . all passed   o some failed   X all failed")
            lines.append("")

        if stats.identity_matches or stats.events_with_identity:
            lines.append("Identity correlation:")
            lines.append(
                f"  events carrying an identity key:  {stats.events_with_identity}"
                f" of {stats.total}"
            )
            lines.append(
                f"  claims matched by identity:       {stats.identity_matches}"
            )
            lines.append(
                "  (the rest were matched by arrival order inside the time window)"
            )
            lines.append("")

        if stats.failed_event_ids:
            lines.append(f"Failed test events ({len(stats.failed_event_ids)}):")
            lines.extend(f"  {event_id}" for event_id in stats.failed_event_ids)
            lines.append("")

            lines.append("Failure breakdown:")
            for status_value, count in sorted(stats.by_status.items()):
                if status_value == FinalStatus.SUCCESS.value:
                    continue
                description = FinalStatus(status_value).description
                lines.append(f"  {count:>5}  {description}")
            lines.append("")

        note: List[str] = []
        if not sniffer_on and not graylog_on:
            note = [
                "NOTE: no transmission or delivery evidence was collected. The results above",
                "      rest on the FortiManager CLI response alone, which is a claim that the",
                "      event was generated, not evidence that a packet was transmitted.",
            ]
        elif not graylog_on:
            note = [
                "NOTE: Graylog is not enabled, so delivery to the log server was not verified.",
                "      A SUCCESS above means FortiManager reported generating the event and a",
                "      matching packet was observed leaving it.",
            ]
        elif not sniffer_on:
            note = [
                "NOTE: the sniffer is not enabled, so there is no evidence the event actually",
                "      left FortiManager. A SUCCESS above means it was generated and later",
                "      found in Graylog, which is strong but does not localise a failure.",
            ]
        if note:
            lines += note + [""]

        lines.append(_LINE)
        return "\n".join(lines)

    # -- files --------------------------------------------------------------

    def _report_path(self, name: str) -> Path:
        directory = self._config.logging.reports_dir
        directory.mkdir(parents=True, exist_ok=True)
        return directory / name

    def write_summary(self, text: str) -> Path:
        path = self._report_path(f"summary_{self._run_stamp}.txt")
        path.write_text(text.rstrip("\n") + "\n", encoding="utf-8")
        return path

    def _metadata(self, ended_at: datetime) -> Dict[str, Any]:
        cfg = self._config
        return {
            "tool_version": __version__,
            "phase": self._phase,
            "config_file": str(cfg.source_path),
            "target": {
                "device_name": cfg.fortimanager.device_name,
                "host": cfg.fortimanager.host,
                "port": cfg.fortimanager.port,
                "username": cfg.fortimanager.username,
            },
            "test_started": self._started_at.isoformat(timespec="milliseconds"),
            "test_ended": ended_at.isoformat(timespec="milliseconds"),
            "duration_seconds": round((ended_at - self._started_at).total_seconds(), 3),
            "correlation": {
                "cli_success_pattern": cfg.correlation.cli_success_pattern,
                "expected_message": cfg.correlation.expected_message,
                "sniffer_match_pattern": cfg.correlation.sniffer_match_pattern,
                "graylog_match_pattern": cfg.correlation.graylog_match_pattern,
                "timeout_seconds": cfg.correlation.timeout_seconds,
                "timestamp_tolerance_seconds": cfg.correlation.timestamp_tolerance_seconds,
                "allow_reuse": cfg.correlation.allow_reuse,
            },
            "collectors_enabled": dict(self._capabilities),
            "collectors": dict(self._collector_detail),
            "sniffer_command": (
                self._config.sniffer.command if self._config.sniffer.enabled else None
            ),
            "command_groups": [
                {
                    "name": g.name,
                    "executions": g.executions,
                    "test_events": g.test_events,
                    "command_errors": g.command_errors,
                    "skipped_overruns": g.skipped_overruns,
                    "session_failures": g.session_failures,
                    "average_duration_ms": g.average_duration_ms,
                    "last_error": g.last_error,
                }
                for g in self._group_stats
            ],
        }

    def write_json(self, ended_at: datetime, stats: RunStatistics, include_raw: bool = False) -> Path:
        path = self._report_path(f"events_{self._run_stamp}.json")
        document = {
            "metadata": self._metadata(ended_at),
            "statistics": stats.to_dict(),
            "events": [e.to_dict(include_raw=include_raw) for e in self._tracker.events],
        }
        with path.open("w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2, default=str)
            handle.write("\n")
        return path

    def render_detail(self) -> str:
        """Per-event human-readable breakdown, one block per test event."""
        cfg = self._capabilities
        lines: List[str] = [
            _LINE,
            "PER-EVENT DETAIL",
            _LINE,
            "",
            "One block per execution of the test command. Times are local.",
            "",
        ]
        for event in self._tracker.events:
            lines.append(event.event_id)
            lines.append("")
            lines.append(f"  CLI execution:        {event.cli_state.value}")
            lines.append(
                f"  Event generated:      "
                f"{'HIT' if event.cli_generated else event.cli_state.value}"
            )
            if cfg.get("debug"):
                lines.append(
                    f"  Debug evidence:       {event.debug_state.value}"
                    + (
                        f"  ({len(event.debug_matches)} line(s))"
                        if event.debug_matches
                        else ""
                    )
                )
            lines.append(f"  Packet observed:      {event.sniffer_state.value}")
            lines.append(f"  Graylog received:     {event.graylog_state.value}")
            lines.append("")

            lines.append(f"  CLI timestamp:        {_clock(event.cli_start_timestamp)}")
            if event.sniffer_timestamp:
                lines.append(f"  Sniffer timestamp:    {_clock(event.sniffer_timestamp)}")
            if event.graylog_timestamp:
                lines.append(f"  Graylog timestamp:    {_clock(event.graylog_timestamp)}")

            deltas = [
                ("CLI -> packet:", event.cli_to_sniffer_ms),
                ("Packet -> Graylog:", event.sniffer_to_graylog_ms),
                ("CLI -> Graylog:", event.cli_to_graylog_ms),
            ]
            shown = [(label, value) for label, value in deltas if value is not None]
            if shown:
                lines.append("")
                for label, value in shown:
                    lines.append(f"  {label:<22}{value:.0f} ms")

            if event.identity:
                lines.append("")
                lines.append(
                    "  Identity:             "
                    + " ".join(f"{k}={v}" for k, v in sorted(event.identity.items()))
                )
            if event.cli_error:
                lines.append(f"  CLI problem:          {event.cli_error}")

            lines.append("")
            lines.append(f"  RESULT: {event.final_status.description}")
            lines.append("")
            lines.append("-" * 60)
            lines.append("")
        if not self._tracker.events:
            lines.append("No test events were executed.")
            lines.append("")
        return "\n".join(lines)

    def write_detail(self) -> Path:
        path = self._report_path(f"detail_{self._run_stamp}.txt")
        path.write_text(self.render_detail(), encoding="utf-8")
        return path

    def write_csv(self) -> Path:
        path = self._report_path(f"events_{self._run_stamp}.csv")
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=_CSV_FIELDS, extrasaction="ignore")
            writer.writeheader()
            for event in self._tracker.events:
                writer.writerow(event.to_dict())
        return path

    def write_all(
        self, ended_at: datetime, stats: RunStatistics, summary_text: str
    ) -> Dict[str, Path]:
        return {
            "summary": self.write_summary(summary_text),
            "detail": self.write_detail(),
            "json": self.write_json(ended_at, stats),
            "csv": self.write_csv(),
        }
