"""Graylog collector: polls for delivered events and records observations.

Like every other collector, this one only observes. It never decides which test
event a Graylog record belongs to; it records GRAYLOG observations and lets the
correlator claim them.

Two rules from the specification are enforced here:

* **The search window starts at the authoritative test-start timestamp** and
  never reaches earlier, so a historical ``Power 1 goes to online`` from last
  week can never be correlated with this run.
* **Every record is deduplicated by Graylog message id**, because consecutive
  polls deliberately overlap (``poll_overlap_seconds``) so a record indexed
  just as a window closed is not lost.

Clock handling is the subtle part. Correlation is anchored on *local* time, so
each message's Graylog timestamp is converted to local time. The lag between
that timestamp and when the poll retrieved it is tracked across the run and
reported: a large negative lag means Graylog's clock is ahead of this machine's
and correlation will silently fail unless the tolerance is raised.
"""

from __future__ import annotations

import asyncio
import re
import statistics
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set

from .config import CorrelationConfig, GraylogConfig
from .events import EventTracker, Source
from .graylog_client import (
    GraylogClient,
    GraylogError,
    GraylogMessage,
    build_query_string,
    describe_window,
    local_to_utc,
    utc_now,
)
from .identity import IdentityExtractor
from .logbus import LogBus

_MAX_SEEN_IDS = 20000


class GraylogCollector:
    """Polls Graylog for the expected event and records matches."""

    def __init__(
        self,
        config: GraylogConfig,
        correlation: CorrelationConfig,
        tracker: EventTracker,
        logbus: LogBus,
        client: GraylogClient,
        test_start: datetime,
        diagnostics=None,
    ) -> None:
        self._config = config
        self._correlation = correlation
        self._tracker = tracker
        self._log = logbus
        self._client = client
        self._diagnostics = diagnostics

        # Authoritative floor for every search: nothing before the test started.
        self._floor_utc = local_to_utc(test_start)
        self._overlap = timedelta(seconds=config.poll_overlap_seconds)
        # Each poll re-scans a rolling window rather than only the slice since
        # the last poll. A record indexed later than the window it belongs to
        # would otherwise fall permanently behind the advancing start time and
        # never be returned at all -- silently, as a MISS. Dedup by message id
        # makes the repeated scanning free of double counting.
        self._lookback = timedelta(
            seconds=(
                config.poll_interval_seconds
                + config.poll_overlap_seconds
                + config.max_indexing_lag_seconds
            )
        )

        self._pattern = correlation.graylog_match_pattern
        self._regex: Optional[re.Pattern[str]] = (
            re.compile(self._pattern, re.IGNORECASE) if correlation.pattern_is_regex else None
        )
        self._needle = self._pattern.lower()

        self.query = build_query_string(
            config.filters,
            config.query_extra,
            self._pattern if config.include_message_in_query else None,
        )

        self._identity = IdentityExtractor(
            [(f) for f in correlation.identity.fields],
            enabled=correlation.identity.enabled,
        )

        self._seen: Set[str] = set()
        self._seen_order: List[str] = []

        self.healthy = False
        self.started = False
        self.polls = 0
        self.failed_polls = 0
        self.messages_seen = 0
        self.matches = 0
        self.last_error: Optional[str] = None
        self.server_description: Optional[str] = None
        self._lags: List[float] = []

    # -- lifecycle ----------------------------------------------------------

    async def start(self) -> bool:
        try:
            self.server_description = await self._client.connect()
        except GraylogError as exc:
            self.last_error = str(exc)
            self._log.log(
                Source.GRAYLOG,
                f"could not connect: {exc} "
                f"Delivery evidence will be reported UNKNOWN, not MISS.",
            )
            return False
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
            self._log.log(Source.GRAYLOG, f"could not connect: {self.last_error}")
            return False

        self._log.log(Source.GRAYLOG, f"connected to {self.server_description}")
        self._log.log(Source.GRAYLOG, f"query: {self.query}")
        self._log.log(
            Source.GRAYLOG,
            f"searching only for records at or after the test start "
            f"({self._floor_utc.isoformat(timespec='milliseconds')}); "
            f"polling every {self._config.poll_interval_seconds:g}s, re-scanning the "
            f"last {self._lookback.total_seconds():g}s each time so records indexed "
            f"late are still found (deduplicated by message id)",
        )
        if not self._config.include_message_in_query:
            self._log.log(
                Source.GRAYLOG,
                f"message content is verified locally, not in the query; records "
                f"matching the filters but lacking {self._pattern!r} are visible in "
                f"debug mode as near misses",
            )
        self.healthy = True
        self.started = True
        return True

    async def run(self, shutdown: asyncio.Event) -> None:
        """Poll until shutdown is requested."""
        while not shutdown.is_set():
            try:
                await self._poll_once()
            except asyncio.CancelledError:
                raise
            except GraylogError as exc:
                self._note_poll_failure(str(exc))
            except Exception as exc:
                self._note_poll_failure(f"{type(exc).__name__}: {exc}")

            try:
                await asyncio.wait_for(
                    shutdown.wait(), timeout=self._config.poll_interval_seconds
                )
                return
            except asyncio.TimeoutError:
                continue

    async def final_poll(self) -> None:
        """One last poll at shutdown, for records indexed after the last one."""
        if not self.started:
            return
        try:
            await self._poll_once(final=True)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._note_poll_failure(f"{type(exc).__name__}: {exc}")

    async def stop(self) -> None:
        await self._client.close()
        self.healthy = False
        if self.started:
            self._log.log(
                Source.GRAYLOG,
                f"stopped after {self.polls} poll(s), {self.messages_seen} record(s) "
                f"examined, {self.matches} match(es)",
            )

    def _note_poll_failure(self, message: str) -> None:
        self.failed_polls += 1
        self.last_error = message
        # A failed poll means we cannot see Graylog right now, so events in this
        # window must resolve UNKNOWN rather than MISS.
        self.healthy = False
        self._log.log(Source.GRAYLOG, f"poll failed: {message}")

    # -- polling ------------------------------------------------------------

    async def _poll_once(self, final: bool = False) -> None:
        to = utc_now()
        frm = max(self._floor_utc, to - self._lookback)
        if to <= frm and not final:
            return

        messages, _raw = await self._client.search(frm, to, self.query)
        self.polls += 1
        self.healthy = True

        fresh = 0
        for message in messages:
            if not self._remember(message):
                continue
            fresh += 1
            self._handle(message)

        if fresh or final:
            self._log.log(
                Source.GRAYLOG,
                f"poll {self.polls}: {len(messages)} record(s) in {describe_window(frm, to)}, "
                f"{fresh} new",
            )

    def _remember(self, message: GraylogMessage) -> bool:
        """Track seen ids so overlapping windows do not double-count."""
        key = message.message_id or (
            f"{message.timestamp_utc}|{message.text[:120]}"
        )
        if key in self._seen:
            return False
        self._seen.add(key)
        self._seen_order.append(key)
        if len(self._seen_order) > _MAX_SEEN_IDS:
            evicted = self._seen_order[: _MAX_SEEN_IDS // 4]
            self._seen_order = self._seen_order[_MAX_SEEN_IDS // 4 :]
            self._seen.difference_update(evicted)
        return True

    # -- matching -----------------------------------------------------------

    def _find(self, text: str) -> bool:
        if self._regex is not None:
            return self._regex.search(text) is not None
        return self._needle in text.lower()

    def _handle(self, message: GraylogMessage) -> None:
        self.messages_seen += 1
        label, text = message.searchable(self._config.message_field)
        matched = bool(text) and self._find(text)
        observed_at = message.correlation_time

        if message.timestamp_local is not None:
            self._lags.append(
                (message.retrieved_at - message.timestamp_local).total_seconds()
            )

        if matched:
            self.matches += 1
            self._tracker.record(
                Source.GRAYLOG,
                observed_at,
                text,
                fields=self._observation_fields(message, label),
            )
            self._log.log(
                Source.GRAYLOG,
                f"MATCH #{self.matches} on {label}: "
                f"{message.timestamp_local or message.retrieved_at:%H:%M:%S.%f}"[:-3]
                + f" id={message.message_id[:12] or '<none>'}",
            )

        self._record_candidate(message, label, text, matched)

    def _observation_fields(self, message: GraylogMessage, label: str) -> Dict[str, Any]:
        interesting = (
            "source",
            "facility",
            "level",
            "devid",
            "devname",
            "logid",
            "log_id",
            "seq",
            "type",
            "subtype",
        )
        fields: Dict[str, Any] = {
            "message_id": message.message_id,
            "matched_on": label,
            "index": message.index,
            "graylog_timestamp": (
                message.timestamp_utc.isoformat(timespec="milliseconds")
                if message.timestamp_utc
                else None
            ),
            "retrieved_at": message.retrieved_at.isoformat(timespec="milliseconds"),
        }
        for key in interesting:
            if key in message.fields:
                fields[key] = message.fields[key]

        identity = self._identity.extract(
            message.text,
            str(message.fields.get(self._config.message_field, "")),
            " ".join(f"{k}={v}" for k, v in message.fields.items()),
        )
        if identity:
            fields["identity"] = identity
        return fields

    def _record_candidate(
        self, message: GraylogMessage, label: str, text: str, matched: bool
    ) -> None:
        if self._diagnostics is None:
            return
        from .diagnostics import Candidate, Reason

        preview = getattr(self._diagnostics._config, "payload_preview_chars", 300)
        if matched:
            code = Reason.MATCHED
            detail = f"expected message found in the {label} field"
        else:
            code = Reason.PATTERN_ABSENT
            detail = (
                f"record matched the Graylog filters but {self._pattern!r} is not "
                f"present in its {label} field"
            )

        self._diagnostics.add_candidate(
            Candidate(
                source=Source.GRAYLOG,
                observed_at=message.correlation_time,
                summary=(
                    f"id={message.message_id[:12] or '<none>'} "
                    f"source={message.fields.get('source', '?')} "
                    f"index={message.index or '?'}"
                ),
                matched=matched,
                code=code,
                detail=detail,
                excerpt=text[:preview],
                raw=text,
                fields={
                    k: v
                    for k, v in message.fields.items()
                    if isinstance(v, (str, int, float, bool))
                },
            )
        )

    # -- reporting ----------------------------------------------------------

    @property
    def lag_summary(self) -> Optional[Dict[str, float]]:
        """Message-timestamp to retrieval lag, in seconds."""
        if not self._lags:
            return None
        ordered = sorted(self._lags)
        return {
            "count": len(ordered),
            "min": round(ordered[0], 3),
            "median": round(statistics.median(ordered), 3),
            "max": round(ordered[-1], 3),
        }

    def clock_warning(self) -> Optional[str]:
        """Flag a clock offset large enough to break correlation.

        Lag is normally positive: a record is retrieved after it was written.
        A consistently negative lag means Graylog timestamps are in this
        machine's future, so matching records fall outside every window.
        """
        summary = self.lag_summary
        if summary is None:
            return None
        tolerance = self._correlation.timestamp_tolerance_seconds
        median = summary["median"]
        if median < -tolerance:
            return (
                f"Graylog message timestamps run {abs(median):.1f}s AHEAD of this "
                f"computer's clock, which is more than correlation."
                f"timestamp_tolerance_seconds ({tolerance:g}s). Matching records will "
                f"fall outside every correlation window. Fix NTP on one of the hosts, "
                f"or raise the tolerance above {abs(median):.0f}s."
            )
        allowance = self._config.max_indexing_lag_seconds
        if summary["max"] > allowance:
            return (
                f"Graylog indexed a record {summary['max']:.1f}s after its own "
                f"timestamp, which is more than graylog.max_indexing_lag_seconds "
                f"({allowance:g}s). Records slower than that can fall outside every "
                f"search window and be reported MISS when they were in fact "
                f"delivered. Raise max_indexing_lag_seconds above {summary['max']:.0f}s."
            )
        window = self._correlation.timeout_seconds
        if median > window:
            return (
                f"Graylog records arrive a median of {median:.1f}s after their own "
                f"timestamp, which exceeds correlation.timeout_seconds ({window:g}s). "
                f"If indexing lag is the cause, raise the timeout; the events are "
                f"arriving, just later than the window allows."
            )
        return None
