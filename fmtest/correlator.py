"""Correlation engine: assigns observations to individual test events.

The rules, in order:

1. **Every CLI execution is its own test event.** Nothing here ever asks "did
   this message appear at some point"; the question is always "did *this* test
   event get its evidence".
2. **Observations are consumable.** An observation claimed by ``TEST-000001``
   can never satisfy ``TEST-000002``. That is what makes a run of identical
   ``Power 1 goes to online`` events countable at all. ``correlation.allow_reuse``
   turns this off if you ever need it.
3. **Oldest event first.** Events are resolved in creation order, so the
   earliest unclaimed observation goes to the earliest waiting event.
4. **Windows, not equality.** An observation is eligible from
   ``cli_start - timestamp_tolerance`` to ``cli_start + timeout``, because
   FortiManager, this computer and Graylog do not share a clock.
5. **A dead collector yields UNKNOWN, not MISS.** If the sniffer session
   dropped, we did not observe the packet; we did not establish its absence.

The engine is deliberately structured around a per-source :class:`SourceBinding`
so additional evidence sources and richer matching rules (source/destination IP,
log_id, sequence number, device id) can be added without reshaping the loop:
each binding may carry a ``predicate`` that inspects an observation's extracted
fields before it is claimed.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Tuple

from .config import CorrelationConfig
from .events import EventTracker, MatchState, Observation, Source, TestEvent
from . import identity as ident
from .logbus import LogBus

# Attribute names on TestEvent for each correlated source.
_STATE_ATTR: Dict[Source, str] = {
    Source.SNIFFER: "sniffer_state",
    Source.DEBUG: "debug_state",
    Source.GRAYLOG: "graylog_state",
}
_TIMESTAMP_ATTR: Dict[Source, Optional[str]] = {
    Source.SNIFFER: "sniffer_timestamp",
    Source.DEBUG: None,
    Source.GRAYLOG: "graylog_timestamp",
}
_MATCH_ATTR: Dict[Source, Optional[str]] = {
    Source.SNIFFER: "sniffer_match",
    Source.DEBUG: None,
    Source.GRAYLOG: "graylog_match",
}


@dataclass
class SourceBinding:
    """How one evidence source participates in correlation."""

    source: Source
    enabled: bool
    health: Callable[[], bool] = lambda: True
    multiple: bool = False
    """True for sources where several observations may belong to one event."""
    predicate: Optional[Callable[[TestEvent, Observation], bool]] = None
    """Optional secondary-field check applied before an observation is claimed."""

    def is_healthy(self) -> bool:
        try:
            return bool(self.health())
        except Exception:
            return False


@dataclass
class CorrelatorStats:
    resolved: int = 0
    claimed: Dict[str, int] = field(default_factory=dict)
    expired: int = 0
    identity_matches: int = 0

    def record_claim(self, source: Source) -> None:
        self.claimed[source.value] = self.claimed.get(source.value, 0) + 1


class Correlator:
    """Matches observations to test events and closes events when due."""

    def __init__(
        self,
        tracker: EventTracker,
        config: CorrelationConfig,
        logbus: LogBus,
        tick_seconds: float = 0.25,
        diagnostics=None,
    ) -> None:
        self._tracker = tracker
        self._config = config
        self._log = logbus
        self._tick = tick_seconds
        self._bindings: List[SourceBinding] = []
        self._window = timedelta(seconds=config.timeout_seconds)
        self._tolerance = timedelta(seconds=config.timestamp_tolerance_seconds)
        self._diagnostics = diagnostics
        self._identity_enabled = config.identity.enabled and bool(config.identity.fields)
        self._identity_required = config.identity.require
        self.stats = CorrelatorStats()

    # -- configuration ------------------------------------------------------

    def bind(self, binding: SourceBinding) -> None:
        self._bindings.append(binding)

    @property
    def bindings(self) -> List[SourceBinding]:
        return list(self._bindings)

    def _binding(self, source: Source) -> Optional[SourceBinding]:
        for binding in self._bindings:
            if binding.source is source:
                return binding
        return None

    def deadline_for(self, event: TestEvent) -> datetime:
        """When an event stops waiting for evidence."""
        return event.cli_start_timestamp + self._window + self._tolerance

    def window_end_for(
        self, event: TestEvent, next_event: Optional[TestEvent]
    ) -> datetime:
        """Latest observation time this event may claim.

        Normally ``cli_start + timeout``. When ``bound_window_by_next_event`` is
        on (the default), the window is also cut off shortly after the *next*
        test command was issued: evidence produced after the next execution
        began belongs to that execution, not this one. Without this bound, an
        earlier event with a long window greedily consumes the later event's
        evidence -- which matters most for supplemental sources where several
        observations may be claimed per event.
        """
        end = event.cli_start_timestamp + self._window
        if self._config.bound_window_by_next_event and next_event is not None:
            # No tolerance is added here on purpose. The next event's own window
            # opens at its start minus the tolerance, so the two overlap by that
            # much and the earlier event still gets first look at the overlap --
            # but nothing produced after the next command was issued can be
            # swallowed by the earlier event.
            end = min(end, next_event.cli_start_timestamp)
        return end

    # -- claiming -----------------------------------------------------------

    def _predicate_for(self, binding: SourceBinding, event: TestEvent):
        if binding.predicate is None:
            return None
        return lambda observation: binding.predicate(event, observation)

    def _claim(
        self,
        event: TestEvent,
        binding: SourceBinding,
        window_end: Optional[datetime] = None,
    ) -> Optional[Observation]:
        return self._tracker.claim(
            binding.source,
            event.event_id,
            not_before=event.cli_start_timestamp,
            window=self._window,
            tolerance=self._tolerance,
            predicate=self._predicate_for(binding, event),
            not_after=window_end,
        )

    def _apply(
        self,
        event: TestEvent,
        binding: SourceBinding,
        observation: Observation,
        by_identity: bool = False,
    ) -> None:
        source = binding.source
        setattr(event, _STATE_ATTR[source], MatchState.HIT)

        timestamp_attr = _TIMESTAMP_ATTR.get(source)
        if timestamp_attr and getattr(event, timestamp_attr) is None:
            setattr(event, timestamp_attr, observation.observed_at)

        match_attr = _MATCH_ATTR.get(source)
        if match_attr and getattr(event, match_attr) is None:
            setattr(event, match_attr, observation)

        if source is Source.DEBUG:
            event.debug_matches.append(observation)

        # Carry the observation's secondary fields onto the event so later
        # phases and the JSON report can use them.
        for key, value in observation.fields.items():
            event.fields.setdefault(f"{source.value.lower()}_{key}", value)

        # Learn the event's identity from the first evidence that carries one,
        # so later sources can be matched by identity instead of by order.
        observed_identity = self._identity_of(observation)
        if self._identity_enabled and observed_identity:
            for key, value in observed_identity.items():
                event.identity.setdefault(key, value)

        self.stats.record_claim(source)
        if by_identity:
            self.stats.identity_matches += 1

        detail = _describe(source, event, observation, by_identity)
        self._log.log(source, f"HIT{detail}", event.event_id)

    def _identity_of(self, observation: Observation) -> Dict[str, str]:
        value = observation.fields.get("identity")
        return value if isinstance(value, dict) else {}

    def _claim_with_identity(
        self,
        event: TestEvent,
        binding: SourceBinding,
        window_end: Optional[datetime],
    ) -> Tuple[Optional[Observation], bool]:
        """Claim an observation, preferring one whose identity matches the event.

        Returns ``(observation, by_identity)``. Two passes:

        1. If this event already carries identity keys from evidence claimed
           earlier, look for an observation agreeing with them. A match here is
           positive proof the two observations describe the same execution, and
           order stops mattering.
        2. Otherwise (or if pass 1 found nothing and identity is not required),
           fall back to the ordered, time-windowed claim.

        Observations whose identity *conflicts* with the event are never taken
        in pass 2 either -- disagreement is evidence, absence is not.
        """
        if self._identity_enabled and event.identity:
            observation = self._tracker.claim(
                binding.source,
                event.event_id,
                not_before=event.cli_start_timestamp,
                window=self._window,
                tolerance=self._tolerance,
                not_after=window_end,
                predicate=lambda obs: ident.matches(event.identity, self._identity_of(obs)),
            )
            if observation is not None:
                return observation, True
            if self._identity_required:
                return None, False

        def acceptable(obs: Observation) -> bool:
            if binding.predicate is not None and not binding.predicate(event, obs):
                return False
            if not self._identity_enabled or not event.identity:
                return True
            # Never take evidence that positively disagrees with what this
            # event has already been shown to be.
            _, _, conflicting = ident.compare(event.identity, self._identity_of(obs))
            return not conflicting

        observation = self._tracker.claim(
            binding.source,
            event.event_id,
            not_before=event.cli_start_timestamp,
            window=self._window,
            tolerance=self._tolerance,
            not_after=window_end,
            predicate=acceptable,
        )
        return observation, False

    def _try_sources(self, event: TestEvent, window_end: Optional[datetime] = None) -> None:
        for binding in self._bindings:
            if not binding.enabled:
                continue
            state = getattr(event, _STATE_ATTR[binding.source])
            if state is MatchState.NOT_ENABLED:
                continue
            if binding.multiple:
                # Supplemental sources may collect several observations.
                while True:
                    observation, by_identity = self._claim_with_identity(
                        event, binding, window_end
                    )
                    if observation is None:
                        break
                    self._apply(event, binding, observation, by_identity)
            elif state is MatchState.PENDING:
                observation, by_identity = self._claim_with_identity(
                    event, binding, window_end
                )
                if observation is not None:
                    self._apply(event, binding, observation, by_identity)

    # -- closing ------------------------------------------------------------

    def explain_miss(
        self, event: TestEvent, source: Source, window_start: datetime, window_end: datetime
    ) -> tuple:
        """Work out *why* a source produced no match. Returns (code, text).

        This inspects the observation queue rather than guessing: it can tell
        "nothing was ever recorded" from "something was recorded but arrived
        outside the window" from "it was claimed by an earlier event", and those
        three lead to completely different fixes.
        """
        from .diagnostics import Reason  # local import avoids a cycle

        queue = self._tracker.queues.get(source)
        items = queue.items if queue is not None else []
        if not items:
            return (
                Reason.NO_OBSERVATIONS,
                "no matching evidence was recorded by this collector at any point "
                "during the run",
            )

        in_window = [o for o in items if window_start <= o.observed_at <= window_end]
        if not in_window:
            nearest = min(
                items,
                key=lambda o: abs((o.observed_at - event.cli_start_timestamp).total_seconds()),
            )
            delta = (nearest.observed_at - event.cli_start_timestamp).total_seconds()
            return (
                Reason.OUTSIDE_WINDOW,
                f"{len(items)} matching observation(s) exist for this run, but none "
                f"inside this event's window; the nearest was {delta:+.3f}s from the "
                f"CLI command",
            )

        claimers = sorted({o.claimed_by for o in in_window if o.claimed_by})
        if claimers:
            return (
                Reason.ALREADY_CLAIMED,
                f"{len(in_window)} matching observation(s) fell inside the window but "
                f"were already claimed by {', '.join(claimers)}",
            )
        return (
            Reason.UNEXPLAINED,
            f"{len(in_window)} unclaimed matching observation(s) were inside the "
            f"window but none was claimed; this is unexpected",
        )

    def _finalise(
        self, event: TestEvent, when: datetime, next_event: Optional[TestEvent] = None
    ) -> None:
        from .diagnostics import Reason, SourceVerdict

        window_start = event.cli_start_timestamp - self._tolerance
        window_end = self.window_end_for(event, next_event)
        verdicts: List["SourceVerdict"] = []

        for binding in self._bindings:
            attribute = _STATE_ATTR[binding.source]
            state = getattr(event, attribute)

            if not binding.enabled or state is MatchState.NOT_ENABLED:
                verdicts.append(
                    SourceVerdict(
                        source=binding.source,
                        state=MatchState.NOT_ENABLED,
                        code=Reason.NOT_ENABLED,
                        reason="collector is not enabled for this run",
                    )
                )
                continue

            if state is MatchState.PENDING:
                if binding.is_healthy():
                    setattr(event, attribute, MatchState.MISS)
                    code, reason = self.explain_miss(
                        event, binding.source, window_start, window_end
                    )
                    self._log.log(binding.source, f"MISS ({code})", event.event_id)
                else:
                    # The collector was not running or had failed: absence of
                    # evidence here is not evidence of absence.
                    setattr(event, attribute, MatchState.UNKNOWN)
                    code = Reason.COLLECTOR_UNHEALTHY
                    reason = "the collector was not running during this window"
                    self._log.log(
                        binding.source,
                        "UNKNOWN (collector was not healthy during this window)",
                        event.event_id,
                    )
            else:
                code = Reason.MATCHED
                reason = "matching evidence was claimed for this event"

            verdicts.append(
                SourceVerdict(
                    source=binding.source,
                    state=getattr(event, attribute),
                    code=code,
                    reason=reason,
                    claimed=_claimed_observation(event, binding.source),
                )
            )

        status = event.close(when)
        self.stats.resolved += 1
        self._log.correlator(f"RESULT: {status.description}{_timings(event)}", event.event_id)

        if self._diagnostics is not None:
            self._attach_candidates(verdicts, window_start, window_end)
            self._refine_reasons(verdicts)
            self._diagnostics.write_event(event, verdicts, (window_start, window_end))

    @staticmethod
    def _refine_reasons(verdicts: List[Any]) -> None:
        """Replace a generic MISS reason with what the evidence actually shows.

        "no matching evidence was recorded" is true but unhelpful when the
        collector examined candidates and rejected them all for the same
        reason. Naming that reason is what turns a MISS into a lead.
        """
        from collections import Counter

        for verdict in verdicts:
            if verdict.state is not MatchState.MISS or not verdict.candidates:
                continue
            codes = Counter(c.code for c in verdict.candidates if not c.matched)
            if not codes:
                continue
            code, count = codes.most_common(1)[0]
            verdict.code = code
            verdict.reason = (
                f"{len(verdict.candidates)} candidate(s) were examined inside the "
                f"window and none matched; {count} of them for the same reason "
                f"({code})"
            )

    def _attach_candidates(
        self, verdicts: List[Any], window_start: datetime, window_end: datetime
    ) -> None:
        """Fill each verdict with the evidence the collector actually examined."""
        for verdict in verdicts:
            if verdict.state is MatchState.NOT_ENABLED:
                continue
            verdict.candidates = self._diagnostics.candidates_between(
                verdict.source, window_start, window_end
            )
            outside = self._diagnostics.candidates_outside(
                verdict.source, window_start, window_end
            )
            verdict.candidates_outside_window = len(outside)
            if outside and not verdict.candidates:
                nearest = min(
                    outside,
                    key=lambda c: min(
                        abs((c.observed_at - window_start).total_seconds()),
                        abs((c.observed_at - window_end).total_seconds()),
                    ),
                )
                verdict.nearest_outside_delta = (
                    nearest.observed_at - window_start
                ).total_seconds()

    # -- driving ------------------------------------------------------------

    def resolve(self, now: Optional[datetime] = None, force: bool = False) -> int:
        """One correlation pass. Returns the number of events closed."""
        moment = now or datetime.now()
        closed = 0
        # Creation order matters: the oldest waiting event has first claim on
        # the oldest unclaimed observation.
        events = self._tracker.events
        for index, event in enumerate(events):
            if not event.is_open:
                continue
            if event.cli_state is MatchState.PENDING:
                # The CLI command is still running; nothing to correlate yet.
                continue
            next_event = events[index + 1] if index + 1 < len(events) else None
            self._try_sources(event, self.window_end_for(event, next_event))
            if force or moment >= self.deadline_for(event):
                if not force:
                    self.stats.expired += 1
                self._finalise(event, moment, next_event)
                closed += 1
        return closed

    async def run(self, shutdown: asyncio.Event) -> None:
        """Periodically correlate until shutdown is requested."""
        while not shutdown.is_set():
            try:
                self.resolve()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self._log.correlator(f"correlation pass failed: {type(exc).__name__}: {exc}")
            try:
                await asyncio.wait_for(shutdown.wait(), timeout=self._tick)
                return
            except asyncio.TimeoutError:
                continue

    async def drain(self, timeout: float) -> None:
        """Let in-flight test events finish their windows, then close the rest.

        Called during shutdown so an event whose packet is still in the air is
        given its remaining window instead of being written off as a MISS.
        """
        if timeout <= 0:
            self.resolve(force=True)
            return

        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            self.resolve()
            open_events = self._tracker.open_events()
            if not open_events:
                return
            # Nothing left to wait for if every open event is already past due.
            now = datetime.now()
            if all(self.deadline_for(e) <= now for e in open_events):
                break
            await asyncio.sleep(min(self._tick, max(0.0, deadline - loop.time())))

        remaining = len(self._tracker.open_events())
        if remaining:
            self._log.correlator(
                f"closing {remaining} test event(s) whose evidence window did not complete"
            )
        self.resolve(force=True)


def _claimed_observation(event: TestEvent, source: Source) -> Optional[Observation]:
    if source is Source.SNIFFER:
        return event.sniffer_match
    if source is Source.GRAYLOG:
        return event.graylog_match
    if source is Source.DEBUG:
        return event.debug_matches[0] if event.debug_matches else None
    return None


def _describe(
    source: Source,
    event: TestEvent,
    observation: Observation,
    by_identity: bool = False,
) -> str:
    """Short suffix for a HIT log line, including the delta from the CLI."""
    delta_ms = (observation.observed_at - event.cli_start_timestamp).total_seconds() * 1000.0
    parts = [f"+{delta_ms:.0f} ms after CLI"]
    if by_identity:
        parts.append(f"matched by identity {ident.describe(event.identity)}")
    if source is Source.SNIFFER:
        src = observation.fields.get("src_ip")
        dst = observation.fields.get("dst_ip")
        if src and dst:
            sport = observation.fields.get("src_port")
            dport = observation.fields.get("dst_port")
            left = f"{src}:{sport}" if sport else str(src)
            right = f"{dst}:{dport}" if dport else str(dst)
            parts.append(f"{left} -> {right}")
        matched_on = observation.fields.get("matched_on")
        if matched_on:
            parts.append(f"matched on {matched_on}")
    return " (" + ", ".join(parts) + ")"


def _timings(event: TestEvent) -> str:
    pieces = []
    if event.cli_to_sniffer_ms is not None:
        pieces.append(f"CLI->packet {event.cli_to_sniffer_ms:.0f} ms")
    if event.sniffer_to_graylog_ms is not None:
        pieces.append(f"packet->Graylog {event.sniffer_to_graylog_ms:.0f} ms")
    if event.cli_to_graylog_ms is not None:
        pieces.append(f"CLI->Graylog {event.cli_to_graylog_ms:.0f} ms")
    return ("  [" + ", ".join(pieces) + "]") if pieces else ""
