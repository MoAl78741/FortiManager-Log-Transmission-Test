"""Turns executions of the test command into TEST events.

This module owns exactly one decision: given the CLI response to one execution
of the test command, did FortiManager *claim* it generated the event?

That claim is recorded as ``cli_state`` and as a CLI observation. It is never
treated as proof that a packet was transmitted -- that is the sniffer's job in
Phase 2, and the correlator's to weigh in Phase 4.

State mapping:

``HIT``
    The configured ``cli_success_pattern`` appeared in the response.
``MISS``
    A response came back, but without the success pattern (or with a
    configured failure pattern).
``UNKNOWN``
    No usable response: timeout, closed shell, write error. We did not observe
    the outcome, which is not the same as observing a failure.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from .config import CorrelationConfig, LoggingConfig
from .events import EventTracker, MatchState, Source, TestEvent
from .logbus import LogBus
from .shell import CommandResult, InteractiveShell


@dataclass(frozen=True)
class CollectorCapabilities:
    """Which evidence collectors are actually running this session.

    Phase 1 has none of them, so test events resolve on the CLI result alone.
    Later phases flip these flags on, which is what makes a test event stay
    open until the correlator can claim sniffer and Graylog observations.
    """

    sniffer: bool = False
    debug: bool = False
    graylog: bool = False

    @property
    def any_async_source(self) -> bool:
        """True when some collector may still contribute after the CLI returns.

        When this is False nothing else can ever update the event, so the probe
        closes it immediately. When it is True the event stays open and the
        correlator owns closing it.
        """
        return self.sniffer or self.graylog or self.debug


class CliProbe:
    """Executes the test command and records the resulting TEST event."""

    def __init__(
        self,
        tracker: EventTracker,
        correlation: CorrelationConfig,
        logbus: LogBus,
        logging_config: LoggingConfig,
        capabilities: CollectorCapabilities,
    ) -> None:
        self._tracker = tracker
        self._correlation = correlation
        self._log = logbus
        self._logging = logging_config
        self._caps = capabilities
        self._success_regex: Optional[re.Pattern[str]] = None
        self._failure_regexes = []
        if correlation.pattern_is_regex:
            self._success_regex = re.compile(correlation.cli_success_pattern, re.IGNORECASE)
            self._failure_regexes = [
                re.compile(p, re.IGNORECASE) for p in correlation.cli_failure_patterns
            ]

    # -- matching -----------------------------------------------------------

    def _is_success(self, text: str) -> bool:
        if self._success_regex is not None:
            return self._success_regex.search(text) is not None
        return self._correlation.cli_success_pattern.lower() in text.lower()

    def _matched_failure(self, text: str) -> Optional[str]:
        if self._failure_regexes:
            for pattern in self._failure_regexes:
                if pattern.search(text):
                    return pattern.pattern
            return None
        lowered = text.lower()
        for pattern in self._correlation.cli_failure_patterns:
            if pattern.lower() in lowered:
                return pattern
        return None

    # -- execution ----------------------------------------------------------

    async def execute(
        self,
        shell: InteractiveShell,
        command: str,
        timeout: float,
    ) -> TestEvent:
        """Run one test command and return its (possibly still open) event."""
        # The local timestamp is taken immediately before the command is sent;
        # everything downstream is measured from this instant.
        started_at = datetime.now()
        event = self._tracker.create_event(started_at, command=command)

        self._initialise_states(event)
        self._log.cli(f"Executing: {command}", event.event_id)

        result = await shell.run(command, timeout=timeout, started_at=started_at)
        self._evaluate(event, result)
        return event

    def _initialise_states(self, event: TestEvent) -> None:
        event.debug_state = MatchState.PENDING if self._caps.debug else MatchState.NOT_ENABLED
        event.sniffer_state = MatchState.PENDING if self._caps.sniffer else MatchState.NOT_ENABLED
        event.graylog_state = MatchState.PENDING if self._caps.graylog else MatchState.NOT_ENABLED

    def _evaluate(self, event: TestEvent, result: CommandResult) -> None:
        event.cli_response_timestamp = result.finished_at
        event.cli_response = result.output

        if self._logging.echo_raw_command_output and result.output:
            self._log.log_block(Source.CLI, result.output, event.event_id, prefix="| ")

        if result.timed_out:
            event.cli_state = MatchState.UNKNOWN
            event.cli_error = f"no prompt returned within {result.duration_ms / 1000:.1f}s"
            self._log.cli(
                f"GENERATION UNKNOWN (timeout after {result.duration_ms:.0f} ms, "
                f"no usable response)",
                event.event_id,
            )
        elif result.error is not None:
            event.cli_state = MatchState.UNKNOWN
            event.cli_error = result.error
            self._log.cli(f"GENERATION UNKNOWN ({result.error})", event.event_id)
        elif self._is_success(result.output):
            event.cli_state = MatchState.HIT
            self._tracker.record(
                Source.CLI,
                result.finished_at,
                result.output,
                fields={"event_id": event.event_id, "command": result.command},
            )
            self._log.cli(
                f"GENERATION HIT (CLI responded in {result.duration_ms:.0f} ms)",
                event.event_id,
            )
        else:
            failure = self._matched_failure(result.output)
            event.cli_state = MatchState.MISS
            if failure:
                event.cli_error = f"failure pattern matched: {failure}"
                self._log.cli(
                    f"GENERATION MISS (device reported failure: {failure!r})",
                    event.event_id,
                )
            else:
                snippet = " / ".join(result.output.split("\n")[:2]).strip() or "<empty response>"
                event.cli_error = "success pattern not present in response"
                self._log.cli(
                    f"GENERATION MISS (expected "
                    f"{self._correlation.cli_success_pattern!r}, got: {snippet})",
                    event.event_id,
                )

        if not self._caps.any_async_source:
            # Nothing else will ever update this event, so classify it now.
            status = event.close(result.finished_at)
            self._log.correlator(f"RESULT: {status.description}", event.event_id)
