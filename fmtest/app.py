"""Application orchestration: startup, supervision and clean shutdown.

Responsibilities kept deliberately in one place:

* render the startup confirmation summary (never printing credentials)
* open the logical device sessions
* run one asyncio task per command group
* translate Ctrl+C into an orderly, traceback-free shutdown
* produce the final reports

Correlation logic lives in :mod:`fmtest.cli_probe` (and, from Phase 4, in the
correlator); this module only wires collectors together.
"""

from __future__ import annotations

import asyncio
import os
import signal
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional

from . import PHASE, __version__
from .cli_probe import CliProbe, CollectorCapabilities
from .command_runner import CommandGroupRunner, SharedSession
from .config import AppConfig
from .correlator import Correlator, SourceBinding
from .debug_session import DebugCollector
from .diagnostics import DiagnosticRecorder
from .events import EventTracker, Source
from .graylog_client import GraylogClient
from .graylog_collector import GraylogCollector
from .logbus import LogBus, NullConsoleSink, StreamConsoleSink
from .mock_device import MockGateway
from .reporting import ReportBuilder, compute_statistics
from .sniffer import SnifferCollector
from .ssh_manager import SSHConnectionError, SSHGateway, probe_reachable
from .ui import RichLiveDisplay, build_stats_provider

CLI_SESSION_NAME = "cli"

_SEPARATOR = "=" * 60


@dataclass
class RunOptions:
    """Command-line options that are not part of config.yaml."""

    assume_yes: bool = False
    duration_seconds: Optional[float] = None
    mock: bool = False
    mock_fail_rate: float = 0.0
    mock_hang_rate: float = 0.0
    mock_drop_rate: float = 0.0
    mock_headers_only: bool = False
    mock_graylog_ingest: Optional[str] = None
    mock_seed: Optional[int] = None
    include_raw_evidence: bool = False
    shutdown_grace_seconds: float = 5.0
    force_plain_console: bool = False
    debug_mode: bool = False


def _phase_note(enabled: bool, available_in_phase: int) -> str:
    if not enabled:
        return "DISABLED"
    if available_in_phase > PHASE:
        return f"ENABLED in config (implemented in Phase {available_in_phase}, not active yet)"
    return "ENABLED"


def build_startup_summary(config: AppConfig, options: RunOptions) -> str:
    """Render the pre-flight summary shown before the test starts.

    Credentials are never included; only the *source* of each credential is
    reported so the operator can confirm the right variable is in play.
    """
    fmg = config.fortimanager
    correlation = config.correlation
    test_group = config.test_group

    lines: List[str] = [
        _SEPARATOR,
        f"FORTIMANAGER LOG TRANSMISSION TEST  (tool v{__version__}, Phase {PHASE})",
        _SEPARATOR,
        "",
        "Target:",
        f"  {fmg.display_name} / {fmg.host}:{fmg.port}",
        f"  user {fmg.username}",
    ]

    if fmg.password is not None:
        lines.append(f"  credential from {fmg.password.origin}")
    if fmg.client_keys:
        lines.append(f"  client keys: {', '.join(fmg.client_keys)}")
    if options.mock:
        lines.append("  MOCK MODE: no SSH connection will be made, no device is contacted")
    lines.append("")

    if test_group is not None:
        lines += [
            "Test command:",
            f"  {test_group.test_command}",
            "",
            "Interval:",
            f"  {test_group.interval_seconds:g} seconds  (group '{test_group.name}')",
            "",
        ]
        extra = [c for i, c in enumerate(test_group.commands) if i != test_group.test_command_index]
        if extra:
            lines += ["Other commands in the test group:"]
            lines += [f"  {c}" for c in extra]
            lines.append("")
    else:
        lines += ["Test command:", "  <none: no command group is marked test_event>", ""]

    other_groups = [g for g in config.enabled_groups if not g.test_event]
    if other_groups:
        lines.append("Additional command groups:")
        for group in other_groups:
            lines.append(f"  {group.name} every {group.interval_seconds:g}s")
            for command in group.commands:
                lines.append(f"    {command}")
        lines.append("")

    lines += [
        "Expected CLI response:",
        f"  {correlation.cli_success_pattern}",
        "",
        "Expected event:",
        f"  {correlation.expected_message}",
        "",
        "Correlation:",
        f"  window {correlation.timeout_seconds:g}s, "
        f"tolerance {correlation.timestamp_tolerance_seconds:g}s, "
        f"reuse matches: {'yes' if correlation.allow_reuse else 'no'}",
        "",
        "Sniffer:",
        f"  {_phase_note(config.sniffer.enabled, 2)}",
    ]
    if config.sniffer.enabled and config.sniffer.command:
        lines.append(f"  command: {config.sniffer.command}")
    lines += [
        "",
        "Debug:",
        f"  {_phase_note(config.debug.enabled, 2)}",
        "",
        "Graylog:",
        f"  {_phase_note(config.graylog.enabled, 3)}",
    ]
    if config.graylog.enabled:
        lines.append(f"  url: {config.graylog.url}")
        if config.graylog.api_token is not None:
            lines.append(f"  credential from {config.graylog.api_token.origin}")
        elif config.graylog.password is not None:
            lines.append(f"  credential from {config.graylog.password.origin}")
        if config.graylog.filters:
            rendered = ", ".join(f"{k}={v}" for k, v in config.graylog.filters.items())
            lines.append(f"  filters: {rendered}")
    lines += [
        "",
        "Log mode:",
        f"  {config.logging.mode}",
        "",
        "Output directory:",
        f"  {config.logging.directory}",
    ]
    if config.logging.report_directory:
        lines.append(f"  reports: {config.logging.report_directory}")

    if options.duration_seconds:
        lines += ["", "Run duration:", f"  {options.duration_seconds:g} seconds (then stop)"]
    else:
        lines += ["", "Run duration:", "  until Ctrl+C"]

    if config.warnings:
        lines.append("")
        lines.append("Warnings:")
        lines.extend(f"  ! {warning}" for warning in config.warnings)

    lines.append("")
    lines.append(_SEPARATOR)
    return "\n".join(lines)


def confirm_start(summary: str, assume_yes: bool) -> bool:
    """Show the summary and ask for confirmation. Returns True to proceed."""
    print(summary)
    if assume_yes:
        print("Start test? [y/N] y  (--yes)")
        return True
    if not sys.stdin or not sys.stdin.isatty():
        print(
            "\nRefusing to start: stdin is not a terminal so the confirmation "
            "prompt cannot be answered. Re-run with --yes to skip it."
        )
        return False
    try:
        answer = input("\nStart test? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return answer in ("y", "yes")


class Application:
    """Owns the running test."""

    def __init__(self, config: AppConfig, options: RunOptions, startup_summary: str) -> None:
        self.config = config
        self.options = options
        self._startup_summary = startup_summary
        self.started_at = datetime.now()
        self.run_stamp = self.started_at.strftime("%Y%m%d_%H%M%S")

        console = (
            NullConsoleSink() if config.logging.console == "none" else StreamConsoleSink()
        )
        self.log = LogBus(config.logging, self.started_at, console=console)

        self.tracker = EventTracker(allow_reuse=config.correlation.allow_reuse)
        self.capabilities = CollectorCapabilities(
            sniffer=config.sniffer.enabled,
            debug=config.debug.enabled,
            graylog=config.graylog.enabled,
        )
        self.diagnostics: Optional[DiagnosticRecorder] = None
        if config.diagnostics.enabled:
            self.diagnostics = DiagnosticRecorder(
                config.diagnostics, config, self.run_stamp
            )

        self.gateway = None
        self.runners: List[CommandGroupRunner] = []
        self.sniffer: Optional[SnifferCollector] = None
        self.debug_collector: Optional[DebugCollector] = None
        self.graylog: Optional[GraylogCollector] = None
        self.correlator: Optional[Correlator] = None
        self._display: Optional[RichLiveDisplay] = None
        self._tasks: List[asyncio.Task] = []
        self._collector_tasks: List[asyncio.Task] = []
        self._shutdown = asyncio.Event()
        self._shutdown_reason = "completed"
        self._shutting_down = False
        self._signals_seen = 0
        self._exit_code = 0

    # -- signals ------------------------------------------------------------

    def _install_signal_handlers(self) -> None:
        loop = asyncio.get_running_loop()
        for sig_name in ("SIGINT", "SIGTERM"):
            sig = getattr(signal, sig_name, None)
            if sig is None:
                continue
            try:
                loop.add_signal_handler(sig, self._on_signal, sig_name)
            except (NotImplementedError, RuntimeError, AttributeError):
                # Windows: fall back to the KeyboardInterrupt path in run().
                pass

    def _on_signal(self, sig_name: str) -> None:
        self._signals_seen += 1
        if self._signals_seen > 1:
            # A second interrupt means the operator wants out now, even at the
            # cost of the reports. Flush what we have and leave: raising from a
            # signal callback would only reach the loop's exception handler.
            self.log.system(f"{sig_name}: second interrupt, exiting immediately")
            self.log.flush()
            self.log.close()
            os._exit(130)
        self.request_shutdown(f"{sig_name} received")

    def request_shutdown(self, reason: str) -> None:
        if not self._shutdown.is_set():
            self._shutdown_reason = reason
            self.log.system(f"shutdown requested: {reason}")
            self._shutdown.set()

    # -- startup ------------------------------------------------------------

    def _build_gateway(self):
        if self.options.mock:
            return MockGateway(
                self.config.fortimanager,
                self.log,
                success_line=self.config.correlation.cli_success_pattern,
                expected_message=self.config.correlation.expected_message,
                fail_rate=self.options.mock_fail_rate,
                hang_rate=self.options.mock_hang_rate,
                drop_rate=self.options.mock_drop_rate,
                headers_only=self.options.mock_headers_only,
                graylog_ingest_url=self.options.mock_graylog_ingest,
                seed=self.options.mock_seed,
            )
        return SSHGateway(self.config.fortimanager, self.log)

    def _activate_display(self) -> None:
        """Switch the log bus over to the live split-screen display."""
        if self.config.logging.console != "rich" or self.options.force_plain_console:
            return
        if not RichLiveDisplay.usable():
            self.log.system(
                "live display requested but unavailable (no TTY or rich missing); "
                "using plain console output"
            )
            return
        display = RichLiveDisplay(stats_provider=build_stats_provider(self))
        if display.start():
            self._display = display
            self.log.set_console(display)
        else:
            self.log.system("live display failed to start; using plain console output")

    def _deactivate_display(self) -> None:
        """Return to plain output so the final summary prints normally."""
        if self._display is None:
            return
        self._display.stop()
        self._display = None
        self.log.set_console(
            NullConsoleSink()
            if self.config.logging.console == "none"
            else StreamConsoleSink()
        )

    async def _startup(self) -> bool:
        # The operator already saw this at the confirmation prompt; record it in
        # the log file so the run is self-describing, without repeating it.
        self.log.banner(self._startup_summary, console=False)
        self.log.system(
            f"test start timestamp: {self.started_at.isoformat(timespec='milliseconds')}"
        )
        self.log.system(f"configuration: {self.config.source_path}")
        for warning in self.config.warnings:
            self.log.system(f"WARNING: {warning}")
        self._warn_about_debug_in_command_groups()
        if self.diagnostics is not None:
            self.log.system(
                f"DEBUG MODE: raw streams, per-candidate reasons and the evidence "
                f"comparison report will be written to {self.diagnostics.directory}"
            )


        if not self.options.mock:
            failure = await probe_reachable(self.config.fortimanager)
            if failure is None:
                self.log.system(
                    f"pre-flight: {self.config.fortimanager.host}:"
                    f"{self.config.fortimanager.port} is accepting connections"
                )
            else:
                self.log.system(f"pre-flight: TCP check failed ({failure}); trying SSH anyway")

        self.gateway = self._build_gateway()
        try:
            await self.gateway.open_session(CLI_SESSION_NAME)
        except SSHConnectionError as exc:
            self.log.system(f"FATAL: {exc}")
            self._exit_code = 2
            return False
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.log.system(f"FATAL: could not open CLI session ({type(exc).__name__}: {exc})")
            self._exit_code = 2
            return False

        self._tap_session(CLI_SESSION_NAME, "repeating CLI commands")
        shared = SharedSession(self.gateway, CLI_SESSION_NAME, self.log)
        probe = CliProbe(
            tracker=self.tracker,
            correlation=self.config.correlation,
            logbus=self.log,
            logging_config=self.config.logging,
            capabilities=self.capabilities,
        )

        for group in self.config.enabled_groups:
            runner = CommandGroupRunner(
                group=group,
                session=shared,
                logbus=self.log,
                device_config=self.config.fortimanager,
                logging_config=self.config.logging,
                shutdown=self._shutdown,
                probe=probe,
            )
            self.runners.append(runner)
            self.log.system(
                f"group '{group.name}': every {group.interval_seconds:g}s, "
                f"{len(group.commands)} command(s)"
                + (" [generates TEST events]" if group.test_event else "")
            )

        # Evidence collectors run on their own sessions. A failure to start one
        # is reported and the test continues: partial evidence beats none, and
        # the correlator reports the missing source as UNKNOWN rather than MISS.
        await self._start_collectors()
        await self._start_graylog()
        self._build_correlator()

        self.log.system(f"log files: {', '.join(str(p) for p in self.log.log_paths)}")
        self.log.system("test running; press Ctrl+C to stop")
        self._activate_display()
        return True

    def _tap_session(self, session_name: str, description: str) -> None:
        """Mirror a session's bytes verbatim into its own debug-mode file."""
        if self.diagnostics is None or self.gateway is None:
            return
        session = self.gateway.get(session_name)
        if session is None:
            return
        writer = self.diagnostics.raw_writer(session_name, description)
        if writer is not None:
            session.shell.add_stream_consumer(writer)

    def _warn_about_debug_in_command_groups(self) -> None:
        """Flag config that makes the CLI session unreliable.

        Enabling device debug from a command group turns the *shared CLI
        session* into a debug stream. That output then interleaves with command
        responses on the same channel, which slows prompt detection and can
        corrupt what the CLI collector reads back.
        """
        offenders = [
            (group.name, command)
            for group in self.config.enabled_groups
            for command in group.commands
            if "debug enable" in command.lower().replace("diag ", "diagnose ")
        ]
        if not offenders:
            return
        for name, command in offenders:
            self.log.system(
                f"WARNING: command group {name!r} runs {command!r} on the shared CLI "
                f"session. Device debug output will interleave with command responses "
                f"there and can distort CLI timing and matching."
            )
        if self.config.debug.enabled:
            self.log.system(
                "WARNING: the dedicated debug collector is also enabled, so debugging "
                "is being turned on twice. Prefer the debug: section alone, which uses "
                "its own session and always cleans up."
            )

    async def _start_collectors(self) -> None:
        if self.config.sniffer.enabled:
            self.sniffer = SnifferCollector(
                config=self.config.sniffer,
                correlation=self.config.correlation,
                tracker=self.tracker,
                logbus=self.log,
                gateway=self.gateway,
                session_name=self.config.sniffer.session_name,
                diagnostics=self.diagnostics,
            )
            if await self.sniffer.start():
                self._tap_session(self.config.sniffer.session_name, "packet sniffer")
                self.log.log(
                    Source.SNIFFER,
                    f"capturing; matching packets on "
                    f"{self.config.correlation.sniffer_match_pattern!r}",
                )
            else:
                self.log.log(
                    Source.SNIFFER,
                    "collector did not start; transmission evidence will be UNKNOWN",
                )

        if self.config.debug.enabled:
            self.debug_collector = DebugCollector(
                config=self.config.debug,
                correlation=self.config.correlation,
                tracker=self.tracker,
                logbus=self.log,
                gateway=self.gateway,
                command_timeout=self.config.fortimanager.command_timeout_seconds,
                diagnostics=self.diagnostics,
            )
            if await self.debug_collector.start():
                self._tap_session(self.config.debug.session_name, "logd debug stream")
                self.log.log(Source.DEBUG, "debug stream active (diagnostic evidence only)")
            else:
                self.log.log(
                    Source.DEBUG,
                    "collector did not start; the test continues without debug evidence",
                )

    async def _start_graylog(self) -> None:
        if not self.config.graylog.enabled:
            return
        client = GraylogClient(self.config.graylog, diagnostics=self.diagnostics)
        self.graylog = GraylogCollector(
            config=self.config.graylog,
            correlation=self.config.correlation,
            tracker=self.tracker,
            logbus=self.log,
            client=client,
            # The authoritative test-start timestamp: no search ever reaches
            # earlier than this, so historical records cannot be correlated.
            test_start=self.started_at,
            diagnostics=self.diagnostics,
        )
        if not await self.graylog.start():
            self.log.log(
                Source.GRAYLOG,
                "collector did not start; delivery evidence will be UNKNOWN",
            )

    def _build_correlator(self) -> None:
        correlator = Correlator(
            tracker=self.tracker,
            config=self.config.correlation,
            logbus=self.log,
            diagnostics=self.diagnostics,
        )
        correlator.bind(
            SourceBinding(
                source=Source.SNIFFER,
                enabled=self.capabilities.sniffer,
                health=lambda: self.sniffer is not None and self.sniffer.healthy,
            )
        )
        correlator.bind(
            SourceBinding(
                source=Source.DEBUG,
                enabled=self.capabilities.debug,
                health=lambda: (
                    self.debug_collector is not None and self.debug_collector.healthy
                ),
                # Debug is supplemental: one test event may match several lines.
                multiple=True,
            )
        )
        correlator.bind(
            SourceBinding(
                source=Source.GRAYLOG,
                enabled=self.capabilities.graylog,
                health=lambda: self.graylog is not None and self.graylog.healthy,
            )
        )
        self.correlator = correlator

    # -- main loop ----------------------------------------------------------

    async def _duration_timer(self, seconds: float) -> None:
        try:
            await asyncio.sleep(seconds)
        except asyncio.CancelledError:
            raise
        self.request_shutdown(f"configured duration of {seconds:g}s elapsed")

    async def _watch_runners(self, tasks: List[asyncio.Task]) -> None:
        # asyncio.wait is used rather than gather because gather cancels its
        # children when the waiting task is cancelled. That would kill in-flight
        # commands the moment shutdown begins, before the grace period in
        # _stop_command_loops has a chance to let them finish.
        done, _pending = await asyncio.wait(tasks)
        for task in done:
            if task.cancelled():
                continue
            exc = task.exception()
            if exc is not None:
                self.log.system(
                    f"{task.get_name()}: task ended with {type(exc).__name__}: {exc}"
                )
        if not self._shutdown.is_set():
            self.request_shutdown("all command groups finished")

    async def _heartbeat(self) -> None:
        """Keep the loop ticking so Ctrl+C is delivered promptly on Windows."""
        while True:
            await asyncio.sleep(0.25)

    async def _main_loop(self) -> None:
        loop = asyncio.get_running_loop()
        runner_tasks = [
            loop.create_task(runner.run(), name=f"group-{runner.group.name}")
            for runner in self.runners
        ]
        self._tasks.extend(runner_tasks)

        # Collectors and the correlator are supervised separately from the
        # command groups: a sniffer failure must not stop the CLI loop.
        if self.sniffer is not None and self.sniffer.started:
            self._collector_tasks.append(
                loop.create_task(self.sniffer.run(), name="sniffer-collector")
            )
        if self.debug_collector is not None and self.debug_collector.started:
            self._collector_tasks.append(
                loop.create_task(self.debug_collector.run(), name="debug-collector")
            )

        if self.graylog is not None and self.graylog.started:
            self._collector_tasks.append(
                loop.create_task(
                    self.graylog.run(self._shutdown), name="graylog-collector"
                )
            )

        watcher = loop.create_task(self._watch_runners(runner_tasks), name="runner-watcher")
        auxiliary = [watcher]
        if self.correlator is not None and self.capabilities.any_async_source:
            auxiliary.append(
                loop.create_task(self.correlator.run(self._shutdown), name="correlator")
            )
        if self.options.duration_seconds:
            auxiliary.append(
                loop.create_task(
                    self._duration_timer(self.options.duration_seconds), name="duration-timer"
                )
            )
        if sys.platform.startswith("win"):
            auxiliary.append(loop.create_task(self._heartbeat(), name="heartbeat"))

        try:
            await self._shutdown.wait()
        finally:
            for task in auxiliary:
                task.cancel()
            await asyncio.gather(*auxiliary, return_exceptions=True)

    # -- shutdown -----------------------------------------------------------

    async def _stop_command_loops(self) -> None:
        if not self._tasks:
            return
        grace = self.options.shutdown_grace_seconds
        self.log.system(
            f"stopping command groups (allowing up to {grace:g}s for in-flight commands)"
        )
        done, pending = await asyncio.wait(self._tasks, timeout=grace)
        for task in pending:
            task.cancel()
        if pending:
            self.log.system(f"cancelling {len(pending)} command group task(s) that did not stop")
            await asyncio.gather(*pending, return_exceptions=True)
        for task in done:
            exc = task.exception() if not task.cancelled() else None
            if exc is not None:
                self.log.system(f"command group task error: {type(exc).__name__}: {exc}")
        self._tasks.clear()

    async def _stop_collectors(self) -> None:
        """Stop the sniffer and turn device-side debugging off again."""
        # The streaming tasks must be cancelled FIRST. They and the cleanup
        # commands read from the same shell queue, so a live stream task would
        # swallow the response to "diagnose debug disable" and the cleanup
        # would hang until its timeout with debugging still enabled.
        if self._collector_tasks:
            for task in self._collector_tasks:
                task.cancel()
            await asyncio.gather(*self._collector_tasks, return_exceptions=True)
            self._collector_tasks.clear()

        # 4. Stop the sniffer.
        if self.sniffer is not None:
            try:
                await asyncio.wait_for(self.sniffer.stop(), timeout=15.0)
            except asyncio.TimeoutError:
                self.log.log(Source.SNIFFER, "timed out stopping the sniffer")
            except Exception as exc:
                self.log.log(Source.SNIFFER, f"error stopping sniffer: {type(exc).__name__}: {exc}")

        # 5. Disable FortiManager debug. This must happen even if everything
        #    else went wrong, so it gets its own generous timeout.
        if self.debug_collector is not None:
            try:
                await asyncio.wait_for(self.debug_collector.stop(), timeout=30.0)
            except asyncio.TimeoutError:
                self.log.log(
                    Source.DEBUG,
                    "timed out running cleanup commands; "
                    "CHECK THE DEVICE: debugging may still be enabled",
                )
            except Exception as exc:
                self.log.log(
                    Source.DEBUG,
                    f"error during debug cleanup ({type(exc).__name__}: {exc}); "
                    f"CHECK THE DEVICE: debugging may still be enabled",
                )

    async def _stop_graylog(self) -> None:
        if self.graylog is None:
            return
        if self.graylog.started:
            try:
                await asyncio.wait_for(self.graylog.final_poll(), timeout=30.0)
            except asyncio.TimeoutError:
                self.log.log(Source.GRAYLOG, "final poll timed out")
            except Exception as exc:
                self.log.log(
                    Source.GRAYLOG, f"final poll failed: {type(exc).__name__}: {exc}"
                )
            # The final poll may have delivered evidence for events closed
            # during the drain, so give the correlator one more pass.
            if self.correlator is not None:
                self.correlator.resolve()
        warning = self.graylog.clock_warning()
        if warning:
            self.log.log(Source.GRAYLOG, f"WARNING: {warning}")
        try:
            await asyncio.wait_for(self.graylog.stop(), timeout=15.0)
        except asyncio.TimeoutError:
            self.log.log(Source.GRAYLOG, "timed out closing the Graylog client")
        except Exception as exc:
            self.log.log(Source.GRAYLOG, f"error closing Graylog client: {exc}")

    async def _drain_correlation(self) -> None:
        """Give test events still inside their window a chance to complete."""
        if self.correlator is None:
            return
        open_events = self.tracker.open_events()
        if not open_events:
            return

        correlation = self.config.correlation
        budget = min(
            correlation.timeout_seconds + correlation.timestamp_tolerance_seconds + 1.0,
            30.0,
        )
        self.log.correlator(
            f"waiting up to {budget:.0f}s for {len(open_events)} in-flight test event(s) "
            f"to finish their correlation window"
        )
        if self.graylog is not None and self.graylog.started:
            # Poll once up front so records indexed since the last scheduled
            # poll are available to the events about to close.
            try:
                await asyncio.wait_for(self.graylog.final_poll(), timeout=20.0)
            except Exception:
                pass
        try:
            await asyncio.wait_for(self.correlator.drain(budget), timeout=budget + 5.0)
        except asyncio.TimeoutError:
            self.correlator.resolve(force=True)
        except Exception as exc:
            self.log.correlator(f"error draining correlation: {type(exc).__name__}: {exc}")
            self.correlator.resolve(force=True)

    async def _shutdown_sequence(self) -> None:
        if self._shutting_down:
            return
        self._shutting_down = True

        # 1. Stop creating new test events / 3. stop command loops.
        self._shutdown.set()
        await self._stop_command_loops()

        # 2. Let in-flight correlation complete or expire. This happens while
        #    the sniffer is still capturing, so a packet that is still in the
        #    air can be claimed instead of being written off as a MISS.
        await self._drain_correlation()

        # 4/5. Sniffer and device debug teardown.
        await self._stop_collectors()

        # 6. Stop Graylog polling, but poll once more first: indexing lag means
        #    the last few events may only have become searchable during the
        #    drain above.
        await self._stop_graylog()

        # Anything still open (for example events created after the drain) is
        # closed now so no test event is left unclassified.
        ended_at = datetime.now()
        still_open = self.tracker.open_events()
        if still_open:
            self.log.system(f"closing {len(still_open)} remaining test event(s)")
            if self.correlator is not None:
                self.correlator.resolve(now=ended_at, force=True)
            else:
                for event in self.tracker.close_all(ended_at):
                    self.log.correlator(
                        f"RESULT: {event.final_status.description}", event.event_id
                    )

        # 7. Flush logs before touching the network again.
        self.log.flush()

        # 8. Close SSH connections.
        if self.gateway is not None:
            self.log.system("closing device sessions")
            try:
                await asyncio.wait_for(self.gateway.close_all(), timeout=15.0)
            except asyncio.TimeoutError:
                self.log.system("timed out closing device sessions")
            except Exception as exc:
                self.log.system(f"error closing device sessions: {type(exc).__name__}: {exc}")

        # 9/10. Reports and final summary. The live display is torn down first
        #       so the summary prints as ordinary scrollable output.
        self._deactivate_display()
        self._write_reports(ended_at)
        self._close_diagnostics()
        self.log.flush()

    def _diagnostic_notes(self) -> List[str]:
        """Observations about the run worth stating in the comparison report."""
        notes: List[str] = []
        sniffer = self.sniffer
        if sniffer is not None and sniffer.packets_seen:
            if sniffer.packets_without_payload == sniffer.packets_seen:
                notes.append(
                    f"NONE of the {sniffer.packets_seen} captured packets contained packet "
                    f"data - only headers were printed. Content matching cannot work at "
                    f"all in this configuration, so every SNIFFER MISS in this run is "
                    f"inconclusive rather than evidence that nothing was transmitted. "
                    f"Raise the sniffer verbosity until the raw capture contains "
                    f"0x0000-style hex dump lines. Current command: "
                    f"{self.config.sniffer.command!r}"
                )
            elif sniffer.packets_without_payload:
                notes.append(
                    f"{sniffer.packets_without_payload} of {sniffer.packets_seen} captured "
                    f"packets contained no packet data and could not be searched."
                )
        if sniffer is not None and sniffer.packets_seen == 0 and sniffer.started:
            notes.append(
                "The sniffer session started but captured no packets at all. Check the "
                "filter in sniffer.command against the traffic you expect."
            )
        graylog = self.graylog
        if graylog is not None:
            if not graylog.started:
                notes.append(
                    f"The Graylog collector never started ({graylog.last_error}). Every "
                    f"GRAYLOG result in this run is UNKNOWN, not MISS: delivery was not "
                    f"observed either way."
                )
            else:
                if graylog.messages_seen == 0:
                    notes.append(
                        f"Graylog returned no records at all for the query "
                        f"{graylog.query!r}. Check graylog.filters against a record you "
                        f"know exists, and confirm the stream is searchable by this "
                        f"account."
                    )
                elif graylog.matches == 0:
                    notes.append(
                        f"Graylog returned {graylog.messages_seen} record(s) matching the "
                        f"filters, but none contained "
                        f"{self.config.correlation.graylog_match_pattern!r}. The filters "
                        f"are right and the content check is what failed - compare the "
                        f"candidate excerpts in this report against the expected message."
                    )
                if graylog.failed_polls:
                    notes.append(
                        f"{graylog.failed_polls} of {graylog.polls + graylog.failed_polls} "
                        f"Graylog polls failed; events in those windows resolve UNKNOWN."
                    )
                warning = graylog.clock_warning()
                if warning:
                    notes.append(warning)
        return notes

    def _close_diagnostics(self) -> None:
        if self.diagnostics is None:
            return
        try:
            paths = self.diagnostics.close(self._diagnostic_notes())
        except Exception as exc:
            self.log.system(f"WARNING: could not finish debug-mode artefacts: {exc}")
            return
        if paths:
            self.log.banner(
                "Debug-mode artefacts:\n"
                + "\n".join(f"  {label:<16} {path}" for label, path in sorted(paths.items()))
            )

    def _collector_summary(self) -> Dict[str, object]:
        detail: Dict[str, object] = {}
        if self.sniffer is not None:
            detail["sniffer"] = {
                "started": self.sniffer.started,
                "healthy_at_end": self.sniffer.healthy,
                "packets_seen": self.sniffer.packets_seen,
                "payload_matches": self.sniffer.matches,
                "bytes_captured": self.sniffer.bytes_captured,
                "unclaimed_matches": len(self.tracker.unclaimed(Source.SNIFFER)),
                "last_error": self.sniffer.last_error,
            }
        if self.graylog is not None:
            detail["graylog"] = {
                "started": self.graylog.started,
                "healthy_at_end": self.graylog.healthy,
                "server": self.graylog.server_description,
                "query": self.graylog.query,
                "polls": self.graylog.polls,
                "failed_polls": self.graylog.failed_polls,
                "records_examined": self.graylog.messages_seen,
                "content_matches": self.graylog.matches,
                "unclaimed_matches": len(self.tracker.unclaimed(Source.GRAYLOG)),
                "timestamp_lag_seconds": self.graylog.lag_summary,
                "clock_warning": self.graylog.clock_warning(),
                "last_error": self.graylog.last_error,
            }
        if self.debug_collector is not None:
            detail["debug"] = {
                "started": self.debug_collector.started,
                "lines_seen": self.debug_collector.lines_seen,
                "matches": self.debug_collector.matches,
                "unclaimed_matches": len(self.tracker.unclaimed(Source.DEBUG)),
                "last_error": self.debug_collector.last_error,
            }
        return detail

    def _write_reports(self, ended_at: datetime) -> None:
        stats = compute_statistics(self.tracker.events)
        if self.correlator is not None:
            stats.identity_matches = self.correlator.stats.identity_matches
        builder = ReportBuilder(
            config=self.config,
            tracker=self.tracker,
            started_at=self.started_at,
            run_stamp=self.run_stamp,
            group_stats=[runner.stats for runner in self.runners],
            capabilities={
                "cli": True,
                "sniffer": self.capabilities.sniffer,
                "debug": self.capabilities.debug,
                "graylog": self.capabilities.graylog,
            },
            phase=PHASE,
            collector_detail=self._collector_summary(),
        )
        summary = builder.render_summary(ended_at, stats)
        try:
            paths: Dict[str, "object"] = builder.write_all(
                ended_at, stats, summary
            )
        except OSError as exc:
            self.log.system(f"WARNING: could not write reports: {exc}")
            paths = {}

        self.log.banner("\n" + summary)
        if paths:
            self.log.banner(
                "Reports written:\n"
                + "\n".join(f"  {label:<8} {path}" for label, path in paths.items())
            )
        if self.log.log_paths:
            self.log.banner(
                "Log files:\n" + "\n".join(f"  {path}" for path in self.log.log_paths)
            )

    # -- entry point --------------------------------------------------------

    async def run(self) -> int:
        self._install_signal_handlers()
        try:
            if not await self._startup():
                return self._exit_code
            await self._main_loop()
        except KeyboardInterrupt:
            # Windows and any platform where the signal handler could not be
            # installed land here.
            self.request_shutdown("keyboard interrupt")
        except asyncio.CancelledError:
            self.request_shutdown("cancelled")
        except Exception as exc:
            self.log.system(f"FATAL: {type(exc).__name__}: {exc}")
            self._exit_code = 1
        finally:
            try:
                await self._shutdown_sequence()
            except Exception as exc:
                self.log.system(f"error during shutdown: {type(exc).__name__}: {exc}")
                self._exit_code = self._exit_code or 1
            self.log.close()
        return self._exit_code
