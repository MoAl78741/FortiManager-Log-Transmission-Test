"""Repeating command groups.

Each configured command group runs as its own asyncio task at its own interval.
There are no blocking loops and no shared timer: a slow group cannot delay a
fast one.

Command groups share a single logical CLI session because FortiManager limits
concurrent admin logins, so execution through that session is serialised by
:class:`SharedSession`. The shared session also owns reconnection, so a
transient SSH failure is repaired once rather than once per group.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import AsyncIterator, Optional

from .cli_probe import CliProbe
from .config import CommandGroupConfig, FortiManagerConfig, LoggingConfig
from .events import Source
from .logbus import LogBus
from .shell import InteractiveShell


class SharedSession:
    """One logical device session, safely shared by several command groups."""

    def __init__(self, gateway, name: str, logbus: LogBus) -> None:
        self._gateway = gateway
        self._name = name
        self._log = logbus
        self._use_lock = asyncio.Lock()
        self._repair_lock = asyncio.Lock()
        self._degraded = False

    @property
    def name(self) -> str:
        return self._name

    @property
    def degraded(self) -> bool:
        """True when the session is currently unusable."""
        return self._degraded

    async def _ensure_shell(self) -> Optional[InteractiveShell]:
        session = self._gateway.get(self._name)
        if session is not None and session.connected:
            self._degraded = False
            return session.shell

        async with self._repair_lock:
            # Another group may have repaired the session while we waited.
            session = self._gateway.get(self._name)
            if session is not None and session.connected:
                self._degraded = False
                return session.shell

            self._log.system(f"session '{self._name}': lost, attempting to reconnect")
            try:
                session = await self._gateway.reconnect(self._name)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self._log.system(
                    f"session '{self._name}': reconnect failed "
                    f"({type(exc).__name__}: {exc})"
                )
                session = None

            if session is None or not session.connected:
                self._degraded = True
                return None
            self._degraded = False
            return session.shell

    @asynccontextmanager
    async def use(self) -> AsyncIterator[Optional[InteractiveShell]]:
        """Exclusive use of the session's shell for the duration of the block."""
        async with self._use_lock:
            shell = await self._ensure_shell()
            yield shell


@dataclass
class GroupStats:
    """Per-group execution counters, reported in the final summary."""

    name: str
    executions: int = 0
    skipped_overruns: int = 0
    session_failures: int = 0
    command_errors: int = 0
    test_events: int = 0
    last_error: Optional[str] = None
    durations_ms: list = field(default_factory=list)

    @property
    def average_duration_ms(self) -> Optional[float]:
        if not self.durations_ms:
            return None
        return round(sum(self.durations_ms) / len(self.durations_ms), 1)


class CommandGroupRunner:
    """Runs one command group on a fixed interval until shutdown."""

    def __init__(
        self,
        group: CommandGroupConfig,
        session: SharedSession,
        logbus: LogBus,
        device_config: FortiManagerConfig,
        logging_config: LoggingConfig,
        shutdown: asyncio.Event,
        probe: Optional[CliProbe] = None,
    ) -> None:
        self.group = group
        self._session = session
        self._log = logbus
        self._device = device_config
        self._logging = logging_config
        self._shutdown = shutdown
        self._probe = probe if group.test_event else None
        self.stats = GroupStats(name=group.name)

    @property
    def timeout(self) -> float:
        return self.group.timeout_seconds or self._device.command_timeout_seconds

    async def _sleep_or_stop(self, seconds: float) -> bool:
        """Sleep, returning True if shutdown was requested during the wait."""
        if seconds <= 0:
            return self._shutdown.is_set()
        try:
            await asyncio.wait_for(self._shutdown.wait(), timeout=seconds)
            return True
        except asyncio.TimeoutError:
            return False

    async def run(self) -> None:
        group = self.group
        if await self._sleep_or_stop(group.initial_delay_seconds):
            return

        loop = asyncio.get_running_loop()
        next_run = loop.time()

        while not self._shutdown.is_set():
            started = loop.time()
            try:
                await self._execute_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.stats.command_errors += 1
                self.stats.last_error = f"{type(exc).__name__}: {exc}"
                self._log.system(
                    f"group '{group.name}': unexpected error "
                    f"({type(exc).__name__}: {exc})"
                )

            elapsed = loop.time() - started
            next_run += group.interval_seconds
            now = loop.time()
            if next_run <= now:
                # The run took longer than the interval. Skip the missed slots
                # rather than letting executions pile up on the device.
                missed = 0
                while next_run <= now:
                    next_run += group.interval_seconds
                    missed += 1
                self.stats.skipped_overruns += missed
                self._log.system(
                    f"group '{group.name}': execution took {elapsed:.1f}s, longer than the "
                    f"{group.interval_seconds:.1f}s interval; skipped {missed} scheduled run(s)"
                )
            if await self._sleep_or_stop(next_run - loop.time()):
                return

    async def _execute_once(self) -> None:
        group = self.group
        async with self._session.use() as shell:
            if shell is None:
                self.stats.session_failures += 1
                self._log.system(
                    f"group '{group.name}': skipped, session "
                    f"'{self._session.name}' is unavailable"
                )
                return

            self.stats.executions += 1
            for index, command in enumerate(group.commands):
                if self._shutdown.is_set():
                    return
                is_test_command = (
                    self._probe is not None and index == group.test_command_index
                )
                if is_test_command:
                    event = await self._probe.execute(shell, command, self.timeout)
                    self.stats.test_events += 1
                    if event.cli_response_ms is not None:
                        self.stats.durations_ms.append(event.cli_response_ms)
                else:
                    await self._run_plain(shell, command)

    async def _run_plain(self, shell: InteractiveShell, command: str) -> None:
        group = self.group
        self._log.log(Source.CLI, f"[{group.name}] Executing: {command}")
        result = await shell.run(command, timeout=self.timeout)

        if result.timed_out:
            self.stats.command_errors += 1
            self.stats.last_error = f"{command}: timed out"
            self._log.log(
                Source.CLI,
                f"[{group.name}] TIMEOUT after {result.duration_ms:.0f} ms: {command}",
            )
            return
        if result.error is not None:
            self.stats.command_errors += 1
            self.stats.last_error = f"{command}: {result.error}"
            self._log.log(Source.CLI, f"[{group.name}] ERROR: {result.error}")
            return

        self.stats.durations_ms.append(result.duration_ms)
        if group.log_output and self._logging.echo_raw_command_output and result.output:
            self._log.log_block(Source.CLI, result.output, prefix=f"[{group.name}] | ")
        else:
            self._log.log(
                Source.CLI,
                f"[{group.name}] completed in {result.duration_ms:.0f} ms "
                f"({len(result.output.splitlines())} line(s))",
            )
