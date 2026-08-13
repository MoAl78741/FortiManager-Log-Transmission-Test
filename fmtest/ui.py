"""Live split-screen terminal display.

A tmux-like three-pane view of the running test::

    +----------------------------------------------------------+
    | CLI / TEST EVENTS                                         |
    +----------------------------------------------------------+
    | SNIFFER / DEBUG                                           |
    +----------------------------------------------------------+
    | GRAYLOG / STATUS                                          |
    +----------------------------------------------------------+

The display is a :class:`~fmtest.logbus.ConsoleSink`, so it is a pure
presentation layer: it receives the same rendered lines that go to disk and
routes them to panes. No producer knows it exists, and turning it off changes
nothing about what is collected or logged.

Reliability comes first. If Rich is missing, stdout is not a terminal, or any
render call raises, the display degrades permanently to plain line output
rather than putting the test at risk.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime
from typing import Callable, Deque, Dict, List, Optional

from .events import Source
from .logbus import ConsoleSink, LogRecord, StreamConsoleSink

try:  # pragma: no cover - exercised by the absence of the dependency
    from rich.console import Console, Group
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    RICH_AVAILABLE = True
except ImportError:  # pragma: no cover
    RICH_AVAILABLE = False


# Which pane each source is displayed in.
_PANE_FOR_SOURCE: Dict[Source, str] = {
    Source.CLI: "cli",
    Source.SNIFFER: "sniffer",
    Source.DEBUG: "sniffer",
    Source.GRAYLOG: "status",
    Source.CORRELATOR: "status",
    Source.SYSTEM: "status",
}

_PANE_TITLES = {
    "cli": "CLI / TEST EVENTS",
    "sniffer": "SNIFFER / DEBUG",
    "status": "GRAYLOG / STATUS",
}

_MAX_HISTORY = 400


def _style_for(line: str) -> str:
    """Pick a style from the content of an already-rendered line."""
    if " HIT" in line or "RESULT: SUCCESS" in line:
        return "green"
    if " MISS" in line or "FATAL" in line or "failed" in line:
        return "red"
    if "UNKNOWN" in line or "WARNING" in line or "NOTE:" in line:
        return "yellow"
    if "] | " in line:
        return "dim"
    return ""


class RichLiveDisplay(ConsoleSink):
    """Three-pane live display driven by log records."""

    def __init__(
        self,
        stats_provider: Optional[Callable[[], List[tuple]]] = None,
        refresh_per_second: float = 4.0,
    ) -> None:
        self._stats_provider = stats_provider
        self._panes: Dict[str, Deque[str]] = {
            name: deque(maxlen=_MAX_HISTORY) for name in _PANE_TITLES
        }
        self._console = Console()
        self._live: Optional[Live] = None
        self._refresh = refresh_per_second
        self._fallback: Optional[StreamConsoleSink] = None
        self._started = False

    # -- availability -------------------------------------------------------

    @staticmethod
    def usable() -> bool:
        if not RICH_AVAILABLE:
            return False
        try:
            return Console().is_terminal
        except Exception:
            return False

    # -- lifecycle ----------------------------------------------------------

    def start(self) -> bool:
        if self._started:
            return True
        try:
            self._live = Live(
                self._render(),
                console=self._console,
                refresh_per_second=self._refresh,
                transient=False,
                redirect_stdout=False,
                redirect_stderr=False,
            )
            self._live.start()
            self._started = True
            return True
        except Exception:
            self._degrade()
            return False

    def _degrade(self) -> None:
        """Give up on the live display and fall back to plain output."""
        if self._live is not None:
            try:
                self._live.stop()
            except Exception:
                pass
            self._live = None
        self._started = False
        if self._fallback is None:
            self._fallback = StreamConsoleSink()

    def stop(self) -> None:
        if self._live is not None:
            try:
                self._live.stop()
            except Exception:
                pass
            self._live = None
        self._started = False

    def close(self) -> None:
        self.stop()

    # -- sink ---------------------------------------------------------------

    def emit(self, record: LogRecord, rendered: str) -> None:
        if self._fallback is not None:
            self._fallback.emit(record, rendered)
            return

        pane = _PANE_FOR_SOURCE.get(record.source, "status")
        self._panes[pane].append(rendered)
        if self._live is None:
            return
        try:
            self._live.update(self._render(), refresh=False)
        except Exception:
            # Rendering must never take the test down.
            self._degrade()
            if self._fallback is not None:
                self._fallback.emit(record, rendered)

    # -- rendering ----------------------------------------------------------

    def _pane_heights(self) -> Dict[str, int]:
        try:
            total = self._console.size.height
        except Exception:
            total = 40
        # Three panels cost two border rows each, plus the header table.
        available = max(total - 9, 9)
        cli = max(int(available * 0.42), 3)
        sniffer = max(int(available * 0.34), 3)
        status = max(available - cli - sniffer, 3)
        return {"cli": cli, "sniffer": sniffer, "status": status}

    def _pane(self, name: str, height: int) -> "Panel":
        lines = list(self._panes[name])[-height:]
        body = Text(no_wrap=True, overflow="ellipsis")
        if not lines:
            body.append("waiting...", style="dim")
        for index, line in enumerate(lines):
            if index:
                body.append("\n")
            body.append(line, style=_style_for(line))
        return Panel(
            body,
            title=_PANE_TITLES[name],
            title_align="left",
            height=height + 2,
            padding=(0, 1),
        )

    def _header(self) -> "Table":
        table = Table.grid(expand=True, padding=(0, 2))
        stats = []
        if self._stats_provider is not None:
            try:
                stats = self._stats_provider()
            except Exception:
                stats = []
        if not stats:
            stats = [("status", "starting")]
        for _ in stats:
            table.add_column(justify="left", no_wrap=True)
        cells = []
        for label, value in stats:
            cell = Text()
            cell.append(f"{label} ", style="dim")
            cell.append(str(value), style="bold")
            cells.append(cell)
        table.add_row(*cells)
        return table

    def _render(self):
        heights = self._pane_heights()
        return Group(
            self._header(),
            self._pane("cli", heights["cli"]),
            self._pane("sniffer", heights["sniffer"]),
            self._pane("status", heights["status"]),
        )


def build_stats_provider(app) -> Callable[[], List[tuple]]:
    """Header statistics for the live display, read from the running app."""

    def provider() -> List[tuple]:
        from .events import MatchState  # local import keeps this module light

        events = app.tracker.events
        elapsed = datetime.now() - app.started_at
        total_seconds = int(elapsed.total_seconds())
        clock = f"{total_seconds // 3600:02d}:{(total_seconds % 3600) // 60:02d}:{total_seconds % 60:02d}"

        cli_hit = sum(1 for e in events if e.cli_state is MatchState.HIT)
        stats: List[tuple] = [
            ("elapsed", clock),
            ("tests", str(len(events))),
            ("CLI HIT", str(cli_hit)),
        ]

        if app.sniffer is not None:
            sniffer_hit = sum(1 for e in events if e.sniffer_state is MatchState.HIT)
            stats.append(("SNIF HIT", f"{sniffer_hit}"))
            stats.append(("packets", str(app.sniffer.packets_seen)))
        if app.graylog is not None:
            graylog_hit = sum(1 for e in events if e.graylog_state is MatchState.HIT)
            stats.append(("GL HIT", str(graylog_hit)))
        if app.debug_collector is not None:
            stats.append(("dbg match", str(app.debug_collector.matches)))

        open_count = sum(1 for e in events if e.is_open)
        stats.append(("in flight", str(open_count)))
        return stats

    return provider
