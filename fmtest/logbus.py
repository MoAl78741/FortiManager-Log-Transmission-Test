"""Tee-style logging: everything displayed is also written to disk.

Every line produced by the application flows through :class:`LogBus` and is
rendered as::

    2026-08-11 15:32:01.125 [TEST-000001] [CLI] GENERATION HIT
    2026-08-11 15:32:01.140 [SYSTEM] connected to 192.168.1.10

The event ID field is omitted when a line is not attributable to a specific
test event. Timestamps are local time with millisecond resolution by default.

Two file layouts are supported:

``combined``
    A single ``<prefix>_test_<timestamp>.log`` containing every source, each
    line labelled with its ``[SOURCE]``.

``separate``
    One file per source, created lazily the first time that source emits:
    ``<prefix>_cli_...``, ``<prefix>_debug_...``, ``<prefix>_sniffer_...``,
    ``graylog_...``, ``correlation_...``.

The console sink is a pluggable object so that Phase 2 can substitute a Rich
live display without touching a single line of producer code.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Protocol, TextIO

from .config import LoggingConfig
from .events import Source


@dataclass(frozen=True)
class LogRecord:
    """One line of application output, before rendering."""

    timestamp: datetime
    source: Source
    message: str
    event_id: Optional[str] = None
    raw: bool = False
    """``raw`` marks verbatim device output, as opposed to tool commentary."""


class ConsoleSink(Protocol):
    """Anything that can display rendered log lines to the operator."""

    def emit(self, record: LogRecord, rendered: str) -> None: ...

    def close(self) -> None: ...


class StreamConsoleSink:
    """Plain-text console sink: writes rendered lines to a stream."""

    def __init__(self, stream: Optional[TextIO] = None) -> None:
        self._stream = stream if stream is not None else sys.stdout

    def emit(self, record: LogRecord, rendered: str) -> None:
        try:
            self._stream.write(rendered + "\n")
            self._stream.flush()
        except (OSError, ValueError):
            # A closed or broken stdout must never take down a running test.
            pass

    def close(self) -> None:
        try:
            self._stream.flush()
        except (OSError, ValueError):
            pass


class NullConsoleSink:
    """Console sink that displays nothing (``logging.console: none``)."""

    def emit(self, record: LogRecord, rendered: str) -> None:
        return

    def close(self) -> None:
        return


# Source -> filename stem used by ``separate`` mode.
_SEPARATE_FILE_STEMS: Dict[Source, str] = {
    Source.CLI: "cli",
    Source.DEBUG: "debug",
    Source.SNIFFER: "sniffer",
    Source.GRAYLOG: "graylog",
    Source.CORRELATOR: "correlation",
    Source.SYSTEM: "system",
}

# Sources whose separate-mode filename is not prefixed with the device prefix,
# matching the layout in the project specification.
_UNPREFIXED_SOURCES = {Source.GRAYLOG, Source.CORRELATOR}


class LogBus:
    """Fans rendered log lines out to the console and to log files."""

    def __init__(
        self,
        config: LoggingConfig,
        run_timestamp: datetime,
        console: Optional[ConsoleSink] = None,
    ) -> None:
        self._config = config
        self._run_stamp = run_timestamp.strftime("%Y%m%d_%H%M%S")
        self._console: ConsoleSink = console or StreamConsoleSink()
        self._files: Dict[str, TextIO] = {}
        self._paths: List[Path] = []
        self._closed = False
        self._directory = config.directory
        self._directory.mkdir(parents=True, exist_ok=True)
        reports = config.reports_dir
        reports.mkdir(parents=True, exist_ok=True)

        if config.mode == "combined":
            # Open the combined file eagerly so its path can be shown at startup.
            self._file_for(Source.SYSTEM)

    # -- sinks --------------------------------------------------------------

    def set_console(self, console: ConsoleSink) -> None:
        """Swap the console sink (used by the Phase 2 live display)."""
        self._console = console

    @property
    def log_paths(self) -> List[Path]:
        return list(self._paths)

    @property
    def directory(self) -> Path:
        return self._directory

    def _file_key(self, source: Source) -> str:
        if self._config.mode == "combined":
            return "combined"
        return _SEPARATE_FILE_STEMS.get(source, source.value.lower())

    def _file_path(self, key: str) -> Path:
        prefix = self._config.file_prefix
        if key == "combined":
            return self._directory / f"{prefix}_test_{self._run_stamp}.log"
        if key in ("graylog", "correlation"):
            return self._directory / f"{key}_{self._run_stamp}.log"
        return self._directory / f"{prefix}_{key}_{self._run_stamp}.log"

    def _file_for(self, source: Source) -> Optional[TextIO]:
        if self._closed:
            return None
        key = self._file_key(source)
        handle = self._files.get(key)
        if handle is not None:
            return handle
        path = self._file_path(key)
        try:
            handle = path.open("a", encoding="utf-8")
        except OSError as exc:  # pragma: no cover - disk problems
            sys.stderr.write(f"WARNING: cannot open log file {path}: {exc}\n")
            return None
        self._files[key] = handle
        self._paths.append(path)
        return handle

    # -- rendering ----------------------------------------------------------

    def format_timestamp(self, moment: datetime) -> str:
        text = moment.strftime(self._config.timestamp_format)
        precision = self._config.timestamp_precision_ms
        if "%f" in self._config.timestamp_format:
            # strftime renders microseconds; trim to the configured precision.
            head, _, frac = text.rpartition(".")
            if head and frac.isdigit():
                text = head if precision == 0 else f"{head}.{frac[:precision]}"
        return text

    def render(self, record: LogRecord) -> str:
        parts = [self.format_timestamp(record.timestamp)]
        if record.event_id:
            parts.append(f"[{record.event_id}]")
        parts.append(f"[{record.source.value}]")
        message = record.message
        limit = self._config.max_raw_line_length
        if record.raw and limit and len(message) > limit:
            message = message[:limit] + " ...[truncated]"
        parts.append(message)
        return " ".join(parts)

    # -- emitting -----------------------------------------------------------

    def emit(self, record: LogRecord) -> str:
        """Render one record, display it and write it to disk."""
        rendered = self.render(record)
        self._console.emit(record, rendered)
        handle = self._file_for(record.source)
        if handle is not None:
            try:
                handle.write(rendered + "\n")
                # Flushed per line: this tool chases an intermittent fault, so
                # losing the tail of the log on an abrupt exit is unacceptable.
                handle.flush()
            except (OSError, ValueError) as exc:  # pragma: no cover
                sys.stderr.write(f"WARNING: log write failed: {exc}\n")
        return rendered

    def log(
        self,
        source: Source,
        message: str,
        event_id: Optional[str] = None,
        *,
        raw: bool = False,
        timestamp: Optional[datetime] = None,
    ) -> str:
        return self.emit(
            LogRecord(
                timestamp=timestamp or datetime.now(),
                source=source,
                message=message,
                event_id=event_id,
                raw=raw,
            )
        )

    def log_block(
        self,
        source: Source,
        text: str,
        event_id: Optional[str] = None,
        *,
        raw: bool = True,
        prefix: str = "",
        timestamp: Optional[datetime] = None,
    ) -> None:
        """Log a multi-line block, one rendered line per source line."""
        moment = timestamp or datetime.now()
        for line in text.splitlines():
            if not line.strip():
                continue
            self.log(source, f"{prefix}{line}", event_id, raw=raw, timestamp=moment)

    # Convenience wrappers -------------------------------------------------

    def system(self, message: str, event_id: Optional[str] = None) -> str:
        return self.log(Source.SYSTEM, message, event_id)

    def cli(self, message: str, event_id: Optional[str] = None, *, raw: bool = False) -> str:
        return self.log(Source.CLI, message, event_id, raw=raw)

    def correlator(self, message: str, event_id: Optional[str] = None) -> str:
        return self.log(Source.CORRELATOR, message, event_id)

    def banner(self, text: str, *, console: bool = True) -> None:
        """Write a pre-formatted multi-line block verbatim to console and disk.

        Used for the startup summary and the final report, which are already
        laid out and must not be prefixed line by line. ``console=False``
        records the block on disk only, for text the operator has already seen
        (the startup summary is shown by the confirmation prompt).
        """
        if console:
            for line in text.splitlines():
                self._console.emit(
                    LogRecord(datetime.now(), Source.SYSTEM, line, raw=True), line
                )
        handle = self._file_for(Source.SYSTEM)
        if handle is not None:
            try:
                handle.write(text.rstrip("\n") + "\n")
                handle.flush()
            except (OSError, ValueError):  # pragma: no cover
                pass

    # -- lifecycle ----------------------------------------------------------

    def flush(self) -> None:
        for handle in self._files.values():
            try:
                handle.flush()
            except (OSError, ValueError):  # pragma: no cover
                pass

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for handle in self._files.values():
            try:
                handle.flush()
                handle.close()
            except (OSError, ValueError):  # pragma: no cover
                pass
        self._files.clear()
        self._console.close()
