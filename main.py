#!/usr/bin/env python3
"""FortiManager log transmission troubleshooting and correlation tool.

Phase 1: CLI test event generation, repeating command groups, tee logging and
reporting. Run ``python main.py --help`` for options.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from typing import Optional

from fmtest import PHASE, __version__
from fmtest.app import Application, RunOptions, build_startup_summary, confirm_start
from fmtest.config import ConfigError, load_config

DEFAULT_CONFIG = "config.yaml"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fortimanager-log-test",
        description=(
            "Determine whether FortiManager consistently generates a test event, "
            "transmits it onto the network, and delivers it to Graylog. "
            f"This build implements Phase {PHASE} (CLI generation testing)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python main.py --config config.yaml\n"
            "  python main.py --yes --duration 60\n"
            "  python main.py --mock --yes --duration 20      offline smoke test\n"
            "  python main.py --debug-mode                    capture all evidence + reasons\n"
            "  python main.py --check-config                  validate config and exit\n"
        ),
    )
    parser.add_argument(
        "-c",
        "--config",
        default=DEFAULT_CONFIG,
        help=f"path to the YAML configuration file (default: {DEFAULT_CONFIG})",
    )
    parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="skip the interactive 'Start test?' confirmation",
    )
    parser.add_argument(
        "-d",
        "--duration",
        type=float,
        default=None,
        metavar="SECONDS",
        help="stop automatically after this many seconds (default: run until Ctrl+C)",
    )
    parser.add_argument(
        "--log-dir",
        default=None,
        metavar="PATH",
        help="override logging.directory from the configuration file",
    )
    parser.add_argument(
        "--log-mode",
        choices=("combined", "separate"),
        default=None,
        help="override logging.mode from the configuration file",
    )
    parser.add_argument(
        "--console",
        choices=("plain", "rich", "none"),
        default=None,
        help="override logging.console: 'rich' is the live split-screen display",
    )
    parser.add_argument(
        "--plain",
        action="store_true",
        help="force plain line output even if logging.console is 'rich'",
    )
    parser.add_argument(
        "--no-sniffer",
        action="store_true",
        help="disable the packet sniffer for this run, whatever config.yaml says",
    )
    parser.add_argument(
        "--no-debug",
        action="store_true",
        help="disable the logd debug session for this run, whatever config.yaml says",
    )
    debug = parser.add_argument_group("debug mode (investigating bad results)")
    debug.add_argument(
        "--debug-mode",
        action="store_true",
        help=(
            "capture everything: verbatim per-session raw files, every candidate "
            "the collectors examined with the reason it did or did not match, and "
            "a per-event evidence comparison report"
        ),
    )
    debug.add_argument(
        "--diagnostics-dir",
        default=None,
        metavar="PATH",
        help="where debug-mode artefacts go (default: <log dir>/diagnostics)",
    )

    parser.add_argument(
        "--check-config",
        action="store_true",
        help="validate the configuration, print the startup summary and exit",
    )
    parser.add_argument(
        "--include-raw-evidence",
        action="store_true",
        help="include full raw device output in the JSON report (larger files)",
    )
    parser.add_argument(
        "--shutdown-grace",
        type=float,
        default=5.0,
        metavar="SECONDS",
        help="how long to let in-flight commands finish on Ctrl+C (default: 5)",
    )

    mock = parser.add_argument_group("offline testing")
    mock.add_argument(
        "--mock",
        action="store_true",
        help="run against an in-process fake FortiManager; no device is contacted",
    )
    mock.add_argument(
        "--mock-fail-rate",
        type=float,
        default=0.0,
        metavar="RATE",
        help="fraction of mock test commands that report failure (0.0-1.0)",
    )
    mock.add_argument(
        "--mock-hang-rate",
        type=float,
        default=0.0,
        metavar="RATE",
        help="fraction of mock test commands that never respond (0.0-1.0)",
    )
    mock.add_argument(
        "--mock-drop-rate",
        type=float,
        default=0.0,
        metavar="RATE",
        help=(
            "fraction of mock events that are generated but never transmitted, "
            "so no packet reaches the sniffer (0.0-1.0)"
        ),
    )
    mock.add_argument(
        "--mock-headers-only",
        action="store_true",
        help=(
            "make the mock sniffer print packet headers with no payload, "
            "reproducing a too-low sniffer verbosity"
        ),
    )
    mock.add_argument(
        "--mock-graylog-ingest",
        default=None,
        metavar="URL",
        help=(
            "test harness only: POST each transmitted mock event to this URL so a "
            "test Graylog receives it, mirroring real log forwarding"
        ),
    )
    mock.add_argument(
        "--mock-seed",
        type=int,
        default=None,
        metavar="N",
        help="seed for reproducible mock failure injection",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__} (Phase {PHASE})",
    )
    return parser


def _apply_overrides(config, args: argparse.Namespace) -> None:
    if args.log_dir:
        config.logging.directory = Path(args.log_dir).expanduser()
    if args.log_mode:
        config.logging.mode = args.log_mode
    if args.console:
        config.logging.console = args.console
    if args.no_sniffer:
        config.sniffer.enabled = False
    if args.no_debug:
        config.debug.enabled = False
    if args.debug_mode:
        config.diagnostics.enabled = True
    if args.diagnostics_dir:
        config.diagnostics.directory = Path(args.diagnostics_dir).expanduser()


def _validate_rates(args: argparse.Namespace) -> Optional[str]:
    for name in ("mock_fail_rate", "mock_hang_rate", "mock_drop_rate"):
        value = getattr(args, name)
        if not 0.0 <= value <= 1.0:
            return f"--{name.replace('_', '-')} must be between 0.0 and 1.0"
    if args.duration is not None and args.duration <= 0:
        return "--duration must be greater than zero"
    return None


async def _amain(config, options: RunOptions, summary: str) -> int:
    app = Application(config, options, summary)
    return await app.run()


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    problem = _validate_rates(args)
    if problem:
        parser.error(problem)

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"Configuration error:\n  {exc}", file=sys.stderr)
        return 2

    _apply_overrides(config, args)

    options = RunOptions(
        assume_yes=args.yes,
        duration_seconds=args.duration,
        mock=args.mock,
        mock_fail_rate=args.mock_fail_rate,
        mock_hang_rate=args.mock_hang_rate,
        mock_drop_rate=args.mock_drop_rate,
        mock_headers_only=args.mock_headers_only,
        mock_graylog_ingest=args.mock_graylog_ingest,
        mock_seed=args.mock_seed,
        include_raw_evidence=args.include_raw_evidence,
        shutdown_grace_seconds=args.shutdown_grace,
        force_plain_console=args.plain,
        debug_mode=config.diagnostics.enabled,
    )

    summary = build_startup_summary(config, options)

    if args.check_config:
        print(summary)
        print("\nConfiguration is valid.")
        return 0

    if not confirm_start(summary, options.assume_yes):
        print("Aborted; no test was started.")
        return 0

    try:
        return asyncio.run(_amain(config, options, summary))
    except KeyboardInterrupt:
        # The application handles Ctrl+C internally; this is the last resort so
        # a normal interrupt never prints a traceback.
        print("\nInterrupted.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
