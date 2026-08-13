"""Configuration loading, validation and credential resolution.

Everything device-specific or test-specific lives in config.yaml. Nothing in
this package hardcodes an IP address, credential, command, expected message,
interval, Graylog filter or correlation parameter.

All four phases' configuration sections are parsed and validated here, even
though Phase 1 only *uses* the CLI-side settings. That keeps config.yaml stable
across the whole project: sections belonging to later phases are validated and
carried, and the application reports them as "not implemented until Phase N"
rather than failing.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


class ConfigError(Exception):
    """Raised when config.yaml is missing, malformed or internally invalid."""


class Secret:
    """A string that refuses to render itself.

    Passwords are wrapped in this type so that an accidental log line, f-string
    or exception traceback cannot leak them. The real value is only reachable
    through :meth:`reveal`, which should be called at the point of use and
    never stored.
    """

    __slots__ = ("_value", "_origin")

    def __init__(self, value: str, origin: str = "") -> None:
        self._value = value
        self._origin = origin

    def reveal(self) -> str:
        return self._value

    @property
    def origin(self) -> str:
        """Human readable description of where the secret came from."""
        return self._origin

    def __bool__(self) -> bool:
        return bool(self._value)

    def __len__(self) -> int:  # pragma: no cover - defensive
        return len(self._value)

    def __str__(self) -> str:
        return "***"

    def __repr__(self) -> str:
        return "Secret(***)"

    def __format__(self, spec: str) -> str:
        return "***"


# ---------------------------------------------------------------------------
# Small parsing helpers
# ---------------------------------------------------------------------------


def _require_mapping(value: Any, where: str) -> Dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"{where}: expected a mapping, got {type(value).__name__}")
    return value


def _get_str(data: Dict[str, Any], key: str, where: str, default: Optional[str] = None) -> str:
    value = data.get(key, default)
    if value is None:
        raise ConfigError(f"{where}.{key} is required")
    if not isinstance(value, str):
        raise ConfigError(f"{where}.{key}: expected a string, got {type(value).__name__}")
    return value


def _get_bool(data: Dict[str, Any], key: str, where: str, default: bool) -> bool:
    value = data.get(key, default)
    if not isinstance(value, bool):
        raise ConfigError(f"{where}.{key}: expected true or false, got {value!r}")
    return value


def _get_number(
    data: Dict[str, Any],
    key: str,
    where: str,
    default: Optional[float],
    minimum: Optional[float] = None,
) -> float:
    value = data.get(key, default)
    if value is None:
        raise ConfigError(f"{where}.{key} is required")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{where}.{key}: expected a number, got {value!r}")
    if minimum is not None and value < minimum:
        raise ConfigError(f"{where}.{key}: must be >= {minimum}, got {value!r}")
    return float(value)


def _get_int(
    data: Dict[str, Any],
    key: str,
    where: str,
    default: Optional[int],
    minimum: Optional[int] = None,
) -> int:
    value = _get_number(data, key, where, default, minimum)
    return int(value)


def _split_commands(raw: Any, where: str) -> List[str]:
    """Accept either a YAML block scalar or a list of command strings.

    Blank lines and ``#`` comment lines are dropped so that config.yaml command
    blocks can be annotated.
    """
    if raw is None:
        return []
    if isinstance(raw, str):
        candidates = raw.splitlines()
    elif isinstance(raw, list):
        candidates = []
        for item in raw:
            if not isinstance(item, str):
                raise ConfigError(f"{where}: command list entries must be strings, got {item!r}")
            candidates.extend(item.splitlines())
    else:
        raise ConfigError(f"{where}: expected a string block or list of strings")

    commands: List[str] = []
    for line in candidates:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        commands.append(stripped)
    return commands


def _resolve_secret(data: Dict[str, Any], where: str, required: bool) -> Optional[Secret]:
    """Resolve a password from ``password_env`` (preferred) or ``password``.

    Returns ``None`` when nothing is configured and ``required`` is False.
    """
    env_name = data.get("password_env")
    literal = data.get("password")

    if env_name is not None:
        if not isinstance(env_name, str) or not env_name.strip():
            raise ConfigError(f"{where}.password_env: expected a non-empty environment variable name")
        env_name = env_name.strip()
        value = os.environ.get(env_name)
        if value is None or value == "":
            raise ConfigError(
                f"{where}.password_env refers to environment variable {env_name!r}, "
                f"but it is not set (or is empty).\n"
                f"  Linux/macOS:  export {env_name}='...'\n"
                f"  PowerShell:   $env:{env_name} = '...'\n"
                f"  cmd.exe:      set {env_name}=..."
            )
        return Secret(value, origin=f"environment variable {env_name}")

    if literal is not None:
        if not isinstance(literal, str) or literal == "":
            raise ConfigError(f"{where}.password: expected a non-empty string")
        return Secret(literal, origin="config.yaml (plaintext)")

    if required:
        raise ConfigError(
            f"{where}: no credential configured. Set {where}.password_env to the name of an "
            f"environment variable (recommended), or {where}.password for lab use."
        )
    return None


# ---------------------------------------------------------------------------
# Configuration dataclasses
# ---------------------------------------------------------------------------


@dataclass
class ReconnectConfig:
    enabled: bool = True
    initial_delay_seconds: float = 2.0
    max_delay_seconds: float = 30.0
    max_attempts: int = 0  # 0 == unlimited


@dataclass
class FortiManagerConfig:
    host: str
    port: int = 22
    username: str = "admin"
    password: Optional[Secret] = None
    device_name: str = ""
    client_keys: List[str] = field(default_factory=list)
    known_hosts_file: Optional[str] = None
    strict_host_key: bool = False
    connect_timeout_seconds: float = 20.0
    command_timeout_seconds: float = 30.0
    login_grace_seconds: float = 10.0
    prompt_pattern: str = r"[\r\n][^\r\n]{0,80}?[#$]\s*$"
    session_init_commands: List[str] = field(default_factory=list)
    encryption_algs: List[str] = field(default_factory=list)
    kex_algs: List[str] = field(default_factory=list)
    server_host_key_algs: List[str] = field(default_factory=list)
    reconnect: ReconnectConfig = field(default_factory=ReconnectConfig)

    @property
    def display_name(self) -> str:
        return self.device_name or self.host


@dataclass
class CommandGroupConfig:
    name: str
    commands: List[str]
    interval_seconds: float
    test_event: bool = False
    test_command_index: int = 0
    enabled: bool = True
    initial_delay_seconds: float = 0.0
    timeout_seconds: Optional[float] = None
    log_output: bool = True

    @property
    def test_command(self) -> str:
        """The command within this group that generates a TEST event."""
        if not self.commands:
            return ""
        index = min(max(self.test_command_index, 0), len(self.commands) - 1)
        return self.commands[index]


@dataclass
class IdentityConfig:
    """Secondary correlation keys extracted from evidence content."""

    enabled: bool = True
    require: bool = False
    fields: List[tuple] = field(default_factory=list)  # (name, compiled pattern)


@dataclass
class FlowConfig:
    """Optional packet-flow constraint applied to sniffer matches."""

    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    direction: str = ""


@dataclass
class CorrelationConfig:
    enabled: bool = True
    test_group: Optional[str] = None
    cli_success_pattern: str = "Sent out one test local event log"
    cli_failure_patterns: List[str] = field(default_factory=list)
    expected_message: str = "Power 1 goes to online"
    sniffer_match_pattern: str = "Power 1 goes to online"
    graylog_match_pattern: str = "Power 1 goes to online"
    timeout_seconds: float = 10.0
    timestamp_tolerance_seconds: float = 2.0
    allow_reuse: bool = False
    pattern_is_regex: bool = False
    bound_window_by_next_event: bool = True
    identity: "IdentityConfig" = field(default_factory=lambda: IdentityConfig())
    sniffer_flow: "FlowConfig" = field(default_factory=lambda: FlowConfig())


@dataclass
class SnifferConfig:
    enabled: bool = False
    command: str = ""
    session_name: str = "sniffer"
    stop_key: str = "\x03"
    block_idle_seconds: float = 0.35
    echo_to_log: bool = True
    decode_hex_payload: bool = True


@dataclass
class DebugConfig:
    enabled: bool = False
    session_name: str = "debug"
    setup_commands: List[str] = field(default_factory=list)
    cleanup_commands: List[str] = field(default_factory=list)
    match_patterns: List[str] = field(default_factory=list)
    echo_to_log: bool = True


@dataclass
class GraylogConfig:
    enabled: bool = False
    url: str = ""
    username: str = ""
    password: Optional[Secret] = None
    api_token: Optional[Secret] = None
    api: str = "views"
    verify_tls: bool = True
    ca_bundle: Optional[str] = None
    timeout_seconds: float = 30.0
    poll_interval_seconds: float = 5.0
    poll_overlap_seconds: float = 2.0
    max_indexing_lag_seconds: float = 30.0
    query_extra: str = ""
    streams: List[str] = field(default_factory=list)
    message_field: str = "message"
    timestamp_field: str = "timestamp"
    limit: int = 500
    include_message_in_query: bool = False
    filters: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DiagnosticsConfig:
    """Debug mode: raw evidence capture and per-event match explanation."""

    enabled: bool = False
    directory: Optional[Path] = None
    raw_streams: bool = True
    capture_all_candidates: bool = True
    comparison_report: bool = True
    include_raw_blocks: bool = True
    max_candidates: int = 5000
    max_candidates_per_event: int = 25
    max_raw_block_lines: int = 24
    payload_preview_chars: int = 300

    def resolve_directory(self, log_directory: Path) -> Path:
        return self.directory or (log_directory / "diagnostics")


@dataclass
class LoggingConfig:
    mode: str = "combined"
    directory: Path = Path("./logs")
    report_directory: Optional[Path] = None
    console: str = "plain"
    file_prefix: str = "fortimanager"
    timestamp_format: str = "%Y-%m-%d %H:%M:%S.%f"
    timestamp_precision_ms: int = 3
    echo_raw_command_output: bool = True
    max_raw_line_length: int = 0  # 0 == unlimited

    @property
    def reports_dir(self) -> Path:
        return self.report_directory or self.directory


@dataclass
class AppConfig:
    fortimanager: FortiManagerConfig
    command_groups: List[CommandGroupConfig]
    correlation: CorrelationConfig
    sniffer: SnifferConfig
    debug: DebugConfig
    graylog: GraylogConfig
    logging: LoggingConfig
    diagnostics: DiagnosticsConfig
    source_path: Path
    warnings: List[str] = field(default_factory=list)

    @property
    def test_group(self) -> Optional[CommandGroupConfig]:
        """The command group whose executions become TEST-xxxxxx events."""
        for group in self.command_groups:
            if group.test_event and group.enabled:
                return group
        return None

    @property
    def enabled_groups(self) -> List[CommandGroupConfig]:
        return [g for g in self.command_groups if g.enabled]


# ---------------------------------------------------------------------------
# Section parsers
# ---------------------------------------------------------------------------


def _parse_fortimanager(data: Dict[str, Any], warnings: List[str]) -> FortiManagerConfig:
    where = "fortimanager"
    section = _require_mapping(data.get("fortimanager"), where)
    if not section:
        raise ConfigError("fortimanager: section is required")

    password = _resolve_secret(section, where, required=False)
    client_keys = [str(k) for k in (section.get("client_keys") or [])]
    if password is None and not client_keys:
        raise ConfigError(
            "fortimanager: no authentication configured. Set fortimanager.password_env "
            "(recommended), fortimanager.password, or fortimanager.client_keys."
        )
    if password is not None and password.origin.endswith("(plaintext)"):
        warnings.append(
            "fortimanager password is stored in plaintext in config.yaml; "
            "password_env is recommended."
        )

    reconnect_raw = _require_mapping(section.get("reconnect"), f"{where}.reconnect")
    reconnect = ReconnectConfig(
        enabled=_get_bool(reconnect_raw, "enabled", f"{where}.reconnect", True),
        initial_delay_seconds=_get_number(
            reconnect_raw, "initial_delay_seconds", f"{where}.reconnect", 2.0, minimum=0.1
        ),
        max_delay_seconds=_get_number(
            reconnect_raw, "max_delay_seconds", f"{where}.reconnect", 30.0, minimum=0.1
        ),
        max_attempts=_get_int(reconnect_raw, "max_attempts", f"{where}.reconnect", 0, minimum=0),
    )

    prompt_pattern = _get_str(
        section, "prompt_pattern", where, r"[\r\n][^\r\n]{0,80}?[#$]\s*$"
    )
    try:
        re.compile(prompt_pattern)
    except re.error as exc:
        raise ConfigError(f"{where}.prompt_pattern is not a valid regular expression: {exc}") from exc

    return FortiManagerConfig(
        host=_get_str(section, "host", where),
        port=_get_int(section, "port", where, 22, minimum=1),
        username=_get_str(section, "username", where, "admin"),
        password=password,
        device_name=_get_str(section, "device_name", where, ""),
        client_keys=client_keys,
        known_hosts_file=section.get("known_hosts_file"),
        strict_host_key=_get_bool(section, "strict_host_key", where, False),
        connect_timeout_seconds=_get_number(
            section, "connect_timeout_seconds", where, 20.0, minimum=1.0
        ),
        command_timeout_seconds=_get_number(
            section, "command_timeout_seconds", where, 30.0, minimum=1.0
        ),
        login_grace_seconds=_get_number(section, "login_grace_seconds", where, 10.0, minimum=0.5),
        prompt_pattern=prompt_pattern,
        session_init_commands=_split_commands(
            section.get("session_init_commands"), f"{where}.session_init_commands"
        ),
        encryption_algs=[str(a) for a in (section.get("encryption_algs") or [])],
        kex_algs=[str(a) for a in (section.get("kex_algs") or [])],
        server_host_key_algs=[str(a) for a in (section.get("server_host_key_algs") or [])],
        reconnect=reconnect,
    )


def _parse_command_groups(data: Dict[str, Any], correlation_test_group: Optional[str]) -> List[CommandGroupConfig]:
    raw_groups = data.get("command_groups")
    if not raw_groups:
        raise ConfigError("command_groups: at least one command group is required")
    if not isinstance(raw_groups, list):
        raise ConfigError("command_groups: expected a list")

    groups: List[CommandGroupConfig] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_groups):
        where = f"command_groups[{index}]"
        entry = _require_mapping(raw, where)
        name = _get_str(entry, "name", where)
        if name in seen:
            raise ConfigError(f"{where}.name: duplicate command group name {name!r}")
        seen.add(name)

        commands = _split_commands(entry.get("commands"), f"{where}.commands")
        if not commands:
            raise ConfigError(f"{where}.commands: at least one command is required")

        timeout = entry.get("timeout_seconds")
        if timeout is not None:
            timeout = _get_number(entry, "timeout_seconds", where, None, minimum=0.5)

        test_command_index = _get_int(entry, "test_command_index", where, 0, minimum=0)
        if test_command_index >= len(commands):
            raise ConfigError(
                f"{where}.test_command_index: {test_command_index} is out of range, "
                f"the group has {len(commands)} command(s)"
            )

        groups.append(
            CommandGroupConfig(
                name=name,
                commands=commands,
                interval_seconds=_get_number(entry, "interval_seconds", where, None, minimum=0.5),
                test_event=_get_bool(entry, "test_event", where, False),
                test_command_index=test_command_index,
                enabled=_get_bool(entry, "enabled", where, True),
                initial_delay_seconds=_get_number(
                    entry, "initial_delay_seconds", where, 0.0, minimum=0.0
                ),
                timeout_seconds=timeout,
                log_output=_get_bool(entry, "log_output", where, True),
            )
        )

    # correlation.test_group is the alternative way to designate the test group.
    if correlation_test_group:
        matches = [g for g in groups if g.name == correlation_test_group]
        if not matches:
            raise ConfigError(
                f"correlation.test_group refers to {correlation_test_group!r}, "
                f"which is not a configured command group name"
            )
        for group in groups:
            group.test_event = group.name == correlation_test_group

    flagged = [g for g in groups if g.test_event]
    if len(flagged) > 1:
        names = ", ".join(g.name for g in flagged)
        raise ConfigError(
            f"command_groups: more than one group is marked test_event ({names}). "
            f"Exactly one group generates TEST events."
        )
    if not flagged:
        # Fall back to the first enabled group so the tool is usable without
        # extra ceremony, but this is worth being explicit about in config.
        for group in groups:
            if group.enabled:
                group.test_event = True
                break

    return groups


# Identity keys that are worth trying by default. Each is a no-op when the
# pattern finds nothing, so shipping them enabled cannot make matching worse.
_DEFAULT_IDENTITY_FIELDS = [
    ("seq", r"\bseq=(\d+)"),
    ("log_id", r'\blogid="?(\d+)"?'),
    ("device_id", r'\bdevid="([^"]+)"'),
    ("device_name", r'\bdevname="([^"]+)"'),
    ("event_time", r"\beventtime=(\d+)"),
]


def _parse_identity(data: Dict[str, Any]) -> IdentityConfig:
    where = "correlation.identity"
    section = _require_mapping(data.get("identity"), where)
    enabled = _get_bool(section, "enabled", where, True)
    require = _get_bool(section, "require", where, False)

    raw_fields = section.get("fields")
    if raw_fields is None:
        specs = list(_DEFAULT_IDENTITY_FIELDS)
    else:
        if not isinstance(raw_fields, list):
            raise ConfigError(f"{where}.fields: expected a list of name/pattern entries")
        specs = []
        for index, entry in enumerate(raw_fields):
            item = _require_mapping(entry, f"{where}.fields[{index}]")
            name = _get_str(item, "name", f"{where}.fields[{index}]")
            pattern = _get_str(item, "pattern", f"{where}.fields[{index}]")
            specs.append((name, pattern))

    compiled: List[tuple] = []
    for name, pattern in specs:
        try:
            compiled.append((name, re.compile(pattern, re.IGNORECASE)))
        except re.error as exc:
            raise ConfigError(
                f"{where}: pattern for {name!r} is not a valid regular expression: {exc}"
            ) from exc
    return IdentityConfig(enabled=enabled, require=require, fields=compiled)


def _parse_flow(data: Dict[str, Any]) -> FlowConfig:
    where = "correlation.sniffer_flow"
    section = _require_mapping(data.get("sniffer_flow"), where)
    direction = _get_str(section, "direction", where, "").lower()
    if direction and direction not in ("in", "out"):
        raise ConfigError(f"{where}.direction: expected 'in' or 'out', got {direction!r}")
    return FlowConfig(
        src_ip=_get_str(section, "src_ip", where, ""),
        dst_ip=_get_str(section, "dst_ip", where, ""),
        src_port=_get_int(section, "src_port", where, 0, minimum=0),
        dst_port=_get_int(section, "dst_port", where, 0, minimum=0),
        direction=direction,
    )


def _parse_correlation(data: Dict[str, Any]) -> CorrelationConfig:
    where = "correlation"
    section = _require_mapping(data.get("correlation"), where)
    expected = _get_str(section, "expected_message", where, "Power 1 goes to online")

    correlation = CorrelationConfig(
        enabled=_get_bool(section, "enabled", where, True),
        test_group=section.get("test_group"),
        cli_success_pattern=_get_str(
            section, "cli_success_pattern", where, "Sent out one test local event log"
        ),
        cli_failure_patterns=[str(p) for p in (section.get("cli_failure_patterns") or [])],
        expected_message=expected,
        sniffer_match_pattern=_get_str(section, "sniffer_match_pattern", where, expected),
        graylog_match_pattern=_get_str(section, "graylog_match_pattern", where, expected),
        timeout_seconds=_get_number(section, "timeout_seconds", where, 10.0, minimum=0.5),
        timestamp_tolerance_seconds=_get_number(
            section, "timestamp_tolerance_seconds", where, 2.0, minimum=0.0
        ),
        allow_reuse=_get_bool(section, "allow_reuse", where, False),
        pattern_is_regex=_get_bool(section, "pattern_is_regex", where, False),
        bound_window_by_next_event=_get_bool(
            section, "bound_window_by_next_event", where, True
        ),
        identity=_parse_identity(section),
        sniffer_flow=_parse_flow(section),
    )

    if correlation.test_group is not None and not isinstance(correlation.test_group, str):
        raise ConfigError(f"{where}.test_group: expected a string command group name")

    if correlation.pattern_is_regex:
        for label, pattern in (
            ("cli_success_pattern", correlation.cli_success_pattern),
            ("sniffer_match_pattern", correlation.sniffer_match_pattern),
            ("graylog_match_pattern", correlation.graylog_match_pattern),
        ):
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ConfigError(f"{where}.{label} is not a valid regular expression: {exc}") from exc

    return correlation


def _parse_sniffer(data: Dict[str, Any]) -> SnifferConfig:
    where = "sniffer"
    section = _require_mapping(data.get("sniffer"), where)
    enabled = _get_bool(section, "enabled", where, False)
    command_lines = _split_commands(section.get("command"), f"{where}.command")
    if enabled and not command_lines:
        raise ConfigError(
            f"{where}.command is required when the sniffer is enabled. "
            f"The complete FortiManager sniffer command must be supplied here; "
            f"the tool never constructs it."
        )
    if len(command_lines) > 1:
        raise ConfigError(f"{where}.command: expected a single command, got {len(command_lines)} lines")

    return SnifferConfig(
        enabled=enabled,
        command=command_lines[0] if command_lines else "",
        session_name=_get_str(section, "session_name", where, "sniffer"),
        stop_key=section.get("stop_key", "\x03"),
        block_idle_seconds=_get_number(section, "block_idle_seconds", where, 0.35, minimum=0.05),
        echo_to_log=_get_bool(section, "echo_to_log", where, True),
        decode_hex_payload=_get_bool(section, "decode_hex_payload", where, True),
    )


def _parse_debug(data: Dict[str, Any]) -> DebugConfig:
    where = "debug"
    section = _require_mapping(data.get("debug"), where)
    enabled = _get_bool(section, "enabled", where, False)
    setup = _split_commands(section.get("setup_commands"), f"{where}.setup_commands")
    cleanup = _split_commands(section.get("cleanup_commands"), f"{where}.cleanup_commands")
    if enabled and not setup:
        raise ConfigError(f"{where}.setup_commands is required when debug is enabled")
    if enabled and not cleanup:
        raise ConfigError(
            f"{where}.cleanup_commands is required when debug is enabled, so that debugging "
            f"is always turned off again on the device at shutdown"
        )

    return DebugConfig(
        enabled=enabled,
        session_name=_get_str(section, "session_name", where, "debug"),
        setup_commands=setup,
        cleanup_commands=cleanup,
        match_patterns=[str(p) for p in (section.get("match_patterns") or [])],
        echo_to_log=_get_bool(section, "echo_to_log", where, True),
    )


def _parse_graylog(data: Dict[str, Any], warnings: List[str]) -> GraylogConfig:
    where = "graylog"
    section = _require_mapping(data.get("graylog"), where)
    enabled = _get_bool(section, "enabled", where, False)

    password: Optional[Secret] = None
    token: Optional[Secret] = None
    token_env = section.get("api_token_env")
    # Credentials are only resolved when Graylog is actually in use, so a
    # disabled Graylog section never forces an environment variable to exist.
    if enabled:
        if token_env:
            if not isinstance(token_env, str):
                raise ConfigError(f"{where}.api_token_env: expected an environment variable name")
            value = os.environ.get(token_env)
            if not value:
                raise ConfigError(
                    f"{where}.api_token_env refers to environment variable {token_env!r}, "
                    f"but it is not set (or is empty)."
                )
            token = Secret(value, origin=f"environment variable {token_env}")
        else:
            password = _resolve_secret(section, where, required=True)
            if password is not None and password.origin.endswith("(plaintext)"):
                warnings.append(
                    "graylog password is stored in plaintext in config.yaml; "
                    "password_env is recommended."
                )

    url = _get_str(section, "url", where, "")
    if enabled and not url:
        raise ConfigError(f"{where}.url is required when graylog is enabled")

    api = _get_str(section, "api", where, "views").lower()
    if api not in ("views",):
        raise ConfigError(
            f"{where}.api: only 'views' (the Graylog Views/Search API) is supported, got {api!r}"
        )

    filters = _require_mapping(section.get("filters"), f"{where}.filters")

    return GraylogConfig(
        enabled=enabled,
        url=url.rstrip("/"),
        username=_get_str(section, "username", where, ""),
        password=password,
        api_token=token,
        api=api,
        verify_tls=_get_bool(section, "verify_tls", where, True),
        ca_bundle=section.get("ca_bundle"),
        timeout_seconds=_get_number(section, "timeout_seconds", where, 30.0, minimum=1.0),
        poll_interval_seconds=_get_number(
            section, "poll_interval_seconds", where, 5.0, minimum=0.5
        ),
        poll_overlap_seconds=_get_number(section, "poll_overlap_seconds", where, 2.0, minimum=0.0),
        max_indexing_lag_seconds=_get_number(
            section, "max_indexing_lag_seconds", where, 30.0, minimum=0.0
        ),
        query_extra=_get_str(section, "query_extra", where, ""),
        streams=[str(s) for s in (section.get("streams") or [])],
        message_field=_get_str(section, "message_field", where, "message"),
        timestamp_field=_get_str(section, "timestamp_field", where, "timestamp"),
        limit=_get_int(section, "limit", where, 500, minimum=1),
        include_message_in_query=_get_bool(
            section, "include_message_in_query", where, False
        ),
        filters=dict(filters),
    )


def _parse_diagnostics(data: Dict[str, Any]) -> DiagnosticsConfig:
    where = "diagnostics"
    section = _require_mapping(data.get("diagnostics"), where)
    directory = section.get("directory")
    return DiagnosticsConfig(
        enabled=_get_bool(section, "enabled", where, False),
        directory=Path(directory).expanduser() if directory else None,
        raw_streams=_get_bool(section, "raw_streams", where, True),
        capture_all_candidates=_get_bool(section, "capture_all_candidates", where, True),
        comparison_report=_get_bool(section, "comparison_report", where, True),
        include_raw_blocks=_get_bool(section, "include_raw_blocks", where, True),
        max_candidates=_get_int(section, "max_candidates", where, 5000, minimum=1),
        max_candidates_per_event=_get_int(
            section, "max_candidates_per_event", where, 25, minimum=1
        ),
        max_raw_block_lines=_get_int(section, "max_raw_block_lines", where, 24, minimum=1),
        payload_preview_chars=_get_int(
            section, "payload_preview_chars", where, 300, minimum=20
        ),
    )


def _parse_logging(data: Dict[str, Any]) -> LoggingConfig:
    where = "logging"
    section = _require_mapping(data.get("logging"), where)

    mode = _get_str(section, "mode", where, "combined").lower()
    if mode not in ("combined", "separate"):
        raise ConfigError(f"{where}.mode: expected 'combined' or 'separate', got {mode!r}")

    console = _get_str(section, "console", where, "plain").lower()
    if console not in ("plain", "rich", "none"):
        raise ConfigError(f"{where}.console: expected 'plain', 'rich' or 'none', got {console!r}")

    report_directory = section.get("report_directory")

    precision = _get_int(section, "timestamp_precision_ms", where, 3, minimum=0)
    if precision > 6:
        raise ConfigError(f"{where}.timestamp_precision_ms: maximum supported precision is 6")

    return LoggingConfig(
        mode=mode,
        directory=Path(_get_str(section, "directory", where, "./logs")).expanduser(),
        report_directory=Path(report_directory).expanduser() if report_directory else None,
        console=console,
        file_prefix=_get_str(section, "file_prefix", where, "fortimanager"),
        timestamp_format=_get_str(section, "timestamp_format", where, "%Y-%m-%d %H:%M:%S.%f"),
        timestamp_precision_ms=precision,
        echo_raw_command_output=_get_bool(section, "echo_raw_command_output", where, True),
        max_raw_line_length=_get_int(section, "max_raw_line_length", where, 0, minimum=0),
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def load_config(path: str | Path) -> AppConfig:
    """Load, validate and return the application configuration.

    Raises :class:`ConfigError` with an actionable message for any problem.
    """
    config_path = Path(path).expanduser()
    if not config_path.is_file():
        raise ConfigError(f"config file not found: {config_path}")

    try:
        with config_path.open("r", encoding="utf-8") as handle:
            raw = yaml.safe_load(handle)
    except yaml.YAMLError as exc:
        raise ConfigError(f"could not parse {config_path}: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"could not read {config_path}: {exc}") from exc

    if raw is None:
        raise ConfigError(f"{config_path} is empty")
    if not isinstance(raw, dict):
        raise ConfigError(f"{config_path}: top level must be a mapping")

    warnings: List[str] = []
    fortimanager = _parse_fortimanager(raw, warnings)
    correlation = _parse_correlation(raw)
    command_groups = _parse_command_groups(raw, correlation.test_group)
    sniffer = _parse_sniffer(raw)
    debug = _parse_debug(raw)
    graylog = _parse_graylog(raw, warnings)
    logging_cfg = _parse_logging(raw)
    diagnostics = _parse_diagnostics(raw)

    if not [g for g in command_groups if g.enabled]:
        raise ConfigError("command_groups: every group is disabled, there is nothing to run")

    return AppConfig(
        fortimanager=fortimanager,
        command_groups=command_groups,
        correlation=correlation,
        sniffer=sniffer,
        debug=debug,
        graylog=graylog,
        logging=logging_cfg,
        diagnostics=diagnostics,
        source_path=config_path,
        warnings=warnings,
    )
