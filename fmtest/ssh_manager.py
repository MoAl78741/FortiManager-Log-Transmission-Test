"""SSH connection management for FortiManager.

The tool needs several *concurrent* logical sessions against the same device:

1. repeating CLI commands
2. the continuous packet sniffer (Phase 2)
3. the optional continuous logd debug stream (Phase 2)

Each logical session gets its own TCP connection rather than sharing channels
on one connection. FortiOS and FortiManager are unreliable about multiplexing
session channels, and separate connections give real fault isolation: a dropped
sniffer session must not take the CLI loop down with it.

:class:`SSHGateway` is the only place that knows about asyncssh. Everything
above it talks to :class:`~fmtest.shell.InteractiveShell`, which is why the
offline mock device in :mod:`fmtest.mock_device` can be swapped in wholesale.
"""

from __future__ import annotations

import asyncio
from typing import Dict, List, Optional, Protocol

import asyncssh

from .config import FortiManagerConfig
from .logbus import LogBus
from .shell import InteractiveShell, ShellClosedError

# FortiManager closes the channel immediately when it will not grant another
# concurrent admin login. That looks like a shell that dies during the login
# handshake, so the failure is annotated with the likely cause.
_SESSION_REFUSED_HINT = (
    "the device closed the session during login. FortiManager limits concurrent "
    "admin logins, and this tool needs one session per collector (cli, sniffer, "
    "debug). Consider disabling a collector, or using a second admin account."
)


class SSHConnectionError(Exception):
    """Raised when a session cannot be established."""


class DeviceGateway(Protocol):
    """Opens named interactive shells against the target device."""

    async def open_session(self, name: str) -> "DeviceSession": ...

    async def close_all(self) -> None: ...

    @property
    def description(self) -> str: ...


class _AsyncSSHTransport:
    """Adapts an asyncssh process to the :class:`ShellTransport` protocol."""

    def __init__(self, process: "asyncssh.SSHClientProcess") -> None:
        self._process = process
        self._closed = False

    async def read(self) -> str:
        if self._closed:
            return ""
        try:
            data = await self._process.stdout.read(65536)
        except (asyncssh.Error, OSError, ConnectionResetError):
            self._closed = True
            return ""
        if data == "":
            self._closed = True
        return data

    async def write(self, data: str) -> None:
        if self._closed:
            raise ConnectionResetError("ssh channel is closed")
        self._process.stdin.write(data)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._process.stdin.write_eof()
        except Exception:
            pass
        try:
            self._process.close()
        except Exception:
            pass

    @property
    def closed(self) -> bool:
        return self._closed or self._process.exit_status is not None


class DeviceSession:
    """A named logical session: one connection plus one interactive shell."""

    def __init__(self, name: str, shell: InteractiveShell) -> None:
        self.name = name
        self.shell = shell
        self._closed = False

    @property
    def connected(self) -> bool:
        return not self._closed and not self.shell.closed

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self.shell.aclose()


class SSHSession(DeviceSession):
    """A :class:`DeviceSession` backed by a real asyncssh connection."""

    def __init__(
        self,
        name: str,
        shell: InteractiveShell,
        connection: "asyncssh.SSHClientConnection",
        process: "asyncssh.SSHClientProcess",
    ) -> None:
        super().__init__(name, shell)
        self._connection = connection
        self._process = process

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        # Ask the device to end the session politely before dropping the TCP
        # connection; FortiManager holds admin session slots otherwise.
        try:
            await asyncio.wait_for(self.shell.write_raw("exit\n"), timeout=2.0)
            await asyncio.sleep(0.2)
        except Exception:
            pass
        await self.shell.aclose()
        try:
            self._connection.close()
            await asyncio.wait_for(self._connection.wait_closed(), timeout=5.0)
        except (asyncio.TimeoutError, Exception):
            pass


class SSHGateway:
    """Creates and tracks asyncssh sessions to one FortiManager."""

    def __init__(self, config: FortiManagerConfig, logbus: LogBus) -> None:
        self._config = config
        self._log = logbus
        self._sessions: Dict[str, DeviceSession] = {}

    @property
    def description(self) -> str:
        cfg = self._config
        return f"{cfg.display_name} ({cfg.host}:{cfg.port}) as {cfg.username}"

    # -- connection ---------------------------------------------------------

    def _connect_kwargs(self) -> dict:
        cfg = self._config
        kwargs: dict = {
            "host": cfg.host,
            "port": cfg.port,
            "username": cfg.username,
            "connect_timeout": cfg.connect_timeout_seconds,
            # FortiManager frequently offers legacy algorithms; do not silently
            # fail on an empty algorithm intersection without telling the user.
            "keepalive_interval": 15,
        }
        if cfg.password is not None:
            kwargs["password"] = cfg.password.reveal()
        if cfg.client_keys:
            kwargs["client_keys"] = cfg.client_keys
        else:
            # Prevent asyncssh from silently trying ~/.ssh keys and tripping
            # FortiManager's failed-login lockout.
            if cfg.password is not None:
                kwargs["client_keys"] = None
        if cfg.strict_host_key:
            if cfg.known_hosts_file:
                kwargs["known_hosts"] = cfg.known_hosts_file
        else:
            kwargs["known_hosts"] = None
        if cfg.encryption_algs:
            kwargs["encryption_algs"] = cfg.encryption_algs
        if cfg.kex_algs:
            kwargs["kex_algs"] = cfg.kex_algs
        if cfg.server_host_key_algs:
            kwargs["server_host_key_algs"] = cfg.server_host_key_algs
        return kwargs

    async def _connect_once(self, name: str) -> SSHSession:
        cfg = self._config
        connection = await asyncio.wait_for(
            asyncssh.connect(**self._connect_kwargs()),
            timeout=cfg.connect_timeout_seconds + 5.0,
        )
        try:
            process = await connection.create_process(
                term_type="vt100",
                term_size=(240, 50),
                encoding="utf-8",
                errors="replace",
            )
        except Exception:
            connection.close()
            raise

        shell = InteractiveShell(
            _AsyncSSHTransport(process),
            name=name,
            prompt_pattern=cfg.prompt_pattern,
        )
        shell.start()
        session = SSHSession(name, shell, connection, process)

        try:
            prompt = await shell.learn_prompt(timeout=cfg.login_grace_seconds)
            if prompt:
                self._log.system(f"session '{name}': prompt detected as {prompt!r}")
            else:
                self._log.system(
                    f"session '{name}': prompt not detected, falling back to "
                    f"fortimanager.prompt_pattern"
                )

            for command in cfg.session_init_commands:
                result = await shell.run(command, timeout=cfg.command_timeout_seconds)
                detail = "ok" if result.ok else (result.error or "timed out")
                self._log.system(f"session '{name}': init command {command!r} -> {detail}")
        except BaseException:
            # Do not leak a half-open connection if login setup fails.
            await shell.aclose()
            connection.close()
            raise

        if shell.closed:
            await shell.aclose()
            connection.close()
            raise ShellClosedError(f"session '{name}' ended during login setup")

        return session

    async def open_session(self, name: str) -> DeviceSession:
        """Open a named session, retrying according to the reconnect policy."""
        cfg = self._config
        policy = cfg.reconnect
        attempt = 0
        delay = policy.initial_delay_seconds
        last_error: Optional[str] = None

        while True:
            attempt += 1
            try:
                self._log.system(
                    f"session '{name}': connecting to {cfg.host}:{cfg.port} "
                    f"as {cfg.username} (attempt {attempt})"
                )
                session = await self._connect_once(name)
                self._sessions[name] = session
                self._log.system(f"session '{name}': connected")
                return session
            except asyncio.CancelledError:
                raise
            except asyncio.TimeoutError:
                last_error = f"timed out after {cfg.connect_timeout_seconds:.0f}s"
            except ShellClosedError:
                last_error = _SESSION_REFUSED_HINT
            except asyncssh.PermissionDenied:
                # Credentials are wrong; retrying risks locking the account.
                raise SSHConnectionError(
                    f"session '{name}': authentication failed for user "
                    f"{cfg.username!r} on {cfg.host}. Check the credential source "
                    f"and that the account is permitted to log in over SSH."
                )
            except (asyncssh.Error, OSError) as exc:
                last_error = f"{type(exc).__name__}: {exc}"

            self._log.system(f"session '{name}': connect failed ({last_error})")
            if not policy.enabled:
                raise SSHConnectionError(f"session '{name}': {last_error}")
            if policy.max_attempts and attempt >= policy.max_attempts:
                raise SSHConnectionError(
                    f"session '{name}': giving up after {attempt} attempts ({last_error})"
                )
            self._log.system(f"session '{name}': retrying in {delay:.1f}s")
            await asyncio.sleep(delay)
            delay = min(delay * 2, policy.max_delay_seconds)

    async def reconnect(self, name: str) -> Optional[DeviceSession]:
        """Replace a dead session with a fresh one."""
        old = self._sessions.pop(name, None)
        if old is not None:
            try:
                await old.close()
            except Exception:
                pass
        try:
            return await self.open_session(name)
        except SSHConnectionError as exc:
            self._log.system(f"reconnect failed: {exc}")
            return None

    def get(self, name: str) -> Optional[DeviceSession]:
        return self._sessions.get(name)

    @property
    def session_names(self) -> List[str]:
        return list(self._sessions)

    async def close_all(self) -> None:
        sessions = list(self._sessions.items())
        self._sessions.clear()
        for name, session in sessions:
            try:
                await asyncio.wait_for(session.close(), timeout=8.0)
                self._log.system(f"session '{name}': closed")
            except asyncio.TimeoutError:
                self._log.system(f"session '{name}': close timed out")
            except Exception as exc:
                self._log.system(f"session '{name}': close error ({type(exc).__name__}: {exc})")


async def probe_reachable(config: FortiManagerConfig, timeout: float = 5.0) -> Optional[str]:
    """Best-effort TCP reachability check used by the startup summary.

    Returns ``None`` when the port accepts a connection, otherwise a short
    description of the failure. Never raises.
    """
    try:
        connection = await asyncio.wait_for(
            asyncio.open_connection(config.host, config.port), timeout=timeout
        )
    except asyncio.TimeoutError:
        return f"no response from {config.host}:{config.port} within {timeout:.0f}s"
    except OSError as exc:
        return f"{type(exc).__name__}: {exc}"
    reader, writer = connection
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    return None
