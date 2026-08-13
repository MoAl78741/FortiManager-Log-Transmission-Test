"""Graylog Views/Search API client.

Transport only: this module builds queries, talks HTTP and returns messages. It
holds no opinion about which test event a message belongs to -- that is the
correlator's job.

The Views/Search API is a two-step protocol, stable since Graylog 3.2:

    POST /api/views/search              -> {"id": "<search id>"}
    POST /api/views/search/<id>/execute -> {"execution": {...}, "results": {...}}

Both require the ``X-Requested-By`` header (CSRF protection). Authentication is
HTTP Basic, either ``username:password`` or, for an API token, the token as the
username with the literal password ``token``.

Nothing in here ever logs a credential. The Authorization header is built by
aiohttp from a :class:`~fmtest.config.Secret` at request time and is never
rendered, stored or passed to the diagnostics recorder.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import aiohttp

from .config import GraylogConfig

# Lucene syntax characters that must be escaped inside a filter value.
_LUCENE_SPECIAL = re.compile(r'([+\-!(){}\[\]^"~*?:\\/]|&&|\|\|)')

_QUERY_ID = "fmtest-query"
_SEARCH_TYPE_ID = "fmtest-messages"


class GraylogError(Exception):
    """Raised when Graylog cannot be reached or returns an unusable response."""


def escape_lucene(value: str) -> str:
    """Escape a value for safe inclusion in a Lucene query string."""
    return _LUCENE_SPECIAL.sub(r"\\\1", value)


def build_query_string(
    filters: Dict[str, Any],
    query_extra: str = "",
    message_pattern: Optional[str] = None,
) -> str:
    """Build the Lucene query from the configured filters.

    Every key under ``graylog.filters`` becomes a ``field:"value"`` term ANDed
    into the query, so adding a new filtering field needs no code change. A
    list value becomes an OR group.

    ``message_pattern`` is only included when
    ``graylog.include_message_in_query`` is on. Leaving it out is the default:
    the tool then fetches everything matching the filters and verifies the
    message content locally, which is slower but shows you the near misses
    instead of an empty result set when analyzer tokenisation disagrees with
    your expected string.
    """
    terms: List[str] = []
    for key, value in filters.items():
        if value is None:
            continue
        if isinstance(value, (list, tuple, set)):
            options = [f'{key}:"{escape_lucene(str(v))}"' for v in value if v is not None]
            if options:
                terms.append("(" + " OR ".join(options) + ")")
        else:
            terms.append(f'{key}:"{escape_lucene(str(value))}"')

    if message_pattern:
        terms.append(f'"{escape_lucene(message_pattern)}"')
    if query_extra.strip():
        terms.append(f"({query_extra.strip()})")

    return " AND ".join(terms) if terms else "*"


def _to_graylog_time(moment: datetime) -> str:
    """Render a datetime as the UTC ISO8601 string Graylog expects."""
    if moment.tzinfo is None:
        moment = moment.astimezone()
    return (
        moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.")
        + f"{moment.astimezone(timezone.utc).microsecond // 1000:03d}Z"
    )


def parse_graylog_timestamp(value: Any) -> Optional[datetime]:
    """Parse a Graylog timestamp into an aware UTC datetime.

    Graylog emits ``2026-08-11T21:42:39.301Z``; some inputs carry an explicit
    offset instead. Both are accepted.
    """
    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S.%f"):
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
        else:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass
class GraylogMessage:
    """One message returned by a search."""

    message_id: str
    timestamp_utc: Optional[datetime]
    timestamp_local: Optional[datetime]
    retrieved_at: datetime
    text: str
    fields: Dict[str, Any] = field(default_factory=dict)
    index: str = ""

    @property
    def correlation_time(self) -> datetime:
        """Local-time anchor used for correlation.

        The message timestamp is preferred because it reflects when the event
        happened rather than when this tool happened to poll; polling would
        quantise every delta to the poll interval. Falls back to retrieval time
        when Graylog gives no usable timestamp.
        """
        return self.timestamp_local or self.retrieved_at

    def searchable(self, message_field: str) -> Tuple[str, str]:
        """(label, text) to match against, preferring the configured field."""
        primary = self.fields.get(message_field)
        if isinstance(primary, str) and primary:
            return (message_field, primary)
        if self.text:
            return ("message", self.text)
        rendered = " ".join(
            f"{k}={v}" for k, v in self.fields.items() if isinstance(v, (str, int, float))
        )
        return ("full_record", rendered)


class GraylogClient:
    """Async client for the Graylog Views/Search API."""

    def __init__(self, config: GraylogConfig, diagnostics=None) -> None:
        self._config = config
        self._diagnostics = diagnostics
        self._session: Optional[aiohttp.ClientSession] = None
        self.version: Optional[str] = None
        self.node_id: Optional[str] = None

    # -- lifecycle ----------------------------------------------------------

    def _auth_header(self) -> str:
        """Build the Basic auth header value.

        Constructed directly rather than via ``aiohttp.BasicAuth``, which is
        deprecated in aiohttp 3.14 and removed in 4.0. The credential is read
        from the Secret here and immediately encoded; it is never stored on the
        client or included in anything the diagnostics recorder sees.
        """
        cfg = self._config
        if cfg.api_token is not None:
            # Graylog API tokens authenticate as <token>:token.
            login, password = cfg.api_token.reveal(), "token"
        else:
            login = cfg.username
            password = cfg.password.reveal() if cfg.password is not None else ""
        encoded = base64.b64encode(f"{login}:{password}".encode("utf-8")).decode("ascii")
        return f"Basic {encoded}"

    def _ssl_context(self):
        cfg = self._config
        if not cfg.url.lower().startswith("https"):
            return None
        if not cfg.verify_tls:
            return False
        if cfg.ca_bundle:
            try:
                return ssl.create_default_context(cafile=cfg.ca_bundle)
            except (OSError, ssl.SSLError) as exc:
                raise GraylogError(
                    f"graylog.ca_bundle {cfg.ca_bundle!r} could not be loaded: {exc}"
                ) from exc
        return None  # aiohttp default: verify with the system trust store

    async def connect(self) -> str:
        """Open the HTTP session and confirm the API answers.

        Returns a short description of the server. Raises :class:`GraylogError`
        with an actionable message on any failure.
        """
        cfg = self._config
        timeout = aiohttp.ClientTimeout(total=cfg.timeout_seconds)
        connector = aiohttp.TCPConnector(ssl=self._ssl_context())
        self._session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers={
                "Authorization": self._auth_header(),
                # Graylog rejects non-GET API calls without this (CSRF guard).
                "X-Requested-By": "fortimanager-log-test",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )

        payload = await self._request("GET", "/api/system")
        self.version = str(payload.get("version", "unknown"))
        self.node_id = str(payload.get("node_id", ""))
        hostname = payload.get("hostname", "")
        return f"Graylog {self.version} at {cfg.url}" + (f" ({hostname})" if hostname else "")

    async def close(self) -> None:
        if self._session is not None:
            try:
                await self._session.close()
            except Exception:
                pass
            self._session = None

    # -- HTTP ---------------------------------------------------------------

    async def _request(
        self, method: str, path: str, body: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        if self._session is None:
            raise GraylogError("Graylog client is not connected")
        url = f"{self._config.url}{path}"
        try:
            async with self._session.request(method, url, json=body) as response:
                text = await response.text()
                status = response.status
        except aiohttp.ClientConnectorCertificateError as exc:
            raise GraylogError(
                f"TLS certificate verification failed for {self._config.url}: {exc}. "
                f"Set graylog.ca_bundle to your internal CA, or graylog.verify_tls: false "
                f"for a self-signed lab certificate."
            ) from exc
        except aiohttp.ClientConnectorError as exc:
            raise GraylogError(
                f"cannot reach {self._config.url}: {exc}. Check graylog.url, the port, "
                f"and that the Graylog API is listening there."
            ) from exc
        except asyncio.TimeoutError as exc:
            raise GraylogError(
                f"request to {path} timed out after {self._config.timeout_seconds:g}s"
            ) from exc
        except aiohttp.ClientError as exc:
            raise GraylogError(f"HTTP error talking to {url}: {type(exc).__name__}: {exc}") from exc

        self._record_exchange(method, path, body, status, text)

        if status == 401:
            raise GraylogError(
                "Graylog rejected the credentials (401). Check the API token or "
                "username/password; the credential itself is not shown here."
            )
        if status == 403:
            raise GraylogError(
                "Graylog returned 403 Forbidden. The account authenticated but is not "
                "permitted to run searches."
            )
        if status == 404:
            raise GraylogError(
                f"Graylog returned 404 for {path}. This build uses the Views/Search API "
                f"(Graylog 3.2+); check the server version and that {self._config.url} "
                f"is the API root."
            )
        if status >= 400:
            raise GraylogError(f"Graylog returned HTTP {status} for {path}: {text[:400]}")

        if not text.strip():
            return {}
        try:
            parsed = json.loads(text)
        except ValueError as exc:
            raise GraylogError(
                f"Graylog returned a non-JSON response for {path} "
                f"(is {self._config.url} really the Graylog API?): {text[:200]}"
            ) from exc
        if not isinstance(parsed, dict):
            raise GraylogError(f"Graylog returned an unexpected payload shape for {path}")
        return parsed

    def _record_exchange(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]],
        status: int,
        text: str,
    ) -> None:
        if self._diagnostics is None:
            return
        # Deliberately records the URL, body and response only. Credentials live
        # in the Authorization header, which is never passed in here.
        self._diagnostics.record_graylog_exchange(
            {"method": method, "path": path, "body": body},
            {"status": status, "body": text[:20000]},
        )

    # -- searching ----------------------------------------------------------

    def _search_request(self, frm: datetime, to: datetime, query: str) -> Dict[str, Any]:
        cfg = self._config
        search_query: Dict[str, Any] = {
            "id": _QUERY_ID,
            "query": {"type": "elasticsearch", "query_string": query},
            "timerange": {
                "type": "absolute",
                "from": _to_graylog_time(frm),
                "to": _to_graylog_time(to),
            },
            "search_types": [
                {
                    "id": _SEARCH_TYPE_ID,
                    "type": "messages",
                    "limit": cfg.limit,
                    "offset": 0,
                    "sort": [{"field": cfg.timestamp_field, "order": "ASC"}],
                }
            ],
        }
        if cfg.streams:
            search_query["filter"] = {
                "type": "or",
                "filters": [
                    {"type": "stream", "id": stream_id} for stream_id in cfg.streams
                ],
            }
        return {"queries": [search_query]}

    async def search(
        self, frm: datetime, to: datetime, query: str
    ) -> Tuple[List[GraylogMessage], Dict[str, Any]]:
        """Run one search and return the messages it produced."""
        request_body = self._search_request(frm, to, query)
        created = await self._request("POST", "/api/views/search", request_body)
        search_id = created.get("id")
        if not search_id:
            raise GraylogError(
                f"Graylog did not return a search id; got keys {sorted(created)[:8]}"
            )

        payload = await self._request("POST", f"/api/views/search/{search_id}/execute", {})

        # Normally synchronous, but honour the async contract if the server
        # reports the job is still running.
        attempts = 0
        while not _execution_done(payload) and attempts < 5:
            attempts += 1
            await asyncio.sleep(0.5)
            payload = await self._request("POST", f"/api/views/search/{search_id}/execute", {})
        if not _execution_done(payload):
            raise GraylogError("Graylog search did not complete within the allowed retries")

        return self._extract_messages(payload), payload

    def _extract_messages(self, payload: Dict[str, Any]) -> List[GraylogMessage]:
        results = payload.get("results") or {}
        query_result = results.get(_QUERY_ID) or {}

        errors = query_result.get("errors") or []
        if errors:
            described = "; ".join(
                str(e.get("description") or e.get("message") or e)[:200] for e in errors[:3]
            )
            raise GraylogError(f"Graylog reported a search error: {described}")

        search_types = query_result.get("search_types") or {}
        block = search_types.get(_SEARCH_TYPE_ID) or {}
        raw_messages = block.get("messages") or []

        retrieved_at = datetime.now()
        messages: List[GraylogMessage] = []
        for entry in raw_messages:
            body = entry.get("message") if isinstance(entry, dict) else None
            if not isinstance(body, dict):
                continue
            timestamp_utc = parse_graylog_timestamp(body.get(self._config.timestamp_field))
            messages.append(
                GraylogMessage(
                    message_id=str(body.get("_id") or body.get("id") or ""),
                    timestamp_utc=timestamp_utc,
                    timestamp_local=(
                        timestamp_utc.astimezone().replace(tzinfo=None)
                        if timestamp_utc
                        else None
                    ),
                    retrieved_at=retrieved_at,
                    text=str(body.get(self._config.message_field, "") or ""),
                    fields={k: v for k, v in body.items() if not k.startswith("streams")},
                    index=str(entry.get("index", "")),
                )
            )
        return messages


def _execution_done(payload: Dict[str, Any]) -> bool:
    execution = payload.get("execution")
    if not isinstance(execution, dict):
        # Older responses omit the block entirely and are always complete.
        return True
    return bool(execution.get("done", True))


def describe_window(frm: datetime, to: datetime) -> str:
    span = (to - frm).total_seconds()
    return f"{_to_graylog_time(frm)} .. {_to_graylog_time(to)} ({span:.1f}s)"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def local_to_utc(moment: datetime) -> datetime:
    if moment.tzinfo is None:
        return moment.astimezone().astimezone(timezone.utc)
    return moment.astimezone(timezone.utc)


