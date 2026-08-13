"""Secondary correlation fields: identity keys extracted from evidence.

Order-based matching is the fallback, not the goal. When the event itself
carries something unique -- a sequence number, a log id, a device id -- two
observations carrying the same value are the *same* event, and correlation
stops depending on arrival order at all.

The extractor is configuration-driven. Each entry is a name and a regular
expression whose first capturing group is the value::

    correlation:
      identity:
        fields:
          - name: "seq"
            pattern: 'seq=(\\d+)'
          - name: "log_id"
            pattern: 'logid="(\\d+)"'

Nothing is required to match. A pattern that finds nothing simply contributes
no key, and correlation falls back to order and time window exactly as before,
so an unhelpful pattern can never make matching worse than not having it.

The important limitation, stated plainly: FortiManager's CLI response to
``diagnose test application miglogd 9`` carries no identifier, so the CLI side
of a test event can never be linked by identity. Identity keys link the
*sniffer* and *Graylog* observations to each other; the CLI is still tied to
them by time window and order.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass(frozen=True)
class IdentityField:
    """One named identity key and the pattern that extracts it."""

    name: str
    pattern: "re.Pattern[str]"

    def extract(self, text: str) -> Optional[str]:
        match = self.pattern.search(text)
        if match is None:
            return None
        value = match.group(1) if match.groups() else match.group(0)
        value = value.strip()
        return value or None


class IdentityExtractor:
    """Pulls identity keys out of evidence text."""

    def __init__(self, fields, enabled: bool = True) -> None:
        # Accepts IdentityField objects or the (name, compiled pattern) tuples
        # the config parser produces.
        self._fields: List[IdentityField] = [
            item if isinstance(item, IdentityField) else IdentityField(item[0], item[1])
            for item in fields
        ]
        self.enabled = enabled and bool(self._fields)

    @property
    def field_names(self) -> List[str]:
        return [f.name for f in self._fields]

    def extract(self, *texts: str) -> Dict[str, str]:
        """Extract every configured key found in any of ``texts``.

        Several texts may be offered (for a packet: the decoded payload and the
        raw block) and the first one yielding a value for a given key wins.
        """
        if not self.enabled:
            return {}
        found: Dict[str, str] = {}
        for field in self._fields:
            for text in texts:
                if not text:
                    continue
                value = field.extract(text)
                if value is not None:
                    found[field.name] = value
                    break
        return found


def shared_keys(left: Dict[str, str], right: Dict[str, str]) -> List[str]:
    """Names present in both identity dicts."""
    return [name for name in left if name in right]


def compare(left: Dict[str, str], right: Dict[str, str]) -> Tuple[bool, List[str], List[str]]:
    """Compare two identity dicts.

    Returns ``(comparable, agreeing, conflicting)``:

    * ``comparable`` -- the two share at least one key, so a verdict is possible
    * ``agreeing``   -- names whose values are equal
    * ``conflicting``-- names whose values differ

    Absence of a shared key is not disagreement. It means identity cannot
    decide, and the caller should fall back to order and time.
    """
    common = shared_keys(left, right)
    if not common:
        return (False, [], [])
    agreeing = [name for name in common if left[name] == right[name]]
    conflicting = [name for name in common if left[name] != right[name]]
    return (True, agreeing, conflicting)


def matches(left: Dict[str, str], right: Dict[str, str]) -> bool:
    """True when the two identities share a key and no shared key conflicts."""
    comparable, agreeing, conflicting = compare(left, right)
    return comparable and bool(agreeing) and not conflicting


def describe(identity: Dict[str, str]) -> str:
    if not identity:
        return "<none>"
    return " ".join(f"{k}={v}" for k, v in sorted(identity.items()))


@dataclass(frozen=True)
class FlowConstraint:
    """Optional packet-flow filter for sniffer matches.

    A packet whose payload contains the expected message but which is going
    somewhere else is not the event under test. Constraining the flow stops
    unrelated traffic -- a neighbouring device relaying the same message, or a
    loopback copy -- from being claimed.
    """

    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    direction: str = ""

    @property
    def active(self) -> bool:
        return bool(
            self.src_ip or self.dst_ip or self.src_port or self.dst_port or self.direction
        )

    def check(self, fields: Dict[str, object]) -> Optional[str]:
        """Return None when the packet is acceptable, else why it is not.

        A field the sniffer could not parse is never treated as a mismatch:
        that would turn a parsing gap into a false negative about
        transmission.
        """
        checks = (
            ("src_ip", self.src_ip, fields.get("src_ip")),
            ("dst_ip", self.dst_ip, fields.get("dst_ip")),
            ("direction", self.direction, fields.get("direction")),
        )
        for name, expected, actual in checks:
            if not expected or actual is None:
                continue
            if str(actual).lower() != str(expected).lower():
                return f"{name} is {actual!r}, expected {expected!r}"

        for name, expected_port, actual_port in (
            ("src_port", self.src_port, fields.get("src_port")),
            ("dst_port", self.dst_port, fields.get("dst_port")),
        ):
            if not expected_port or actual_port is None:
                continue
            try:
                if int(actual_port) != int(expected_port):
                    return f"{name} is {actual_port}, expected {expected_port}"
            except (TypeError, ValueError):
                continue
        return None

    def describe(self) -> str:
        parts = []
        if self.direction:
            parts.append(f"direction={self.direction}")
        if self.src_ip:
            parts.append(f"src={self.src_ip}" + (f":{self.src_port}" if self.src_port else ""))
        if self.dst_ip:
            parts.append(f"dst={self.dst_ip}" + (f":{self.dst_port}" if self.dst_port else ""))
        elif self.dst_port:
            parts.append(f"dst_port={self.dst_port}")
        if self.src_port and not self.src_ip:
            parts.append(f"src_port={self.src_port}")
        return ", ".join(parts) if parts else "<none>"
