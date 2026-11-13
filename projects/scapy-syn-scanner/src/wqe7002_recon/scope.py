"""Load and strictly validate the lecturer-issued scope manifest.

The manifest decides everything the tool is allowed to probe.  Anything
that is not a completed, well-formed, bounded manifest is rejected before a
single packet can be constructed.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import (
    HARD_MAX_ATTEMPTS,
    HARD_MAX_PORTS,
    HARD_MAX_RATE_PPS,
    HARD_MAX_TIMEOUT_S,
    SUPPORTED_OPTION,
)

SCOPE_SCHEMA = "wqe7002-recon-scope-v1"
REQUIRED_FIELDS = (
    "schema",
    "scope_id",
    "option",
    "environment",
    "interface",
    "target",
    "ports",
    "maximum_rate_pps",
    "maximum_attempts",
    "timeout_seconds",
)

_PLACEHOLDER_RE = re.compile(
    r"(?i)"
    r"replace|placeholder|change[_ -]?me|todo|your[_ -]?(target|host|port)|"
    r"<[^>]+>|\$\{[^}]+\}|"
    r"(?:^|[._-])x{2,}(?:[._-]|$)"  # x.x.x.x style placeholders
)

_IFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,14}$")

# ICMP type 3 codes whose unreachable messages can carry a quoted original
# segment that this scanner is able to verify.
RELEVANT_UNREACHABLE_CODES = frozenset({0, 1, 2, 3, 4, 5, 9, 10, 13})


# Address blocks that can never name a real lab host: documentation ranges
# and IANA special-purpose blocks that Python's is_reserved does not cover.
_REJECTED_NETWORKS = tuple(
    ipaddress.ip_network(net)
    for net in (
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "240.0.0.0/4",
    )
)


class ScopeError(ValueError):
    """Raised when a scope manifest is malformed, incomplete or out of bounds."""


@dataclass(frozen=True)
class Scope:
    """A validated, completed scope manifest."""

    scope_id: str
    environment: str
    interface: str
    target: str
    ports: tuple[int, ...]
    maximum_rate_pps: int
    maximum_attempts: int
    timeout_seconds: float

    @property
    def target_ip(self) -> ipaddress.IPv4Address:
        return ipaddress.IPv4Address(self.target)


def _check_no_placeholder(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ScopeError(f"{field}: empty or non-string value")
    if _PLACEHOLDER_RE.search(value):
        raise ScopeError(
            f"{field}: looks like an unfilled placeholder: {value!r}"
        )


def load_scope(path: str | Path) -> Scope:
    """Read and validate a scope manifest from disk.

    Raises ScopeError with a useful message on any invalid input.
    """
    raw_path = Path(path)
    try:
        text = raw_path.read_text(encoding="utf-8")
    except OSError as error:
        raise ScopeError(f"cannot read scope file {raw_path}: {error}") from error

    try:
        document: Any = json.loads(text)
    except json.JSONDecodeError as error:
        raise ScopeError(
            f"scope file is not valid JSON: {error} (line {error.lineno}, "
            f"column {error.colno})"
        ) from error

    if not isinstance(document, dict):
        raise ScopeError("scope document must be a JSON object")

    for field in REQUIRED_FIELDS:
        if field not in document:
            raise ScopeError(f"scope is missing required field {field!r}")

    # --- text fields -----------------------------------------------------
    if document["schema"] != SCOPE_SCHEMA:
        raise ScopeError(
            f"unsupported scope schema {document['schema']!r}; "
            f"expected {SCOPE_SCHEMA!r}"
        )
    if document["option"] != SUPPORTED_OPTION:
        raise ScopeError(
            f"scope option is {document['option']!r}; this tool implements "
            f"only {SUPPORTED_OPTION!r}. Use the matching scope manifest."
        )
    if document["environment"] != "isolated-course-lab":
        raise ScopeError(
            f"scope environment {document['environment']!r} is not the "
            "authorised isolated course lab"
        )

    scope_id = document["scope_id"]
    _check_no_placeholder(scope_id, "scope_id")

    iface = document["interface"]
    _check_no_placeholder(iface, "interface")
    if not _IFACE_RE.match(iface):
        raise ScopeError(f"interface: invalid interface name {iface!r}")

    target = document["target"]
    _check_no_placeholder(target, "target")
    try:
        target_ip = ipaddress.IPv4Address(target)
    except ValueError as error:
        raise ScopeError(f"target: {target!r} is not an IPv4 address") from error
    if target_ip.is_unspecified or target_ip.is_loopback:
        raise ScopeError(
            f"target: {target!r} is an unspecified or loopback address; "
            "the authorised target must be a real lab host"
        )
    if target_ip.is_multicast or target_ip.is_reserved:
        raise ScopeError(f"target: {target!r} is multicast or reserved")
    if any(target_ip in net for net in _REJECTED_NETWORKS):
        raise ScopeError(
            f"target: {target!r} is a documentation or special-purpose "
            "address, not an authorised lab host"
        )

    # --- ports ------------------------------------------------------------
    ports = document["ports"]
    if not isinstance(ports, list) or not ports:
        raise ScopeError("ports: must be a non-empty list of integers")
    if len(ports) > HARD_MAX_PORTS:
        raise ScopeError(
            f"ports: {len(ports)} ports declared; the brief allows at most "
            f"{HARD_MAX_PORTS}"
        )
    checked_ports: list[int] = []
    for item in ports:
        if isinstance(item, bool) or not isinstance(item, int):
            raise ScopeError(f"ports: {item!r} is not an integer")
        if not 1 <= item <= 65535:
            raise ScopeError(f"ports: {item!r} is outside 1-65535")
        if item in checked_ports:
            raise ScopeError(f"ports: duplicate port {item}")
        checked_ports.append(item)
    ports_tuple = tuple(sorted(checked_ports))

    # --- bounds -----------------------------------------------------------
    rate = document["maximum_rate_pps"]
    if isinstance(rate, bool) or not isinstance(rate, int):
        raise ScopeError("maximum_rate_pps: must be an integer")
    if not 1 <= rate <= HARD_MAX_RATE_PPS:
        raise ScopeError(
            f"maximum_rate_pps: {rate} is outside 1-{HARD_MAX_RATE_PPS}; "
            "the brief caps the probe rate at 20 pps"
        )

    attempts = document["maximum_attempts"]
    if isinstance(attempts, bool) or not isinstance(attempts, int):
        raise ScopeError("maximum_attempts: must be an integer")
    if not 1 <= attempts <= HARD_MAX_ATTEMPTS:
        raise ScopeError(
            f"maximum_attempts: {attempts} is outside 1-{HARD_MAX_ATTEMPTS}"
        )

    timeout = document["timeout_seconds"]
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ScopeError("timeout_seconds: must be a number")
    timeout = float(timeout)
    if not 0.0 < timeout <= HARD_MAX_TIMEOUT_S:
        raise ScopeError(
            f"timeout_seconds: {timeout} is outside (0, {HARD_MAX_TIMEOUT_S}]"
        )

    return Scope(
        scope_id=scope_id,
        environment=document["environment"],
        interface=iface,
        target=target,
        ports=ports_tuple,
        maximum_rate_pps=rate,
        maximum_attempts=attempts,
        timeout_seconds=timeout,
    )
