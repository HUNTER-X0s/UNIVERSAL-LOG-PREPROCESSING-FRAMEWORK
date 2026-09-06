"""Network telemetry normalizer for ULPF Phase 3.

Validates and normalizes:
- IP addresses (IPv4 / IPv6 validation and canonical formatting)
- Port numbers (validates 1-65535 integer range)
- Protocol names (maps IANA protocol numbers to canonical uppercase names)
- Traffic direction (inbound, outbound, internal, unknown)
- Metrics (bytes, packets, duration)

Adheres to:
- Spec §30: Network Field Normalization Strategy
- Spec §33: Universal Canonical Event (UCE) Schema
"""

import ipaddress
from typing import Any

# IANA protocol numbers
_PROTO_MAP: dict[str, str] = {
    "1": "ICMP",
    "2": "IGMP",
    "6": "TCP",
    "17": "UDP",
    "41": "IPV6",
    "47": "GRE",
    "50": "ESP",
    "51": "AH",
    "58": "ICMPV6",
    "89": "OSPF",
}


def normalize_ip(raw_val: Any) -> str | None:
    """Validate and return canonical IPv4 or IPv6 string, or None if invalid."""
    if not raw_val:
        return None
    val_str = str(raw_val).strip()
    try:
        addr = ipaddress.ip_address(val_str)
        return str(addr)
    except ValueError:
        return None


def normalize_port(raw_val: Any) -> int | None:
    """Validate port number in range 1-65535, or None if invalid."""
    if raw_val is None:
        return None
    try:
        p = int(raw_val)
        if 0 <= p <= 65535:
            return p
    except (ValueError, TypeError):
        pass
    return None


def normalize_protocol(raw_val: Any) -> str:
    """Normalize protocol name or number to canonical uppercase string."""
    if raw_val is None:
        return "UNKNOWN"
    val_str = str(raw_val).strip()
    if val_str in _PROTO_MAP:
        return _PROTO_MAP[val_str]
    return val_str.upper() if val_str else "UNKNOWN"


def normalize_direction(raw_val: Any) -> str:
    """Normalize flow direction to canonical taxonomy."""
    if not raw_val:
        return "unknown"
    val_str = str(raw_val).strip().lower()
    if val_str in ("in", "inbound", "incoming", "ingress"):
        return "inbound"
    if val_str in ("out", "outbound", "outgoing", "egress"):
        return "outbound"
    if val_str in ("internal", "intra", "lateral"):
        return "internal"
    return "unknown"


def normalize_metric(raw_val: Any) -> int:
    """Normalize byte or packet count to non-negative integer."""
    if raw_val is None:
        return 0
    try:
        num = int(raw_val)
        return max(0, num)
    except (ValueError, TypeError):
        return 0
