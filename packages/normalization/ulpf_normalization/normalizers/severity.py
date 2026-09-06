"""Severity normalizer for ULPF Phase 3.

Maps vendor-specific and protocol-specific severities to a canonical 0-10 integer:
- Syslog RFC 5424/3164 (0 to 7) inverted to 0-10 scale
- ArcSight CEF (0-10 or text Low/Medium/High)
- Common vendor keywords (emergency, critical, error, warning, notice, info, debug)

Scale:
  10: Emergency / Fatal
   8-9: Critical / Alert
   6-7: Error / High
   4-5: Warning / Medium / Notice
   2-3: Low / Informational
   0-1: Debug / Trace / Unknown

Adheres to:
- Spec §29: Severity Normalization Strategy
- Spec §33: Universal Canonical Event (UCE) Schema
"""

from typing import Any

_TEXT_SEVERITY_MAP: dict[str, int] = {
    "emergency": 10,
    "emerg": 10,
    "fatal": 10,
    "catastrophic": 10,
    "alert": 9,
    "critical": 8,
    "crit": 8,
    "error": 7,
    "err": 7,
    "high": 8,
    "warning": 5,
    "warn": 5,
    "medium": 5,
    "med": 5,
    "notice": 4,
    "low": 3,
    "informational": 2,
    "information": 2,
    "info": 2,
    "debug": 1,
    "trace": 1,
    "verbose": 1,
    "unknown": 0,
}

_SYSLOG_TO_CANONICAL: dict[int, int] = {
    0: 10,  # Emergency
    1: 9,  # Alert
    2: 8,  # Critical
    3: 7,  # Error
    4: 5,  # Warning
    5: 4,  # Notice
    6: 2,  # Informational
    7: 1,  # Debug
}


def normalize_severity(raw_val: Any, is_syslog: bool = False) -> int:
    """Map raw severity indicator to canonical 0-10 integer score."""
    if raw_val is None:
        return 0

    # Numeric input
    if isinstance(raw_val, int | float):

        num = int(raw_val)
        if is_syslog and num in _SYSLOG_TO_CANONICAL:
            return _SYSLOG_TO_CANONICAL[num]
        return min(10, max(0, num))

    val_str = str(raw_val).strip().lower()
    if not val_str:
        return 0

    # If it's a numeric string
    if val_str.isdigit():
        num = int(val_str)
        if is_syslog and num in _SYSLOG_TO_CANONICAL:
            return _SYSLOG_TO_CANONICAL[num]
        return min(10, max(0, num))

    # Keyword lookup
    if val_str in _TEXT_SEVERITY_MAP:
        return _TEXT_SEVERITY_MAP[val_str]

    # Partial substring matching
    for key, score in _TEXT_SEVERITY_MAP.items():
        if key in val_str:
            return score

    return 0
