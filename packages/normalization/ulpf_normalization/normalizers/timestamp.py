"""Multi-format timestamp normalizer for ULPF Phase 3.

Normalizes diverse source timestamp formats into canonical UTC ISO-8601 strings:
- ISO-8601 / RFC 3339 (with Z, +HH:MM, +HHMM offsets)
- RFC 3164 BSD Syslog (Mmm dd hh:mm:ss)
- Combined Log Format (dd/Mmm/yyyy:hh:mm:ss +offset)
- FortiOS / PAN-OS date & time (yyyy-mm-dd hh:mm:ss or yyyy/mm/dd hh:mm:ss)
- Unix epoch (seconds, milliseconds, microseconds, nanoseconds)

Adheres to:
- Spec §28: Timestamp Normalization Strategy
- Spec §33: Universal Canonical Event (UCE) Schema
- Spec §41: Resource Bounds
"""

import re
from datetime import UTC, datetime
from typing import Any

# Regex for common formats
RE_EPOCH_SEC = re.compile(r"^\d{10}(?:\.\d+)?$")
RE_EPOCH_MS = re.compile(r"^\d{13}$")
RE_EPOCH_US = re.compile(r"^\d{16}$")
RE_EPOCH_NS = re.compile(r"^\d{19}$")

_MONTH_MAP = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}


def normalize_timestamp(
    raw_val: Any,
    date_val: str | None = None,
    time_val: str | None = None,
    reference_year: int | None = None,
) -> str:
    """Normalize a raw timestamp or (date, time) pair to UTC ISO-8601 string.

    Returns RFC3339 string formatted as 'YYYY-MM-DDTHH:MM:SS[.ffffff]+00:00' or '...Z'.
    """
    if reference_year is None:
        reference_year = datetime.now(UTC).year

    # 1. Check for separate date & time fields
    if date_val and time_val:
        combined = f"{date_val.strip()} {time_val.strip()}"
        return _parse_datetime_string(combined, reference_year)

    if raw_val is None:
        return datetime.now(UTC).isoformat()

    # 2. Integer or Float Epoch
    if isinstance(raw_val, int | float):
        val = float(raw_val)
        if val > 1e17:  # nanoseconds
            val /= 1e9
        elif val > 1e14:  # microseconds
            val /= 1e6
        elif val > 1e11:  # milliseconds
            val /= 1e3
        return _epoch_to_iso(val)

    raw_str = str(raw_val).strip()
    if not raw_str:
        return datetime.now(UTC).isoformat()

    # 3. Numeric string epoch
    if RE_EPOCH_SEC.match(raw_str):
        return _epoch_to_iso(float(raw_str))
    if RE_EPOCH_MS.match(raw_str):
        return _epoch_to_iso(float(raw_str) / 1000.0)
    if RE_EPOCH_US.match(raw_str):
        return _epoch_to_iso(float(raw_str) / 1_000_000.0)
    if RE_EPOCH_NS.match(raw_str):
        return _epoch_to_iso(float(raw_str) / 1_000_000_000.0)

    # 4. String datetime parsing
    return _parse_datetime_string(raw_str, reference_year)


def _epoch_to_iso(epoch_seconds: float) -> str:
    """Convert float epoch seconds to UTC ISO-8601 string."""
    try:
        dt = datetime.fromtimestamp(epoch_seconds, tz=UTC)
        return dt.isoformat()
    except (OSError, OverflowError, ValueError):
        return datetime.now(UTC).isoformat()


def _parse_datetime_string(s: str, reference_year: int) -> str:
    """Parse various datetime string formats into UTC ISO-8601."""
    # Attempt Python 3.11+ fromisoformat first (handles standard ISO-8601 with T or space)
    # Clean up +0000 format to +00:00 if needed for fromisoformat
    cleaned = s
    if re.search(r"[+-]\d{4}$", cleaned):
        cleaned = cleaned[:-2] + ":" + cleaned[-2:]

    try:
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        else:
            dt = dt.astimezone(UTC)
        return dt.isoformat()
    except ValueError:
        pass

    # Try Apache / CLF: 10/Oct/2026:13:55:36 +0000
    try:
        dt = datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z")
        return dt.astimezone(UTC).isoformat()
    except ValueError:
        pass

    # Try PAN-OS format: 2026/09/05 14:00:01
    try:
        dt = datetime.strptime(s, "%Y/%m/%d %H:%M:%S")
        dt = dt.replace(tzinfo=UTC)
        return dt.isoformat()
    except ValueError:
        pass

    # Try Syslog RFC 3164: Sep  5 14:00:00 or Oct 11 22:14:15
    tokens = s.split()
    if len(tokens) >= 3 and tokens[0].lower()[:3] in _MONTH_MAP:
        try:
            month = _MONTH_MAP[tokens[0].lower()[:3]]
            day = int(tokens[1])
            h, m, sec = (int(x) for x in tokens[2].split(":"))
            dt = datetime(reference_year, month, day, h, m, sec, tzinfo=UTC)
            return dt.isoformat()
        except (ValueError, TypeError):
            pass

    # Try standard SQL: 2026-09-05 14:00:00
    try:
        dt = datetime.strptime(s[:19], "%Y-%m-%d %H:%M:%S")
        dt = dt.replace(tzinfo=UTC)
        return dt.isoformat()
    except ValueError:
        pass

    # Fallback to current time if unparseable
    return datetime.now(UTC).isoformat()
