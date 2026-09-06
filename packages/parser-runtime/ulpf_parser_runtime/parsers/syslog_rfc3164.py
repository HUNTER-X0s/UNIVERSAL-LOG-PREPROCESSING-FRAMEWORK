"""Syslog RFC 3164 parser for ULPF Phase 3.

Parses BSD/RFC3164 syslog messages:
  <PRI>Mmm dd hh:mm:ss HOSTNAME TAG[PID]: MSG
  or without PRI:
  Mmm dd hh:mm:ss HOSTNAME TAG: MSG

Adheres to:
- Spec §19: Syslog (RFC3164)
- Spec §41: Resource Bounds (bounded regex, linear-time)
- Spec §45: Deterministic Parsing
"""

import re
import time
from datetime import UTC, datetime

from ulpf_parser_runtime.errors import ErrorCode, ErrorSeverity, ParseError
from ulpf_parser_runtime.framing import FramedRecord
from ulpf_parser_runtime.models import (
    Origin,
    ParseResult,
    ParserMetadata,
    ParseStatus,
)
from ulpf_parser_runtime.parsers.base import BaseParser

# Bounded RFC 3164 regex (no catastrophic backtracking)
_MONTHS = "Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec"
RE_3164_PRI = re.compile(
    r"^<(\d{1,3})>"
    r"(" + _MONTHS + r")\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})"
    r"\s+([^\s]{1,255})"
    r"\s+([^\s:\[]{1,64})"
    r"(?:\[(\d{1,10})\])?"
    r"(?::\s+(.*))?\s*$",
    re.DOTALL,
)
RE_3164_NO_PRI = re.compile(
    r"^(" + _MONTHS + r")\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})"
    r"\s+([^\s]{1,255})"
    r"\s+([^\s:\[]{1,64})"
    r"(?:\[(\d{1,10})\])?"
    r"(?::\s+(.*))?\s*$",
    re.DOTALL,
)

_SYSLOG_MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


class SyslogRFC3164Parser(BaseParser):
    """Deterministic RFC 3164 BSD syslog parser."""

    metadata = ParserMetadata(
        parser_id="parser.syslog.rfc3164",
        version="1.0.0",
        supported_formats=("syslog_rfc3164",),
        supported_vendors=(),
        supported_products=(),
        tier="A",
        description="Generic RFC 3164 BSD Syslog parser",
    )

    def parse(self, record: FramedRecord) -> ParseResult:
        t0 = time.perf_counter()
        text = record.text.rstrip("\r\n")

        match = RE_3164_PRI.match(text)
        has_pri = bool(match)

        if not match:
            match = RE_3164_NO_PRI.match(text)

        if not match:
            err = ParseError(
                code=ErrorCode.INVALID_SYSLOG,
                stage="syslog_rfc3164",
                message="Record does not match RFC 3164 grammar",
                severity=ErrorSeverity.WARNING,
                recoverable=True,
            )
            return ParseResult(
                status=ParseStatus.PARTIAL,
                parser_id=self.metadata.parser_id,
                parser_version=self.metadata.version,
                format="syslog_rfc3164",
                extracted_fields={},
                unmapped_fields={"raw_text": text},
                unparsed_fragments=(text,),
                errors=(err,),
                duration_ms=self.measure_duration(t0),
            )

        fields = {}

        if has_pri:
            pri_str, month, day, time_str, host, tag, pid, msg = match.groups()
            pri = int(pri_str)
            facility = pri >> 3
            severity_num = pri & 0x7
            fields["pri"] = self.make_field("pri", pri, Origin.OBSERVED, raw_locator="rfc3164:pri")
            fields["facility"] = self.make_field(
                "facility", facility, Origin.DERIVED, raw_locator="rfc3164:pri/facility"
            )
            fields["severity"] = self.make_field(
                "severity", severity_num, Origin.DERIVED, raw_locator="rfc3164:pri/severity"
            )
        else:
            month, day, time_str, host, tag, pid, msg = match.groups()

        # Attempt timestamp construction (use current year; RFC3164 has no year)
        try:
            month_num = _SYSLOG_MONTHS.get(month, 1)
            year = datetime.now(UTC).year
            day_num = int(day.strip())
            h, m, s = (int(x) for x in time_str.split(":"))
            ts = datetime(year, month_num, day_num, h, m, s, tzinfo=UTC)
            fields["timestamp"] = self.make_field(
                "timestamp",
                ts.isoformat(),
                Origin.DERIVED,
                raw_locator="rfc3164:timestamp",
                explanation="Year inferred from current year; RFC3164 has no year field",
            )
        except (ValueError, TypeError):
            fields["raw_timestamp"] = self.make_field(
                "raw_timestamp", f"{month} {day} {time_str}", Origin.OBSERVED
            )

        fields["hostname"] = self.make_field(
            "hostname", host, Origin.OBSERVED, raw_locator="rfc3164:hostname"
        )
        fields["app_name"] = self.make_field(
            "app_name", tag, Origin.OBSERVED, raw_locator="rfc3164:tag"
        )
        if pid:
            fields["process_id"] = self.make_field(
                "process_id", pid, Origin.OBSERVED, raw_locator="rfc3164:pid"
            )
        if msg is not None:
            fields["message"] = self.make_field(
                "message", msg.strip(), Origin.OBSERVED, raw_locator="rfc3164:msg"
            )

        return ParseResult(
            status=ParseStatus.PARSED,
            parser_id=self.metadata.parser_id,
            parser_version=self.metadata.version,
            format="syslog_rfc3164",
            extracted_fields=fields,
            duration_ms=self.measure_duration(t0),
        )
