"""Syslog RFC 5424 parser for ULPF Phase 3.

Parses IETF RFC 5424 syslog messages:
  <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD-ELEMENT ...] MSG

Adheres to:
- Spec §19: Syslog (RFC5424)
- Spec §41: Resource Bounds
- Spec §45: Deterministic Parsing
"""

import re
import time

from ulpf_parser_runtime.errors import ErrorCode, ErrorSeverity, ParseError
from ulpf_parser_runtime.framing import FramedRecord
from ulpf_parser_runtime.models import (
    Origin,
    ParseResult,
    ParserMetadata,
    ParseStatus,
)
from ulpf_parser_runtime.parsers.base import BaseParser

# Strict RFC 5424 header (bounded length fields per RFC spec)
RE_5424_HEADER = re.compile(
    r"^<(\d{1,3})>"  # PRI
    r"(\d+)\s+"  # VERSION
    r"([^\s]{1,48})\s+"  # TIMESTAMP or -
    r"([^\s]{1,255})\s+"  # HOSTNAME or -
    r"([^\s]{1,48})\s+"  # APP-NAME or -
    r"([^\s]{1,128})\s+"  # PROCID or -
    r"([^\s]{1,32})"  # MSGID or -
    r"([\s\S]*)$"  # SD + MSG
)
# Structured data param extraction (bounded key/value)
RE_SD_ELEMENT = re.compile(r"\[([^\]]{1,512})\]")
RE_SD_PARAM = re.compile(r'([A-Za-z0-9_\.\-]{1,32})="([^"]{0,4096})"')


class SyslogRFC5424Parser(BaseParser):
    """Deterministic RFC 5424 IETF syslog parser with structured data support."""

    metadata = ParserMetadata(
        parser_id="parser.syslog.rfc5424",
        version="1.0.0",
        supported_formats=("syslog_rfc5424",),
        supported_vendors=(),
        supported_products=(),
        tier="A",
        description="Generic RFC 5424 IETF Syslog parser",
    )

    def parse(self, record: FramedRecord) -> ParseResult:
        t0 = time.perf_counter()
        text = record.text.rstrip("\r\n")

        match = RE_5424_HEADER.match(text)
        if not match:
            err = ParseError(
                code=ErrorCode.INVALID_SYSLOG,
                stage="syslog_rfc5424",
                message="Record does not match RFC 5424 grammar",
                severity=ErrorSeverity.WARNING,
                recoverable=True,
            )
            return ParseResult(
                status=ParseStatus.PARTIAL,
                parser_id=self.metadata.parser_id,
                parser_version=self.metadata.version,
                format="syslog_rfc5424",
                extracted_fields={},
                unmapped_fields={"raw_text": text},
                unparsed_fragments=(text,),
                errors=(err,),
                duration_ms=self.measure_duration(t0),
            )

        pri_str, version, timestamp, hostname, app_name, procid, msgid, sd_and_msg = match.groups()

        pri = int(pri_str)
        facility = pri >> 3
        severity_num = pri & 0x7

        fields = {}
        fields["pri"] = self.make_field("pri", pri, Origin.OBSERVED, raw_locator="rfc5424:pri")
        fields["facility"] = self.make_field(
            "facility", facility, Origin.DERIVED, raw_locator="rfc5424:pri/facility"
        )
        fields["severity"] = self.make_field(
            "severity", severity_num, Origin.DERIVED, raw_locator="rfc5424:pri/severity"
        )
        fields["version"] = self.make_field(
            "version", int(version), Origin.OBSERVED, raw_locator="rfc5424:version"
        )

        if timestamp != "-":
            fields["timestamp"] = self.make_field(
                "timestamp", timestamp, Origin.OBSERVED, raw_locator="rfc5424:timestamp"
            )
        if hostname != "-":
            fields["hostname"] = self.make_field(
                "hostname", hostname, Origin.OBSERVED, raw_locator="rfc5424:hostname"
            )
        if app_name != "-":
            fields["app_name"] = self.make_field(
                "app_name", app_name, Origin.OBSERVED, raw_locator="rfc5424:app_name"
            )
        if procid != "-":
            fields["process_id"] = self.make_field(
                "process_id", procid, Origin.OBSERVED, raw_locator="rfc5424:procid"
            )
        if msgid != "-":
            fields["message_id"] = self.make_field(
                "message_id", msgid, Origin.OBSERVED, raw_locator="rfc5424:msgid"
            )

        # Parse structured data (up to 20 elements for safety)
        rest = sd_and_msg.strip()
        structured_data: dict[str, dict[str, str]] = {}

        if rest.startswith("["):
            sd_elements = RE_SD_ELEMENT.findall(rest[:32768])
            for elem in sd_elements[:20]:
                parts = elem.split(None, 1)
                sd_id = parts[0][:32]
                structured_data[sd_id] = {}
                if len(parts) > 1:
                    for param_m in RE_SD_PARAM.finditer(parts[1][:4096]):
                        structured_data[sd_id][param_m.group(1)] = param_m.group(2)
            if structured_data:
                fields["structured_data"] = self.make_field(
                    "structured_data",
                    structured_data,
                    Origin.OBSERVED,
                    raw_locator="rfc5424:structured_data",
                )
            # Message follows the last closing bracket
            last_bracket = rest.rfind("]")
            if last_bracket != -1:
                rest = rest[last_bracket + 1 :].lstrip()
        elif rest.startswith("- "):
            rest = rest[2:]
        elif rest == "-":
            rest = ""

        # Strip optional BOM from MSG
        if rest.startswith("\ufeff"):
            rest = rest[1:]

        if rest:
            fields["message"] = self.make_field(
                "message", rest.strip(), Origin.OBSERVED, raw_locator="rfc5424:msg"
            )

        return ParseResult(
            status=ParseStatus.PARSED,
            parser_id=self.metadata.parser_id,
            parser_version=self.metadata.version,
            format="syslog_rfc5424",
            extracted_fields=fields,
            duration_ms=self.measure_duration(t0),
        )
