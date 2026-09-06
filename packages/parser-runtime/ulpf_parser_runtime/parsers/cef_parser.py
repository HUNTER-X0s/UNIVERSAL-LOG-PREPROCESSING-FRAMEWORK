r"""ArcSight Common Event Format (CEF) parser for ULPF Phase 3.

Format standard:
  CEF:Version|Device Vendor|Device Product|Device Version|
  Device Event Class ID|Name|Severity|Extension


Handles:
- Pipe delimiter with escape sequence `\|` and `\\`
- Extension key=value pairs with space delimiter and quote/escape handling
- Multi-word values in extension
- Prefix handling (Syslog wrapper before CEF header)
- Raw locator tracking per field

Adheres to:
- Spec §20: Common Event Format (CEF) Strategy
- Spec §41: Resource Bounds
- Spec §45: Deterministic Parsing
"""

import re
import time
from typing import Any

from ulpf_parser_runtime.errors import ErrorCode, ErrorSeverity, ParseError
from ulpf_parser_runtime.framing import FramedRecord
from ulpf_parser_runtime.models import (
    Origin,
    ParseResult,
    ParserMetadata,
    ParseStatus,
)
from ulpf_parser_runtime.parsers.base import BaseParser

# Regex to find CEF: header, allowing optional syslog prefix
RE_CEF_START = re.compile(r"(?:^|\s)CEF:(\d+)\|")
# Extension key=value parser: key starts with letter, value extends until next key= or end
RE_CEF_EXT = re.compile(r"([A-Za-z0-9_.\-]+)=")


def _split_cef_header(text: str, max_fields: int = 8) -> tuple[list[str], str]:
    """Split CEF text on unescaped pipes into up to 7 header fields + extension string."""
    fields: list[str] = []
    curr: list[str] = []
    i = 0
    length = len(text)

    while i < length and len(fields) < max_fields - 1:
        char = text[i]
        if char == "\\" and i + 1 < length:
            next_c = text[i + 1]
            if next_c in ("|", "\\", "="):
                curr.append(next_c)
                i += 2
                continue
            curr.append(char)
            i += 1
            continue
        elif char == "|":
            fields.append("".join(curr))
            curr = []
            i += 1
            continue
        curr.append(char)
        i += 1

    # Remaining text is the 8th field (Extension)
    remainder = "".join(curr) + text[i:]
    return fields, remainder


def _parse_cef_extension(ext_str: str) -> dict[str, str]:
    """Parse CEF extension key=value pairs handling spaces in values."""
    ext_str = ext_str.strip()
    if not ext_str:
        return {}

    pairs: dict[str, str] = {}
    matches = list(RE_CEF_EXT.finditer(ext_str))
    if not matches:
        return {}

    for i in range(len(matches)):
        key = matches[i].group(1)
        val_start = matches[i].end()
        val_end = matches[i + 1].start() if i + 1 < len(matches) else len(ext_str)

        val = ext_str[val_start:val_end].strip()
        # Unescape CEF escaped sequences (\=, \|, \\, \n, \r)
        val = (
            val.replace(r"\=", "=")
            .replace(r"\|", "|")
            .replace(r"\\", "\\")
            .replace(r"\n", "\n")
            .replace(r"\r", "\r")
        )
        pairs[key] = val

    return pairs


class CefParser(BaseParser):
    """ArcSight CEF (Common Event Format) parser with header & extension extraction."""

    metadata = ParserMetadata(
        parser_id="parser.generic.cef",
        version="1.0.0",
        supported_formats=("cef",),
        supported_vendors=(),
        supported_products=(),
        tier="A",
        description="ArcSight Common Event Format (CEF) generic parser",
    )

    def parse(self, record: FramedRecord) -> ParseResult:
        t0 = time.perf_counter()
        text = record.text.strip()

        start_match = RE_CEF_START.search(text)
        if not start_match:
            err = ParseError(
                code=ErrorCode.UNKNOWN_FORMAT,
                stage="cef_parser",
                message="No 'CEF:Version|' header found in record",
                severity=ErrorSeverity.ERROR,
                recoverable=False,
            )
            return ParseResult(
                status=ParseStatus.FAILED,
                parser_id=self.metadata.parser_id,
                parser_version=self.metadata.version,
                format="cef",
                extracted_fields={},
                unmapped_fields={"raw_text": text},
                unparsed_fragments=(text,),
                errors=(err,),
                duration_ms=self.measure_duration(t0),
            )

        # Handle optional syslog prefix before CEF:
        prefix_end = start_match.start()
        syslog_prefix = text[:prefix_end].strip()
        cef_payload = text[start_match.start() :].lstrip()

        # Split CEF header: Version|Vendor|Product|Version|EventClassId|Name|Severity|Extension
        # Strip "CEF:" prefix

        cef_body = cef_payload[4:]  # skip "CEF:"
        header_parts, extension_raw = _split_cef_header(cef_body, max_fields=8)

        if len(header_parts) < 7:
            err = ParseError(
                code=ErrorCode.MALFORMED_RECORD,
                stage="cef_parser",
                message=f"CEF header has only {len(header_parts)} fields (expected 7)",
                severity=ErrorSeverity.ERROR,
                recoverable=True,
            )
            return ParseResult(
                status=ParseStatus.PARTIAL,
                parser_id=self.metadata.parser_id,
                parser_version=self.metadata.version,
                format="cef",
                extracted_fields={},
                unmapped_fields={"raw_text": text},
                unparsed_fragments=(text,),
                errors=(err,),
                duration_ms=self.measure_duration(t0),
            )

        fields: dict[str, Any] = {}
        if syslog_prefix:
            fields["syslog_prefix"] = self.make_field(
                "syslog_prefix",
                syslog_prefix,
                Origin.OBSERVED,
                raw_locator="cef:syslog_prefix",
            )

        # Standard CEF header fields
        fields["cef_version"] = self.make_field(
            "cef_version", header_parts[0], Origin.OBSERVED, raw_locator="cef:header:0"
        )
        fields["device_vendor"] = self.make_field(
            "device_vendor", header_parts[1], Origin.OBSERVED, raw_locator="cef:header:1"
        )
        fields["device_product"] = self.make_field(
            "device_product", header_parts[2], Origin.OBSERVED, raw_locator="cef:header:2"
        )
        fields["device_version"] = self.make_field(
            "device_version", header_parts[3], Origin.OBSERVED, raw_locator="cef:header:3"
        )
        fields["device_event_class_id"] = self.make_field(
            "device_event_class_id", header_parts[4], Origin.OBSERVED, raw_locator="cef:header:4"
        )
        fields["name"] = self.make_field(
            "name", header_parts[5], Origin.OBSERVED, raw_locator="cef:header:5"
        )
        fields["severity"] = self.make_field(
            "severity", header_parts[6], Origin.OBSERVED, raw_locator="cef:header:6"
        )

        # Parse extension key-value pairs
        ext_pairs = _parse_cef_extension(extension_raw)
        for k, v in ext_pairs.items():
            fields[k] = self.make_field(k, v, Origin.OBSERVED, raw_locator=f"cef:ext:{k}")

        return ParseResult(
            status=ParseStatus.PARSED,
            parser_id=self.metadata.parser_id,
            parser_version=self.metadata.version,
            format="cef",
            extracted_fields=fields,
            unmapped_fields={"raw_extension": extension_raw}
            if not ext_pairs and extension_raw
            else {},
            duration_ms=self.measure_duration(t0),
        )
