"""IBM Log Event Extended Format (LEEF) parser for ULPF Phase 3.

Supports:
- LEEF 1.0: LEEF:1.0|Vendor|Product|Version|EventID|Extension
- LEEF 2.0: LEEF:2.0|Vendor|Product|Version|EventID|Delimiter|Extension
- Configurable delimiter (tab, custom character, hex escape)
- Syslog header handling (syslog prefix before LEEF:)
- Raw locator tracking per field

Adheres to:
- Spec §21: Log Event Extended Format (LEEF) Strategy
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

RE_LEEF_START = re.compile(r"(?:^|\s)LEEF:([0-9.]+)\|")


def _split_leef_header(text: str) -> tuple[list[str], str]:
    """Split LEEF pipe-delimited header fields up to extension."""
    parts = text.split("|")
    if len(parts) < 5:
        return parts, ""

    version = parts[0]
    if version.startswith("2."):
        # LEEF 2.0: Version|Vendor|Product|Version|EventID|Delimiter|Extension
        if len(parts) >= 7:
            headers = parts[:6]
            extension = "|".join(parts[6:])
            return headers, extension
        return parts[: len(parts) - 1], parts[-1]
    else:
        # LEEF 1.0: Version|Vendor|Product|Version|EventID|Extension
        headers = parts[:5]
        extension = "|".join(parts[5:])
        return headers, extension


def _parse_leef_extension(ext_str: str, delimiter: str = "\t") -> dict[str, str]:
    """Parse LEEF extension using the specified delimiter between key=value pairs."""
    ext_str = ext_str.strip()
    if not ext_str:
        return {}

    pairs: dict[str, str] = {}
    tokens = ext_str.split(delimiter)

    for tok in tokens:
        tok = tok.strip()
        if not tok or "=" not in tok:
            continue
        k, v = tok.split("=", 1)
        pairs[k.strip()] = v.strip()

    return pairs


class LeefParser(BaseParser):
    """IBM LEEF (Log Event Extended Format) generic parser supporting 1.0 and 2.0."""

    metadata = ParserMetadata(
        parser_id="parser.generic.leef",
        version="1.0.0",
        supported_formats=("leef",),
        supported_vendors=(),
        supported_products=(),
        tier="A",
        description="IBM Log Event Extended Format (LEEF) parser for v1.0 and v2.0",
    )

    def parse(self, record: FramedRecord) -> ParseResult:
        t0 = time.perf_counter()
        text = record.text.strip()

        start_match = RE_LEEF_START.search(text)
        if not start_match:
            err = ParseError(
                code=ErrorCode.UNKNOWN_FORMAT,
                stage="leef_parser",
                message="No 'LEEF:Version|' header found in record",
                severity=ErrorSeverity.ERROR,
                recoverable=False,
            )
            return ParseResult(
                status=ParseStatus.FAILED,
                parser_id=self.metadata.parser_id,
                parser_version=self.metadata.version,
                format="leef",
                extracted_fields={},
                unmapped_fields={"raw_text": text},
                unparsed_fragments=(text,),
                errors=(err,),
                duration_ms=self.measure_duration(t0),
            )

        prefix_end = start_match.start()
        syslog_prefix = text[:prefix_end].strip()
        leef_payload = text[start_match.start() :].lstrip()

        # Strip "LEEF:"
        leef_body = leef_payload[5:]
        header_parts, extension_raw = _split_leef_header(leef_body)

        if len(header_parts) < 5:
            err = ParseError(
                code=ErrorCode.MALFORMED_RECORD,
                stage="leef_parser",
                message=f"LEEF header has only {len(header_parts)} fields (expected at least 5)",
                severity=ErrorSeverity.ERROR,
                recoverable=True,
            )
            return ParseResult(
                status=ParseStatus.PARTIAL,
                parser_id=self.metadata.parser_id,
                parser_version=self.metadata.version,
                format="leef",
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
                raw_locator="leef:syslog_prefix",
            )

        version = header_parts[0]
        fields["leef_version"] = self.make_field(
            "leef_version", version, Origin.OBSERVED, raw_locator="leef:header:0"
        )
        fields["vendor"] = self.make_field(
            "vendor", header_parts[1], Origin.OBSERVED, raw_locator="leef:header:1"
        )
        fields["product"] = self.make_field(
            "product", header_parts[2], Origin.OBSERVED, raw_locator="leef:header:2"
        )
        fields["version"] = self.make_field(
            "version", header_parts[3], Origin.OBSERVED, raw_locator="leef:header:3"
        )
        fields["event_id"] = self.make_field(
            "event_id", header_parts[4], Origin.OBSERVED, raw_locator="leef:header:4"
        )

        delimiter = "\t"
        if version.startswith("2.") and len(header_parts) >= 6:
            delim_field = header_parts[5]
            if delim_field.startswith("x") or delim_field.startswith("0x"):
                try:
                    delimiter = chr(int(delim_field.replace("0x", "").replace("x", ""), 16))
                except ValueError:
                    delimiter = "\t"
            elif delim_field:
                delimiter = delim_field

        ext_pairs = _parse_leef_extension(extension_raw, delimiter=delimiter)
        for k, v in ext_pairs.items():
            fields[k] = self.make_field(k, v, Origin.OBSERVED, raw_locator=f"leef:ext:{k}")

        return ParseResult(
            status=ParseStatus.PARSED,
            parser_id=self.metadata.parser_id,
            parser_version=self.metadata.version,
            format="leef",
            extracted_fields=fields,
            unmapped_fields={"raw_extension": extension_raw}
            if not ext_pairs and extension_raw
            else {},
            duration_ms=self.measure_duration(t0),
        )
