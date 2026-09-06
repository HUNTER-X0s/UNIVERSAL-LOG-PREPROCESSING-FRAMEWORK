"""W3C Extended Log File Format parser for ULPF Phase 3.

Format specification:
- Comment directives start with '#' (e.g., #Fields:, #Software:, #Version:, #Date:)
- '#Fields:' defines column headers (e.g., '#Fields: date time s-ip cs-method cs-uri-stem ...')
- Data rows are space/tab separated values corresponding to the active #Fields definition
- Hyphen '-' denotes null/unset values

Adheres to:
- Spec §24: Web Server Log Strategy (W3C Extended Log Format)
- Spec §41: Resource Bounds
- Spec §45: Deterministic Parsing
"""

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

# Common default IIS W3C field layout if no #Fields directive is present in single-line mode
DEFAULT_IIS_FIELDS = (
    "date",
    "time",
    "s_ip",
    "cs_method",
    "cs_uri_stem",
    "cs_uri_query",
    "s_port",
    "cs_username",
    "c_ip",
    "cs_user_agent",
    "cs_referer",
    "sc_status",
    "sc_substatus",
    "sc_win32_status",
    "time_taken",
)


def _sanitize_w3c_field_name(name: str) -> str:
    """Normalize W3C header names (e.g. 'c-ip' -> 'c_ip', 'cs(User-Agent)' -> 'cs_user_agent')."""
    cleaned = name.replace("-", "_").replace("(", "_").replace(")", "").strip("_").lower()
    return cleaned[:64]


class W3CParser(BaseParser):
    """Deterministic W3C Extended Log Format parser."""

    metadata = ParserMetadata(
        parser_id="parser.generic.w3c",
        version="1.0.0",
        supported_formats=("w3c",),
        supported_vendors=(),
        supported_products=(),
        tier="A",
        description="W3C Extended Log File Format parser with #Fields directive parsing",
    )

    def __init__(self, default_fields: tuple[str, ...] | None = None) -> None:
        self.default_fields = default_fields or DEFAULT_IIS_FIELDS
        self._current_fields: list[str] = list(self.default_fields)

    def parse(self, record: FramedRecord) -> ParseResult:
        t0 = time.perf_counter()
        text = record.text.strip()

        # Check for directive comments
        if text.startswith("#"):
            if text.lower().startswith("#fields:"):
                raw_fields = text[8:].strip().split()
                self._current_fields = [_sanitize_w3c_field_name(f) for f in raw_fields]
                return ParseResult(
                    status=ParseStatus.PARSED,
                    parser_id=self.metadata.parser_id,
                    parser_version=self.metadata.version,
                    format="w3c",
                    extracted_fields={
                        "directive": self.make_field("directive", "Fields", Origin.OBSERVED),
                        "columns": self.make_field(
                            "columns", self._current_fields, Origin.OBSERVED
                        ),
                    },
                    duration_ms=self.measure_duration(t0),
                )
            else:
                # Other comment/metadata directive
                parts = text[1:].split(":", 1)
                d_name = parts[0].strip()
                d_val = parts[1].strip() if len(parts) > 1 else ""
                return ParseResult(
                    status=ParseStatus.PARSED,
                    parser_id=self.metadata.parser_id,
                    parser_version=self.metadata.version,
                    format="w3c",
                    extracted_fields={
                        "directive": self.make_field("directive", d_name, Origin.OBSERVED),
                        "value": self.make_field("value", d_val, Origin.OBSERVED),
                    },
                    duration_ms=self.measure_duration(t0),
                )

        # Data row: split by whitespace
        values = text.split()
        if not values:
            err = ParseError(
                code=ErrorCode.MALFORMED_RECORD,
                stage="w3c_parser",
                message="Empty record",
                severity=ErrorSeverity.WARNING,
                recoverable=True,
            )
            return ParseResult(
                status=ParseStatus.PARTIAL,
                parser_id=self.metadata.parser_id,
                parser_version=self.metadata.version,
                format="w3c",
                extracted_fields={},
                unmapped_fields={"raw_text": text},
                errors=(err,),
                duration_ms=self.measure_duration(t0),
            )

        fields: dict[str, Any] = {}
        headers = self._current_fields

        for idx, val in enumerate(values):
            if idx < len(headers):
                fname = headers[idx]
            else:
                fname = f"col_{idx}"

            # In W3C, "-" denotes null/missing
            if val != "-":
                fields[fname] = self.make_field(
                    fname,
                    val,
                    Origin.OBSERVED,
                    raw_locator=f"w3c:{fname}",
                )

        return ParseResult(
            status=ParseStatus.PARSED,
            parser_id=self.metadata.parser_id,
            parser_version=self.metadata.version,
            format="w3c",
            extracted_fields=fields,
            duration_ms=self.measure_duration(t0),
        )
