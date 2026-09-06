"""Generic CSV parser for ULPF Phase 3.

Safe CSV parsing with:
- Configurable delimiter auto-detection (comma, tab, pipe, semicolon)
- Row count and column count limits
- Header-based field naming with sanitized keys
- Positional fallback when no header is present
- Full provenance via raw_locator (csv:col_N or csv:<header>)

Adheres to:
- Spec §17: Structured CSV Strategy
- Spec §41: Resource Bounds
- Spec §45: Deterministic Parsing
"""

import csv
import io
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

_MAX_COLUMNS = 512
_MAX_ROWS = 50000
_SAFE_KEY_RE = re.compile(r"[^a-zA-Z0-9_]")

_DELIMITERS = [",", "\t", "|", ";"]


def _sanitize_key(raw: str, index: int) -> str:
    """Convert a header cell to a safe identifier, falling back to col_N."""
    cleaned = _SAFE_KEY_RE.sub("_", raw.strip()).strip("_").lower()
    if not cleaned:
        return f"col_{index}"
    return cleaned[:64]


def _sniff_delimiter(sample: str) -> str:
    """Attempt to detect delimiter from a sample line; default to comma."""
    try:
        dialect = csv.Sniffer().sniff(sample[:4096], delimiters="".join(_DELIMITERS))
        return dialect.delimiter
    except csv.Error:
        return ","


class GenericCsvParser(BaseParser):
    """Row-bounded generic CSV parser with header and delimiter auto-detection."""

    metadata = ParserMetadata(
        parser_id="parser.generic.csv",
        version="1.0.0",
        supported_formats=("csv",),
        supported_vendors=(),
        supported_products=(),
        tier="A",
        description="Generic CSV parser with delimiter sniffing and bounded parsing",
    )

    def __init__(
        self,
        delimiter: str | None = None,
        has_header: bool = True,
        max_columns: int = _MAX_COLUMNS,
        max_rows: int = _MAX_ROWS,
    ) -> None:
        self.delimiter = delimiter
        self.has_header = has_header
        self.max_columns = max_columns
        self.max_rows = max_rows

    def parse(self, record: FramedRecord) -> ParseResult:
        t0 = time.perf_counter()
        text = record.text

        # Detect delimiter from first line
        first_line = text.splitlines()[0] if text.strip() else ""
        delimiter = self.delimiter or _sniff_delimiter(first_line)

        try:
            reader = csv.reader(io.StringIO(text), delimiter=delimiter)
        except csv.Error as exc:
            err = ParseError(
                code=ErrorCode.INVALID_CSV,
                stage="csv_parser",
                message=f"CSV reader init failed: {str(exc)[:256]}",
                severity=ErrorSeverity.ERROR,
                recoverable=False,
            )
            return ParseResult(
                status=ParseStatus.FAILED,
                parser_id=self.metadata.parser_id,
                parser_version=self.metadata.version,
                format="csv",
                extracted_fields={},
                unmapped_fields={"raw_text": text},
                errors=(err,),
                duration_ms=self.measure_duration(t0),
            )

        headers: list[str] = []
        rows: list[dict[str, str]] = []
        errors: list[ParseError] = []

        try:
            for row_idx, row in enumerate(reader):
                if row_idx == 0 and self.has_header:
                    headers = [
                        _sanitize_key(cell, idx) for idx, cell in enumerate(row[: self.max_columns])
                    ]
                    continue

                if row_idx > self.max_rows:
                    errors.append(
                        ParseError(
                            code=ErrorCode.RESOURCE_LIMIT,
                            stage="csv_parser",
                            message=f"Row limit {self.max_rows} exceeded; truncating",
                            severity=ErrorSeverity.WARNING,
                            recoverable=True,
                        )
                    )
                    break

                truncated_row = row[: self.max_columns]
                row_dict: dict[str, str] = {}
                for col_idx, cell in enumerate(truncated_row):
                    key = (
                        headers[col_idx] if headers and col_idx < len(headers) else f"col_{col_idx}"
                    )
                    row_dict[key] = cell

                rows.append(row_dict)

        except csv.Error as exc:
            errors.append(
                ParseError(
                    code=ErrorCode.INVALID_CSV,
                    stage="csv_parser",
                    message=f"CSV row read error: {str(exc)[:256]}",
                    severity=ErrorSeverity.ERROR,
                    recoverable=True,
                )
            )

        if not rows:
            return ParseResult(
                status=ParseStatus.PARTIAL,
                parser_id=self.metadata.parser_id,
                parser_version=self.metadata.version,
                format="csv",
                extracted_fields={},
                unmapped_fields={"raw_text": text},
                errors=tuple(errors),
                duration_ms=self.measure_duration(t0),
            )

        # For single-row parse (common pipeline use case): emit fields directly
        if len(rows) == 1:
            fields = {}
            for col_key, value in rows[0].items():
                fields[col_key] = self.make_field(
                    col_key,
                    value,
                    Origin.OBSERVED,
                    raw_locator=f"csv:{col_key}",
                )
            return ParseResult(
                status=ParseStatus.PARSED,
                parser_id=self.metadata.parser_id,
                parser_version=self.metadata.version,
                format="csv",
                extracted_fields=fields,
                errors=tuple(errors),
                duration_ms=self.measure_duration(t0),
            )

        # Multi-row: emit as rows array in unmapped (caller should frame per-row)
        return ParseResult(
            status=ParseStatus.PARSED,
            parser_id=self.metadata.parser_id,
            parser_version=self.metadata.version,
            format="csv",
            extracted_fields={},
            unmapped_fields={"rows": rows, "headers": headers},
            errors=tuple(errors),
            duration_ms=self.measure_duration(t0),
        )
