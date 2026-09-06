"""Generic JSON and NDJSON parsers for ULPF Phase 3.

Implements safe, depth-bounded JSON parsing with key count limits,
recursion depth limits, and raw JSON path locators for every extracted field.

Adheres to:
- Spec §16: Structured JSON Strategy
- Spec §23: JSON Security (depth and key limits)
- Spec §41: Resource Bounds
- Spec §27: Unknown Field Preservation
"""

import json
import time
from typing import Any

from ulpf_parser_runtime.errors import (
    ErrorCode,
    ErrorSeverity,
    NestingLimitExceededException,
    ParseError,
)
from ulpf_parser_runtime.framing import FramedRecord
from ulpf_parser_runtime.models import (
    Origin,
    ParseResult,
    ParserMetadata,
    ParseStatus,
)
from ulpf_parser_runtime.parsers.base import BaseParser

_MAX_DEPTH = 30
_MAX_KEYS = 2000


def _flatten_json(
    obj: Any,
    prefix: str = "",
    depth: int = 0,
    max_depth: int = _MAX_DEPTH,
    max_keys: int = _MAX_KEYS,
    out: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Flatten nested JSON into dot-path fields, enforcing depth and key limits."""
    if out is None:
        out = {}
    if depth > max_depth:
        raise NestingLimitExceededException(
            ParseError(
                code=ErrorCode.NESTING_LIMIT_EXCEEDED,
                stage="json_parser",
                message=f"JSON nesting depth {depth} exceeds max {max_depth}",
                severity=ErrorSeverity.ERROR,
                recoverable=True,
            )
        )
    if len(out) >= max_keys:
        return out

    if isinstance(obj, dict):
        for key in list(obj.keys())[:max_keys]:
            path = f"{prefix}.{key}" if prefix else key
            value = obj[key]
            if isinstance(value, dict | list):
                _flatten_json(value, path, depth + 1, max_depth, max_keys, out)
            else:
                out[path] = value
            if len(out) >= max_keys:
                break
    elif isinstance(obj, list):
        for idx, item in enumerate(obj[:max_keys]):
            path = f"{prefix}[{idx}]"
            if isinstance(item, dict | list):
                _flatten_json(item, path, depth + 1, max_depth, max_keys, out)
            else:
                out[path] = item
            if len(out) >= max_keys:
                break
    else:
        out[prefix] = obj

    return out


class GenericJsonParser(BaseParser):
    """Depth-bounded generic JSON parser producing flat field paths and raw locators."""

    metadata = ParserMetadata(
        parser_id="parser.generic.json",
        version="1.0.0",
        supported_formats=("json",),
        supported_vendors=(),
        supported_products=(),
        tier="A",
        description="Generic JSON parser with depth and key limits",
    )

    def __init__(
        self,
        max_depth: int = _MAX_DEPTH,
        max_keys: int = _MAX_KEYS,
    ) -> None:
        self.max_depth = max_depth
        self.max_keys = max_keys

    def parse(self, record: FramedRecord) -> ParseResult:
        t0 = time.perf_counter()
        text = record.text.strip()

        try:
            parsed = json.loads(text)
        except (json.JSONDecodeError, ValueError) as exc:
            err = ParseError(
                code=ErrorCode.MALFORMED_JSON,
                stage="json_parser",
                message=f"JSON decode failed: {str(exc)[:256]}",
                severity=ErrorSeverity.ERROR,
                recoverable=False,
            )
            return ParseResult(
                status=ParseStatus.FAILED,
                parser_id=self.metadata.parser_id,
                parser_version=self.metadata.version,
                format="json",
                extracted_fields={},
                unmapped_fields={"raw_text": text},
                unparsed_fragments=(text,),
                errors=(err,),
                duration_ms=self.measure_duration(t0),
            )

        if not isinstance(parsed, dict):
            # JSON array or scalar — wrap preserving raw value
            return ParseResult(
                status=ParseStatus.PARTIAL,
                parser_id=self.metadata.parser_id,
                parser_version=self.metadata.version,
                format="json",
                extracted_fields={},
                unmapped_fields={"raw_value": parsed},
                duration_ms=self.measure_duration(t0),
            )

        fields = {}
        warnings: list[ParseError] = []
        try:
            flat_fields = _flatten_json(
                parsed,
                max_depth=self.max_depth,
                max_keys=self.max_keys,
            )
        except NestingLimitExceededException as exc:
            warnings.append(exc.parse_error)
            # Still extract top-level keys
            flat_fields = {k: v for k, v in parsed.items() if not isinstance(v, dict | list)}

        for path, value in flat_fields.items():
            fields[path] = self.make_field(
                path,
                value,
                Origin.OBSERVED,
                raw_locator=f"json:{path}",
            )

        # Unmapped: raw dict for complete provenance
        unmapped = {
            k: v
            for k, v in parsed.items()
            if k not in flat_fields
            and not any(
                existing.startswith(f"{k}.") or existing.startswith(f"{k}[")
                for existing in flat_fields
            )
        }

        return ParseResult(
            status=ParseStatus.PARSED,
            parser_id=self.metadata.parser_id,
            parser_version=self.metadata.version,
            format="json",
            extracted_fields=fields,
            unmapped_fields=unmapped if unmapped else {},
            warnings=tuple(warnings),
            duration_ms=self.measure_duration(t0),
        )


class NdJsonParser(BaseParser):
    """NDJSON (newline-delimited JSON) parser delegating to GenericJsonParser per line."""

    metadata = ParserMetadata(
        parser_id="parser.generic.ndjson",
        version="1.0.0",
        supported_formats=("ndjson",),
        supported_vendors=(),
        supported_products=(),
        tier="A",
        description="NDJSON parser (delegates to GenericJsonParser per line)",
    )

    def __init__(
        self,
        max_depth: int = _MAX_DEPTH,
        max_keys: int = _MAX_KEYS,
    ) -> None:
        self._inner = GenericJsonParser(max_depth=max_depth, max_keys=max_keys)

    def parse(self, record: FramedRecord) -> ParseResult:
        """Parse a single NDJSON line via the inner generic JSON parser."""
        t0 = time.perf_counter()
        inner_result = self._inner.parse(record)
        # Return with ndjson format label
        return ParseResult(
            status=inner_result.status,
            parser_id=self.metadata.parser_id,
            parser_version=self.metadata.version,
            format="ndjson",
            extracted_fields=inner_result.extracted_fields,
            unmapped_fields=inner_result.unmapped_fields,
            unparsed_fragments=inner_result.unparsed_fragments,
            errors=inner_result.errors,
            warnings=inner_result.warnings,
            duration_ms=self.measure_duration(t0),
        )
