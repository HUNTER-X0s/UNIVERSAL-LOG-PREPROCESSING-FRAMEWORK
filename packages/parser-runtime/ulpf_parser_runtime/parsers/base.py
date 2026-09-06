"""BaseParser interface and contracts for generic and specialized parsers.

Adheres to:
- Spec §11: Parser Registry
- Spec §14: Generic Parsers
- Spec §41: Resource Bounds
- Spec §45: Deterministic Parsing
"""

import time
from abc import ABC, abstractmethod
from typing import Any

from ulpf_parser_runtime.framing import FramedRecord
from ulpf_parser_runtime.models import (
    ExtractedField,
    FieldProvenance,
    Origin,
    ParseResult,
    ParserMetadata,
    ParseStatus,
)


class BaseParser(ABC):
    """Abstract base class for all deterministic ULPF parsers."""

    metadata: ParserMetadata

    @abstractmethod
    def parse(self, record: FramedRecord) -> ParseResult:
        """Parse a single framed record into typed fields and unmapped residue.

        Must be linear-time, resource-bounded, and never raise unhandled exceptions.
        """
        ...

    def make_field(
        self,
        name: str,
        value: Any,
        origin: Origin = Origin.OBSERVED,
        raw_locator: str | None = None,
        confidence: float = 1.0,
        explanation: str | None = None,
    ) -> ExtractedField:
        """Convenience builder for an ExtractedField with valid provenance."""
        prov = FieldProvenance(
            origin=origin,
            transformation_id=f"{self.metadata.parser_id}:extract",
            rule_version=self.metadata.version,
            confidence=confidence,
            explanation=explanation,
        )
        return ExtractedField(
            name=name,
            value=value,
            provenance=prov,
            raw_locator=raw_locator,
        )

    def measure_duration(self, start_time: float) -> float:
        """Compute elapsed wall-clock time in milliseconds."""
        return (time.perf_counter() - start_time) * 1000.0

    def create_failed_result(
        self,
        record: FramedRecord,
        errors: tuple[Any, ...],
        format_name: str | None = None,
        duration_ms: float = 0.0,
    ) -> ParseResult:
        """Produce a safe failed ParseResult without raising an exception."""
        default_fmt = (
            self.metadata.supported_formats[0] if self.metadata.supported_formats else "unknown"
        )
        return ParseResult(
            status=ParseStatus.FAILED,
            parser_id=self.metadata.parser_id,
            parser_version=self.metadata.version,
            format=format_name or default_fmt,
            extracted_fields={},
            unmapped_fields={"raw_text": record.text},
            unparsed_fragments=(record.text,),
            errors=errors,
            duration_ms=duration_ms,
        )
