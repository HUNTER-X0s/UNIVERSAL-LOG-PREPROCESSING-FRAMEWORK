"""Phase 3 Domain Models for record representation, format/source detection, and parse results.

Adheres to:
- Spec §4: Define the Phase-3 Domain Model
- Spec §26: Observed vs Derived vs Enriched vs Inferred
- Spec §27: Unknown Field Preservation
- Spec §34: Normalization Status
- Spec §35: Parser Confidence
- Spec §36: Parse Result Contract
- contracts/jsonschema/parsed-event.v1.schema.json
- contracts/jsonschema/ulpf-common.v1.schema.json
"""

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from ulpf_parser_runtime.errors import ParseError


class Origin(StrEnum):
    """Authoritative assertion origin defined in ulpf-common.v1.schema.json."""

    OBSERVED = "observed"
    INFERRED = "inferred"
    ENRICHED = "enriched"
    DERIVED = "derived"


class ParseStatus(StrEnum):
    """ParsedEvent status defined in parsed-event.v1.schema.json."""

    PARSED = "parsed"
    PARTIAL = "partial"
    FAILED = "failed"


class NormalizationStatus(StrEnum):
    """Level of semantic normalization achieved for an event."""

    FULL = "FULL"
    PARTIAL = "PARTIAL"
    NONE = "NONE"
    FAILED = "FAILED"


@dataclass(frozen=True, slots=True)
class FieldProvenance:
    """Lineage and origin metadata for an individual field."""

    origin: Origin
    transformation_id: str = "identity"
    raw_paths: tuple[str, ...] = field(default_factory=tuple)
    input_field_paths: tuple[str, ...] = field(default_factory=tuple)
    rule_version: str = "1.0.0"
    confidence: float = 1.0
    explanation: str | None = None

    def to_contract_dict(self) -> dict[str, Any]:
        """Convert to JSON Schema compliant fieldProvenance dict."""
        doc: dict[str, Any] = {
            "origin": self.origin.value,
            "transformation_id": self.transformation_id,
        }
        if self.raw_paths:
            doc["raw_paths"] = list(self.raw_paths)
        if self.input_field_paths:
            doc["input_field_paths"] = list(self.input_field_paths)
        if self.rule_version:
            doc["rule_version"] = self.rule_version
        if self.confidence is not None:
            doc["confidence"] = max(0.0, min(1.0, float(self.confidence)))
        if self.explanation:
            doc["explanation"] = self.explanation[:4096]
        return doc


@dataclass(frozen=True, slots=True)
class ExtractedField:
    """An extracted typed field with its origin and raw evidence locator."""

    name: str
    value: Any
    provenance: FieldProvenance
    raw_locator: str | None = None

    def to_contract_dict(self) -> dict[str, Any]:
        """Convert to JSON Schema compliant fields property entry."""
        return {
            "value": self.value,
            "provenance": self.provenance.to_contract_dict(),
        }


@dataclass(frozen=True, slots=True)
class DetectedFormat:
    """Scored format candidate produced by a deterministic format detector."""

    format_name: str
    score: float
    confidence: float
    evidence: tuple[str, ...] = field(default_factory=tuple)
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class DetectedSource:
    """Scored source/vendor/product candidate produced by a source resolver."""

    vendor: str
    product: str
    source_type: str
    score: float
    confidence: float
    evidence: tuple[str, ...] = field(default_factory=tuple)
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class DetectionResult:
    """Composite detection result with ranked format and source candidates."""

    format: DetectedFormat
    source: DetectedSource | None = None
    candidate_formats: tuple[DetectedFormat, ...] = field(default_factory=tuple)
    candidate_sources: tuple[DetectedSource, ...] = field(default_factory=tuple)
    is_ambiguous: bool = False


@dataclass(frozen=True, slots=True)
class ParserMetadata:
    """Governed metadata describing an immutable parser implementation or pack."""

    parser_id: str
    version: str = "1.0.0"
    supported_formats: tuple[str, ...] = field(default_factory=tuple)
    supported_vendors: tuple[str, ...] = field(default_factory=tuple)
    supported_products: tuple[str, ...] = field(default_factory=tuple)
    tier: str = "A"  # Tier A (generic), Tier B (perimeter), Tier C (universal)
    description: str = ""

    def to_versioned_ref(self) -> dict[str, str]:
        return {
            "id": self.parser_id,
            "version": self.version,
        }


@dataclass(frozen=True, slots=True)
class ParserCandidate:
    """A scored parser candidate for a given record."""

    metadata: ParserMetadata
    priority: int
    suitability_score: float


@dataclass(frozen=True, slots=True)
class ParserSelection:
    """Selected parser with selection rationale."""

    selected_parser: ParserMetadata
    confidence: float
    selection_reason: str
    candidates: tuple[ParserCandidate, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class ParseResult:
    """Result of structural parsing before normalization into a canonical event.

    Strictly preserves unmapped fields, unparsed fragments, and raw locators.
    """

    status: ParseStatus
    parser_id: str
    parser_version: str
    format: str
    extracted_fields: dict[str, ExtractedField] = field(default_factory=dict)
    unmapped_fields: dict[str, Any] = field(default_factory=dict)
    unparsed_fragments: tuple[str, ...] = field(default_factory=tuple)
    raw_evidence_ref: str | None = None
    errors: tuple[ParseError, ...] = field(default_factory=tuple)
    warnings: tuple[ParseError, ...] = field(default_factory=tuple)
    duration_ms: float = 0.0
    processed_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_parsed_event_contract(
        self,
        raw_event_id: str,
        source_id: str = "unknown",
        source_profile_id: str | None = None,
        source_profile_version: str | None = None,
    ) -> dict[str, Any]:
        """Project parse result into the frozen parsed-event.v1.schema.json contract."""
        source_resolution: dict[str, Any] = {
            "status": "resolved" if source_id != "unknown" else "unknown",
            "source_profile": (
                {"id": source_profile_id, "version": source_profile_version or "1.0.0"}
                if source_profile_id
                else None
            ),
        }
        fields_doc: dict[str, Any] = {
            name: field_obj.to_contract_dict() for name, field_obj in self.extracted_fields.items()
        }

        doc: dict[str, Any] = {
            "contract_version": "1.0.0",
            "parsed_event_id": str(uuid.uuid4()),
            "raw_event_id": raw_event_id,
            "source_id": source_id,
            "source_resolution": source_resolution,
            "parser": {
                "id": self.parser_id,
                "version": self.parser_version,
            },
            "format": self.format,
            "status": self.status.value,
            "fields": fields_doc,
            "processed_at": self.processed_at.isoformat(),
        }

        if self.unparsed_fragments:
            doc["unparsed_fragments"] = list(self.unparsed_fragments)
        if self.warnings:
            doc["warnings"] = [w.to_contract_dict() for w in self.warnings]

        return doc
