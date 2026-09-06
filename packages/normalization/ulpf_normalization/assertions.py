"""Field assertions and provenance tracking for ULPF Phase 3 Normalization.

Adheres to:
- Spec §31: Field Provenance Tracking
- Spec §32: Assertion Origins (observed, derived, enriched, inferred)
- Spec §33: Universal Canonical Event (UCE) Schema
- Contracts: contracts/jsonschema/ulpf-common.v1.schema.json#/$defs/fieldProvenance
"""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class AssertionOrigin(StrEnum):
    """Authoritative origins for field values per ULPF contract."""

    OBSERVED = "observed"
    DERIVED = "derived"
    ENRICHED = "enriched"
    INFERRED = "inferred"


@dataclass(frozen=True, slots=True)
class FieldProvenanceRecord:
    """Immutable provenance record strictly matching ulpf-common.v1.schema.json."""

    origin: AssertionOrigin
    transformation_id: str
    rule_version: str = "1.0.0"
    raw_paths: tuple[str, ...] = field(default_factory=tuple)
    input_field_paths: tuple[str, ...] = field(default_factory=tuple)
    lineage_step_id: str | None = None
    approval_audit_event_id: str | None = None
    confidence: float = 1.0
    explanation: str | None = None

    def to_contract_dict(self) -> dict[str, Any]:
        """Serialize to contract dictionary conforming to schema."""
        out: dict[str, Any] = {
            "origin": self.origin.value,
            "transformation_id": self.transformation_id,
            "rule_version": self.rule_version,
            "confidence": min(1.0, max(0.0, float(self.confidence))),
        }
        if self.raw_paths:
            out["raw_paths"] = list(self.raw_paths)
        if self.input_field_paths:
            out["input_field_paths"] = list(self.input_field_paths)
        if self.lineage_step_id:
            out["lineage_step_id"] = self.lineage_step_id
        if self.approval_audit_event_id:
            out["approval_audit_event_id"] = self.approval_audit_event_id
        if self.explanation:
            out["explanation"] = self.explanation[:4096]
        return out


@dataclass(frozen=True, slots=True)
class FieldAssertion:
    """An asserted canonical field with typed value and attached provenance."""

    path: str
    value: Any
    provenance: FieldProvenanceRecord
