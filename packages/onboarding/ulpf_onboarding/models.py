"""Domain models for ULPF Phase 5 Onboarding & Governance Plane."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class DriftState(str, Enum):
    """Classification of schema drift severity."""

    STABLE = "STABLE"
    MINOR_DRIFT = "MINOR_DRIFT"
    MAJOR_DRIFT = "MAJOR_DRIFT"
    BREAKING_DRIFT = "BREAKING_DRIFT"
    UNKNOWN = "UNKNOWN"


class ApprovalDecision(str, Enum):
    """Human approval decision."""

    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    CHANGES_REQUESTED = "CHANGES_REQUESTED"


@dataclass(frozen=True)
class FieldProfile:
    """Statistical and structural profile of a single field."""

    path: str
    inferred_type: str
    null_frequency: float = 0.0
    sample_values: tuple[str, ...] = field(default_factory=tuple)
    cardinality: int = 0


@dataclass
class SourceProfile:
    """Profile describing the structural schema of a log source."""

    profile_id: str
    version: str
    vendor: str
    product: str
    format: str
    fields: list[FieldProfile] = field(default_factory=list)
    description: str = ""
    status: str = "ACTIVE"
    parser_reference: str = ""
    checksum: str = ""
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0.0",
            "profile_id": self.profile_id,
            "version": self.version,
            "vendor": self.vendor,
            "product": self.product,
            "format": self.format,
            "description": self.description,
            "status": self.status,
            "parser_reference": self.parser_reference,
            "checksum": self.checksum,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "fields": [
                {
                    "path": f.path,
                    "inferred_type": f.inferred_type,
                    "null_frequency": f.null_frequency,
                    "sample_values": list(f.sample_values),
                    "cardinality": f.cardinality,
                }
                for f in self.fields
            ],
        }


@dataclass
class DriftReport:
    """Report detailing detected schema drift between profile and new samples."""

    report_id: str
    profile_id: str
    profile_version: str
    drift_state: DriftState
    timestamp: str
    fields_added: list[str] = field(default_factory=list)
    fields_removed: list[str] = field(default_factory=list)
    type_changes: list[dict[str, str]] = field(default_factory=list)
    recommended_action: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0.0",
            "report_id": self.report_id,
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "drift_state": self.drift_state.value,
            "timestamp": self.timestamp,
            "fields_added": self.fields_added,
            "fields_removed": self.fields_removed,
            "type_changes": self.type_changes,
            "recommended_action": self.recommended_action,
        }


@dataclass
class ReplayResult:
    """Evaluation result of replaying sample events through a candidate mapping."""

    mapping_id: str
    mapping_version: str
    total_events: int
    passed_events: int
    failed_events: int
    semantic_diffs: list[dict[str, Any]] = field(default_factory=list)
    success_rate: float = 1.0


@dataclass
class OnboardingResult:
    """Comprehensive result of an onboarding run for an unseen log sample."""

    onboarding_id: str
    detected_format: str
    detected_vendor: str
    detected_product: str
    field_inventory: list[str]
    candidate_mappings: list[dict[str, Any]]
    quality_score: float
    status: str
    sample_hash: str = ""
    sample_count: int = 1
    warnings: list[str] = field(default_factory=list)
    ai_assisted: bool = False
    ai_metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0.0",
            "onboarding_id": self.onboarding_id,
            "sample_hash": self.sample_hash,
            "sample_count": self.sample_count,
            "detected_format": self.detected_format,
            "detected_vendor": self.detected_vendor,
            "detected_product": self.detected_product,
            "field_inventory": self.field_inventory,
            "candidate_mappings": self.candidate_mappings,
            "quality_score": self.quality_score,
            "status": self.status,
            "warnings": self.warnings,
            "ai_assisted": self.ai_assisted,
            "ai_metadata": self.ai_metadata,
            "created_at": self.created_at,
        }
