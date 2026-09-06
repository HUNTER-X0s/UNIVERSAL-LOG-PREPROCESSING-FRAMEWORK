"""Domain models for ULPF Phase 5 AI Intelligence Plane."""

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class AIConfidenceBreakdown:
    """Multi-dimensional confidence breakdown for explainable AI suggestions."""

    rule_match_strength: float
    schema_match_strength: float
    evidence_strength: float
    model_confidence: float
    composite_confidence: float


@dataclass(frozen=True)
class FieldSemanticsSuggestion:
    """Field-level semantic interpretation candidate."""

    source_field: str
    target_canonical_field: str
    inferred_type: str
    confidence: float
    evidence: tuple[str, ...] = ()
    reasoning: str = ""


@dataclass
class AISuggestion:
    """Structured, untrusted AI onboarding candidate output."""

    suggestion_id: str
    provider_id: str
    model_version: str
    candidate_mapping: dict[str, Any]
    confidence_breakdown: AIConfidenceBreakdown
    evidence: list[str] = field(default_factory=list)
    uncertainties: list[str] = field(default_factory=list)
    explanation: str = ""
    requires_human_review: bool = True
    input_sample_hash: str = ""
    prompt_template_version: str = "onboarding_semantic_prompt.v1"
