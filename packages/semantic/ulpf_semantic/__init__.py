"""ULPF Phase 4 Semantic Intelligence and Interoperability Package."""

from ulpf_semantic.classification.classifier import SemanticClassifier
from ulpf_semantic.errors import (
    ErrorSeverity,
    SemanticError,
    SemanticErrorCode,
)
from ulpf_semantic.mapping.engine import SemanticMapper
from ulpf_semantic.models import (
    ConfidenceLevel,
    CorrelationContext,
    DecisionTrace,
    Entity,
    EntityRelationship,
    EntityType,
    Indicator,
    IndicatorType,
    MitreAttackRef,
    RiskContext,
    SecurityContext,
    SemanticAction,
    SemanticConfidence,
    SemanticEvent,
    SemanticProvenance,
    SemanticResult,
    SemanticStatus,
    SemanticTriple,
)
from ulpf_semantic.projections.base import BaseProjection, ProjectionResult, ProjectionStatus
from ulpf_semantic.projections.ocsf.mapper import OCSFProjection
from ulpf_semantic.projections.otel.mapper import OTelProjection
from ulpf_semantic.projections.registry import (
    ProjectionRegistry,
    create_default_projection_registry,
)
from ulpf_semantic.service import SemanticService
from ulpf_semantic.validation import SemanticEventValidator

__all__ = [
    "BaseProjection",
    "ConfidenceLevel",
    "CorrelationContext",
    "DecisionTrace",
    "Entity",
    "EntityRelationship",
    "EntityType",
    "ErrorSeverity",
    "Indicator",
    "IndicatorType",
    "MitreAttackRef",
    "OCSFProjection",
    "OTelProjection",
    "ProjectionRegistry",
    "ProjectionResult",
    "ProjectionStatus",
    "RiskContext",
    "SecurityContext",
    "SemanticAction",
    "SemanticClassifier",
    "SemanticConfidence",
    "SemanticError",
    "SemanticErrorCode",
    "SemanticEvent",
    "SemanticEventValidator",
    "SemanticMapper",
    "SemanticProvenance",
    "SemanticResult",
    "SemanticService",
    "SemanticStatus",
    "SemanticTriple",
    "create_default_projection_registry",
]
