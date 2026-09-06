"""ULPF Phase 4 Semantic Intelligence Domain Models.

Formal domain models representing:
- SemanticEvent and SemanticTriple (Category, Class, Type)
- SemanticAction and SemanticResult taxonomies
- Entity, Relationship, and Indicator context
- SecurityContext, RiskContext, and CorrelationContext
- Field-level provenance, confidence scoring, and explainable decision traces
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class SemanticStatus(str, Enum):
    """Quality status of semantic interpretation."""

    FULL = "FULL"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"
    FAILED = "FAILED"


class ConfidenceLevel(str, Enum):
    """Confidence levels for semantic classification and mapping."""

    EXACT = "EXACT"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class SemanticProvenance(str, Enum):
    """Field-level origin and derivation provenance."""

    OBSERVED = "OBSERVED"
    NORMALIZED = "NORMALIZED"
    DERIVED = "DERIVED"
    ENRICHED = "ENRICHED"
    INFERRED = "INFERRED"


class EntityType(str, Enum):
    """Controlled taxonomy of normalized entity types."""

    IP = "IP"
    HOST = "HOST"
    USER = "USER"
    PROCESS = "PROCESS"
    FILE = "FILE"
    DEVICE = "DEVICE"
    SERVICE = "SERVICE"
    CONTAINER = "CONTAINER"
    POD = "POD"
    CLUSTER = "CLUSTER"
    CLOUD_ACCOUNT = "CLOUD_ACCOUNT"
    CLOUD_RESOURCE = "CLOUD_RESOURCE"
    DATABASE = "DATABASE"
    APPLICATION = "APPLICATION"
    DOMAIN = "DOMAIN"
    URL = "URL"
    CERTIFICATE = "CERTIFICATE"


class IndicatorType(str, Enum):
    """Controlled taxonomy of threat hunting and telemetry indicators."""

    IP = "IP"
    DOMAIN = "DOMAIN"
    URL = "URL"
    HASH_MD5 = "HASH_MD5"
    HASH_SHA1 = "HASH_SHA1"
    HASH_SHA256 = "HASH_SHA256"
    EMAIL = "EMAIL"
    CERT_FINGERPRINT = "CERT_FINGERPRINT"


@dataclass(frozen=True)
class SemanticConfidence:
    """Confidence measurement and justification for semantic decisions."""

    level: ConfidenceLevel
    score: float
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level.value,
            "score": round(self.score, 4),
            "explanation": self.explanation,
        }


@dataclass(frozen=True)
class DecisionTrace:
    """Explainable audit trace detailing why semantic choices were made."""

    rule_id: str
    rule_version: str
    mapping_id: str
    provenance_type: SemanticProvenance
    evidence: tuple[str, ...] = ()
    explanation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        res: dict[str, Any] = {
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "mapping_id": self.mapping_id,
            "provenance_type": self.provenance_type.value,
            "evidence": list(self.evidence),
        }
        if self.explanation:
            res["explanation"] = self.explanation
        return res


@dataclass(frozen=True)
class SemanticTriple:
    """Universal semantic classification triple: (Category, Class, Type)."""

    category: str
    class_name: str
    type_name: str

    def to_dict(self) -> dict[str, str]:
        return {
            "category": self.category,
            "class": self.class_name,
            "type": self.type_name,
        }


@dataclass(frozen=True)
class SemanticAction:
    """Semantic action representation preserving original, normalized, and mapped actions."""

    semantic: str
    original: str | None = None
    normalized: str | None = None
    mapping_rule: str | None = None

    def to_dict(self) -> dict[str, Any]:
        res: dict[str, Any] = {"semantic": self.semantic}
        if self.original:
            res["original"] = self.original
        if self.normalized:
            res["normalized"] = self.normalized
        if self.mapping_rule:
            res["mapping_rule"] = self.mapping_rule
        return res


@dataclass(frozen=True)
class SemanticResult:
    """Semantic outcome/result of the action."""

    status: str
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        res: dict[str, Any] = {"status": self.status}
        if self.detail:
            res["detail"] = self.detail
        return res


@dataclass(frozen=True)
class Entity:
    """Normalized entity representation with original and normalized attributes."""

    entity_id: str
    entity_type: str
    value: str
    normalized_value: str | None = None
    role: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        res: dict[str, Any] = {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "value": self.value,
            "confidence": round(self.confidence, 4),
        }
        if self.normalized_value:
            res["normalized_value"] = self.normalized_value
        if self.role:
            res["role"] = self.role
        if self.attributes:
            res["attributes"] = self.attributes
        return res


@dataclass(frozen=True)
class EntityRelationship:
    """Directed semantic relationship between two entities."""

    relationship_id: str
    subject: str
    predicate: str
    object_ref: str
    confidence: float = 1.0
    provenance: str = "DERIVED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "relationship_id": self.relationship_id,
            "subject": self.subject,
            "predicate": self.predicate,
            "object": self.object_ref,
            "confidence": round(self.confidence, 4),
            "provenance": self.provenance,
        }


@dataclass(frozen=True)
class Indicator:
    """Security or telemetry indicator extracted deterministically from event evidence."""

    indicator_type: str
    value: str
    source: str = "OBSERVED"
    confidence: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "indicator_type": self.indicator_type,
            "value": self.value,
            "source": self.source,
            "confidence": round(self.confidence, 4),
        }


@dataclass(frozen=True)
class MitreAttackRef:
    """Deterministic MITRE ATT&CK reference with concrete evidence."""

    technique_id: str
    tactic: str | None = None
    evidence: str | None = None

    def to_dict(self) -> dict[str, str]:
        res: dict[str, str] = {"technique_id": self.technique_id}
        if self.tactic:
            res["tactic"] = self.tactic
        if self.evidence:
            res["evidence"] = self.evidence
        return res


@dataclass(frozen=True)
class SecurityContext:
    """Security attributes, detection finding details, and rule metadata."""

    threat: str | None = None
    alert: str | None = None
    rule: str | None = None
    signature: str | None = None
    attack_phase: str | None = None
    policy: str | None = None
    detection_source: str | None = None
    mitre_attack: tuple[MitreAttackRef, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        res: dict[str, Any] = {}
        if self.threat:
            res["threat"] = self.threat
        if self.alert:
            res["alert"] = self.alert
        if self.rule:
            res["rule"] = self.rule
        if self.signature:
            res["signature"] = self.signature
        if self.attack_phase:
            res["attack_phase"] = self.attack_phase
        if self.policy:
            res["policy"] = self.policy
        if self.detection_source:
            res["detection_source"] = self.detection_source
        if self.mitre_attack:
            res["mitre_attack"] = [m.to_dict() for m in self.mitre_attack]
        return res


@dataclass(frozen=True)
class RiskContext:
    """Deterministic risk assessment based on observable event indicators."""

    risk_level: str = "INFORMATIONAL"
    risk_score: float = 0.0
    reason_codes: tuple[str, ...] = ()
    confidence: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk_level": self.risk_level,
            "risk_score": round(self.risk_score, 2),
            "reason_codes": list(self.reason_codes),
            "confidence": round(self.confidence, 4),
        }


@dataclass(frozen=True)
class CorrelationContext:
    """Correlation dimensions and deterministic fingerprinting keys."""

    equivalence_key: str
    event_fingerprint: str
    source_ip: str | None = None
    destination_ip: str | None = None
    user: str | None = None
    host: str | None = None
    session_id: str | None = None
    trace_id: str | None = None
    span_id: str | None = None
    correlation_dimensions: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        res: dict[str, Any] = {
            "equivalence_key": self.equivalence_key,
            "event_fingerprint": self.event_fingerprint,
        }
        if self.source_ip:
            res["source_ip"] = self.source_ip
        if self.destination_ip:
            res["destination_ip"] = self.destination_ip
        if self.user:
            res["user"] = self.user
        if self.host:
            res["host"] = self.host
        if self.session_id:
            res["session_id"] = self.session_id
        if self.trace_id:
            res["trace_id"] = self.trace_id
        if self.span_id:
            res["span_id"] = self.span_id
        if self.correlation_dimensions:
            res.update(self.correlation_dimensions)
        return res


@dataclass
class SemanticEvent:
    """Top-level Semantic Event model providing semantic understanding of UCE."""

    contract_version: str
    semantic_event_id: str
    uce_event_id: str
    raw_event_id: str
    timestamp: str
    semantic_triple: SemanticTriple
    action: SemanticAction
    result: SemanticResult
    confidence: SemanticConfidence
    decision_trace: DecisionTrace
    severity: int = 1
    status: SemanticStatus = SemanticStatus.FULL
    entities: list[Entity] = field(default_factory=list)
    relationships: list[EntityRelationship] = field(default_factory=list)
    indicators: list[Indicator] = field(default_factory=list)
    security_context: SecurityContext = field(default_factory=SecurityContext)
    risk_context: RiskContext = field(default_factory=RiskContext)
    correlation_context: CorrelationContext | None = None
    projections: dict[str, Any] = field(default_factory=dict)
    unmapped_semantic_fields: dict[str, Any] = field(default_factory=dict)

    def to_contract_dict(self) -> dict[str, Any]:
        """Serialize into a valid dictionary for semantic-event.v1.schema.json."""
        doc: dict[str, Any] = {
            "contract_version": self.contract_version,
            "semantic_event_id": self.semantic_event_id,
            "uce_event_id": self.uce_event_id,
            "raw_event_id": self.raw_event_id,
            "timestamp": self.timestamp,
            "semantic_triple": self.semantic_triple.to_dict(),
            "action": self.action.to_dict(),
            "result": self.result.to_dict(),
            "severity": self.severity,
            "confidence": self.confidence.to_dict(),
            "decision_trace": self.decision_trace.to_dict(),
        }
        if self.entities:
            doc["entities"] = [e.to_dict() for e in self.entities]
        if self.relationships:
            doc["relationships"] = [r.to_dict() for r in self.relationships]
        if self.indicators:
            doc["indicators"] = [i.to_dict() for i in self.indicators]

        sec_dict = self.security_context.to_dict()
        if sec_dict:
            doc["security_context"] = sec_dict

        risk_dict = self.risk_context.to_dict()
        if risk_dict:
            doc["risk_context"] = risk_dict

        if self.correlation_context:
            doc["correlation_context"] = self.correlation_context.to_dict()

        if self.projections:
            doc["projections"] = self.projections

        if self.unmapped_semantic_fields:
            doc["unmapped_semantic_fields"] = self.unmapped_semantic_fields

        return doc
