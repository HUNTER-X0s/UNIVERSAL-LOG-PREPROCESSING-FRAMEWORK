"""Domain models for ULPF Phase 5 Configuration-Driven Mapping Plane."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class MappingLifecycleState(str, Enum):
    """Lifecycle state of a mapping definition."""

    DRAFT = "DRAFT"
    VALIDATED = "VALIDATED"
    TESTED = "TESTED"
    APPROVED = "APPROVED"
    ACTIVE = "ACTIVE"
    DEPRECATED = "DEPRECATED"
    RETIRED = "RETIRED"


class MappingProvenance(str, Enum):
    """Origin of a mapping definition."""

    BUILT_IN = "BUILT_IN"
    VENDOR_PROFILE = "VENDOR_PROFILE"
    USER_AUTHORED = "USER_AUTHORED"
    AI_SUGGESTED = "AI_SUGGESTED"
    AI_ASSISTED = "AI_ASSISTED"
    IMPORTED = "IMPORTED"
    DERIVED = "DERIVED"


@dataclass(frozen=True)
class MappingCondition:
    """Safe rule condition evaluating a single field."""

    field: str
    op: str
    value: Any


@dataclass(frozen=True)
class MatchCriteria:
    """Criteria determining whether an incoming event triggers a mapping."""

    vendor: str | None = None
    product: str | None = None
    parser_id: str | None = None
    event_type: str | None = None
    conditions: tuple[MappingCondition, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class SemanticTarget:
    """Semantic classification targets for category, class, type, action, result."""

    category: str
    class_name: str
    type_name: str
    action: str | None = None
    result: str | None = None


@dataclass(frozen=True)
class FieldMappingRule:
    """Transformation rule copying/normalizing an extracted field."""

    source_field: str
    target_field: str
    transform: str = "copy"
    required: bool = False


@dataclass(frozen=True)
class EntityExtractionRule:
    """Rule extracting normalized entities from event evidence."""

    source_field: str
    entity_type: str
    role: str = "generic"
    confidence: float = 1.0


@dataclass(frozen=True)
class IndicatorExtractionRule:
    """Rule extracting observable threat/telemetry indicators."""

    source_field: str
    indicator_type: str
    confidence: float = 1.0


@dataclass
class MappingDefinition:
    """Top-level configuration-driven mapping specification."""

    mapping_id: str
    version: str
    vendor: str
    product: str
    match: MatchCriteria
    semantic: SemanticTarget
    schema_version: str = "1.0.0"
    format: str | None = None
    description: str | None = None
    priority: int = 100
    confidence: float = 0.95
    lifecycle_state: MappingLifecycleState = MappingLifecycleState.DRAFT
    provenance: MappingProvenance = MappingProvenance.USER_AUTHORED
    field_mappings: list[FieldMappingRule] = field(default_factory=list)
    entity_rules: list[EntityExtractionRule] = field(default_factory=list)
    indicator_rules: list[IndicatorExtractionRule] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    tests: list[dict[str, Any]] = field(default_factory=list)
    checksum: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize into dictionary compliant with semantic-mapping.v1.schema.json."""
        match_dict: dict[str, Any] = {}
        if self.match.vendor:
            match_dict["vendor"] = self.match.vendor
        if self.match.product:
            match_dict["product"] = self.match.product
        if self.match.parser_id:
            match_dict["parser_id"] = self.match.parser_id
        if self.match.event_type:
            match_dict["event_type"] = self.match.event_type
        if self.match.conditions:
            match_dict["conditions"] = [
                {"field": c.field, "op": c.op, "value": c.value} for c in self.match.conditions
            ]

        res: dict[str, Any] = {
            "schema_version": self.schema_version,
            "mapping_id": self.mapping_id,
            "version": self.version,
            "vendor": self.vendor,
            "product": self.product,
            "priority": self.priority,
            "confidence": self.confidence,
            "lifecycle_state": self.lifecycle_state.value,
            "provenance": self.provenance.value,
            "match": match_dict,
            "semantic": {
                "category": self.semantic.category,
                "class": self.semantic.class_name,
                "type": self.semantic.type_name,
            },
        }
        if self.semantic.action:
            res["semantic"]["action"] = self.semantic.action
        if self.semantic.result:
            res["semantic"]["result"] = self.semantic.result
        if self.format:
            res["format"] = self.format
        if self.description:
            res["description"] = self.description
        if self.field_mappings:
            res["field_mappings"] = [
                {
                    "source_field": f.source_field,
                    "target_field": f.target_field,
                    "transform": f.transform,
                    "required": f.required,
                }
                for f in self.field_mappings
            ]
        if self.entity_rules:
            res["entity_rules"] = [
                {
                    "source_field": e.source_field,
                    "entity_type": e.entity_type,
                    "role": e.role,
                    "confidence": e.confidence,
                }
                for e in self.entity_rules
            ]
        if self.indicator_rules:
            res["indicator_rules"] = [
                {
                    "source_field": i.source_field,
                    "indicator_type": i.indicator_type,
                    "confidence": i.confidence,
                }
                for i in self.indicator_rules
            ]
        if self.metadata:
            res["metadata"] = self.metadata
        if self.tests:
            res["tests"] = self.tests
        return res

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "MappingDefinition":
        """Deserialize dictionary into MappingDefinition."""
        match_d = d.get("match", {})
        conditions = []
        for c in match_d.get("conditions", []):
            conditions.append(
                MappingCondition(
                    field=c["field"],
                    op=c.get("op", c.get("operator", "equals")),
                    value=c.get("value"),
                )
            )
        match_crit = MatchCriteria(
            vendor=match_d.get("vendor"),
            product=match_d.get("product"),
            parser_id=match_d.get("parser_id"),
            event_type=match_d.get("event_type"),
            conditions=tuple(conditions),
        )
        sem_d = d.get("semantic", {})
        semantic = SemanticTarget(
            category=sem_d.get("category", "SYSTEM"),
            class_name=sem_d.get("class", sem_d.get("class_name", "EVENT")),
            type_name=sem_d.get("type", sem_d.get("type_name", "UNKNOWN")),
            action=sem_d.get("action"),
            result=sem_d.get("result", sem_d.get("disposition")),
        )
        prov_raw = d.get("provenance", {})
        prov_origin = (
            prov_raw.get("origin", "USER_AUTHORED") if isinstance(prov_raw, dict) else str(prov_raw)
        )
        prov_enum = (
            MappingProvenance[prov_origin]
            if prov_origin in MappingProvenance.__members__
            else MappingProvenance.USER_AUTHORED
        )

        state_str = d.get("lifecycle_state", "DRAFT")
        state_enum = (
            MappingLifecycleState[state_str]
            if state_str in MappingLifecycleState.__members__
            else MappingLifecycleState.DRAFT
        )

        return cls(
            mapping_id=d["mapping_id"],
            version=d.get("version", "1.0.0"),
            vendor=d.get("vendor", match_d.get("vendor", "generic")),
            product=d.get("product", match_d.get("product", "generic")),
            match=match_crit,
            semantic=semantic,
            schema_version=d.get("schema_version", "1.0.0"),
            format=d.get("format", match_d.get("source_format")),
            description=d.get("description"),
            priority=d.get("priority", 100),
            confidence=d.get("confidence", 0.95),
            lifecycle_state=state_enum,
            provenance=prov_enum,
            metadata=d.get("metadata", {}),
            tests=d.get("tests", []),
            checksum=d.get("checksum", ""),
        )


@dataclass(frozen=True)
class CompiledMapping:
    """Immutable, deterministic compiled representation of a mapping rule."""

    mapping_id: str
    version: str
    priority: int
    confidence: float
    provenance: MappingProvenance
    semantic: SemanticTarget
    checksum: str
    field_mappings: tuple[FieldMappingRule, ...]
    entity_rules: tuple[EntityExtractionRule, ...]
    indicator_rules: tuple[IndicatorExtractionRule, ...]
    match_fn: Any  # Callable[[dict[str, Any]], bool]


@dataclass
class MappingPack:
    """Portable, air-gap-friendly bundle of mappings, profiles, and golden tests."""

    pack_id: str
    version: str
    mappings: list[MappingDefinition] = field(default_factory=list)
    description: str = ""
    author: str = "ULPF"
    checksum: str = ""
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "pack_id": self.pack_id,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "checksum": self.checksum,
            "created_at": self.created_at,
            "mappings": [m.to_dict() for m in self.mappings],
        }
