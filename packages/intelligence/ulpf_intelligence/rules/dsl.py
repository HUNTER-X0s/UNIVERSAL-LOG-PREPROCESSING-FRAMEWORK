"""Strongly typed, safe Detection Rule DSL for ULPF Phase 8.

Enforces:
- Rule 4: Deterministic rule execution
- Zero eval(), exec(), or arbitrary code execution
- Safe regex compilation and syntax validation
- Versioned rule specifications
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ulpf_intelligence.errors import RuleValidationError
from ulpf_intelligence.models.provenance import AlertSeverity, RuleState


class RuleOperator(str, Enum):
    """Safe evaluation operators for rule conditions."""

    EQUALS = "EQUALS"
    NOT_EQUALS = "NOT_EQUALS"
    CONTAINS = "CONTAINS"
    NOT_CONTAINS = "NOT_CONTAINS"
    REGEX = "REGEX_SAFE"
    REGEX_SAFE = "REGEX_SAFE"
    GT = "GT"
    GREATER_THAN = "GT"
    GTE = "GTE"
    LT = "LT"
    LESS_THAN = "LT"
    LTE = "LTE"
    IN = "IN_LIST"
    IN_LIST = "IN_LIST"
    NOT_IN = "NOT_IN_LIST"
    NOT_IN_LIST = "NOT_IN_LIST"
    EXISTS = "EXISTS"
    NOT_EXISTS = "NOT_EXISTS"


@dataclass(frozen=True)
class RuleCondition:
    """Atomic condition evaluating a single field in event payload or metadata."""

    field: str
    operator: RuleOperator
    value: Any = None

    def __post_init__(self) -> None:
        if isinstance(self.operator, str) and not isinstance(self.operator, RuleOperator):
            object.__setattr__(self, "operator", RuleOperator(self.operator))

    def evaluate(self, context: dict[str, Any]) -> bool:
        """Deterministically evaluate this condition against a field dictionary."""
        parts = self.field.split(".")
        curr: Any = context
        for p in parts:
            if isinstance(curr, dict):
                curr = curr.get(p)
            else:
                curr = None
                break

        if self.operator == RuleOperator.EXISTS:
            return curr is not None
        if self.operator == RuleOperator.NOT_EXISTS:
            return curr is None

        if curr is None:
            return False

        op = self.operator
        val = self.value

        if op == RuleOperator.EQUALS:
            return str(curr).lower() == str(val).lower()
        if op == RuleOperator.NOT_EQUALS:
            return str(curr).lower() != str(val).lower()
        if op == RuleOperator.CONTAINS:
            return str(val).lower() in str(curr).lower()
        if op == RuleOperator.NOT_CONTAINS:
            return str(val).lower() not in str(curr).lower()
        if op in (RuleOperator.REGEX, RuleOperator.REGEX_SAFE):
            try:
                pattern = re.compile(str(val), re.IGNORECASE)
                return bool(pattern.search(str(curr)))
            except re.error:
                return False
        if op in (RuleOperator.GT, RuleOperator.GREATER_THAN):
            try:
                return float(curr) > float(val)
            except (ValueError, TypeError):
                return False
        if op == RuleOperator.GTE:
            try:
                return float(curr) >= float(val)
            except (ValueError, TypeError):
                return False
        if op in (RuleOperator.LT, RuleOperator.LESS_THAN):
            try:
                return float(curr) < float(val)
            except (ValueError, TypeError):
                return False
        if op == RuleOperator.LTE:
            try:
                return float(curr) <= float(val)
            except (ValueError, TypeError):
                return False
        if op in (RuleOperator.IN, RuleOperator.IN_LIST):
            if isinstance(val, list | tuple | set):
                return str(curr).lower() in {str(x).lower() for x in val}
            return False
        if op in (RuleOperator.NOT_IN, RuleOperator.NOT_IN_LIST):
            if isinstance(val, list | tuple | set):
                return str(curr).lower() not in {str(x).lower() for x in val}
            return True

        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "field": self.field,
            "operator": self.operator.value,
            "value": self.value,
        }


@dataclass(frozen=True)
class RuleThreshold:
    """Frequency threshold specification."""

    count: int
    window_seconds: int
    group_by: str | None = None  # e.g., "src_ip"
    group_by_fields: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if isinstance(self.group_by_fields, list):
            object.__setattr__(self, "group_by_fields", tuple(self.group_by_fields))
        if not self.group_by and self.group_by_fields:
            object.__setattr__(self, "group_by", self.group_by_fields[0])
        elif self.group_by and not self.group_by_fields:
            object.__setattr__(self, "group_by_fields", (self.group_by,))

    def to_dict(self) -> dict[str, Any]:
        return {
            "count": self.count,
            "window_seconds": self.window_seconds,
            "group_by": self.group_by,
            "group_by_fields": list(self.group_by_fields),
        }


@dataclass(frozen=True)
class DetectionRule:
    """Immutable, versioned detection rule definition."""

    rule_id: str
    name: str
    description: str
    severity: AlertSeverity
    conditions: tuple[RuleCondition, ...] = field(default_factory=tuple)
    threshold: RuleThreshold | None = None
    version: str = "1.0.0"
    state: RuleState = RuleState.DRAFT
    tenant_id: str | None = None
    mitre_attack: str | None = None
    mitre_tactics: tuple[str, ...] = field(default_factory=tuple)
    mitre_techniques: tuple[str, ...] = field(default_factory=tuple)
    confidence: float = 0.9
    base_risk: float = 50.0
    tags: tuple[str, ...] = field(default_factory=tuple)
    enabled: bool = True

    def __post_init__(self) -> None:
        if isinstance(self.conditions, list):
            object.__setattr__(self, "conditions", tuple(self.conditions))
        if isinstance(self.tags, list):
            object.__setattr__(self, "tags", tuple(self.tags))
        if isinstance(self.mitre_tactics, list):
            object.__setattr__(self, "mitre_tactics", tuple(self.mitre_tactics))
        if isinstance(self.mitre_techniques, list):
            object.__setattr__(self, "mitre_techniques", tuple(self.mitre_techniques))
        if isinstance(self.severity, str) and not isinstance(self.severity, AlertSeverity):
            object.__setattr__(self, "severity", AlertSeverity(self.severity))
        self.validate()

    def validate(self) -> None:
        """Validate safety and syntax of the rule definition."""
        if not self.rule_id or not self.version or not self.name:
            raise RuleValidationError("Empty rule_id, version, or name")

        if not self.conditions and not self.threshold:
            raise RuleValidationError("Rule must contain at least one condition or threshold")

        for cond in self.conditions:
            if not cond.field:
                raise RuleValidationError("RuleCondition field cannot be empty")
            if cond.operator in (RuleOperator.REGEX, RuleOperator.REGEX_SAFE):
                try:
                    re.compile(str(cond.value))
                except re.error as exc:
                    raise RuleValidationError(f"Invalid regular expression in condition: {exc}") from exc

    def matches(self, context: dict[str, Any]) -> bool:
        """Helper to evaluate static conditions directly."""
        return all(c.evaluate(context) for c in self.conditions)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "version": self.version,
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value,
            "conditions": [c.to_dict() for c in self.conditions],
            "threshold": self.threshold.to_dict() if self.threshold else None,
            "state": self.state.value,
            "tenant_id": self.tenant_id,
            "mitre_attack": self.mitre_attack,
            "mitre_tactics": list(self.mitre_tactics),
            "mitre_techniques": list(self.mitre_techniques),
            "confidence": self.confidence,
            "base_risk": self.base_risk,
            "tags": list(self.tags),
            "enabled": self.enabled,
        }
