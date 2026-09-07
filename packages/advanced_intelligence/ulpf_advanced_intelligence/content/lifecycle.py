"""Detection Content Engineering and Lifecycle Governance for ULPF Phase 9."""

from __future__ import annotations

import dataclasses
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from ulpf_advanced_intelligence.errors import ConflictDetectionError
from ulpf_intelligence.rules.dsl import DetectionRule, RuleCondition, RuleThreshold


class DetectionLifecycleState(StrEnum):
    """Detection rule governance lifecycle states."""

    DRAFT = "DRAFT"
    REVIEW = "REVIEW"
    APPROVED = "APPROVED"
    ACTIVE = "ACTIVE"
    DEPRECATED = "DEPRECATED"
    ROLLED_BACK = "ROLLED_BACK"


@dataclass(frozen=True)
class AdvancedDetectionRule:
    """Enterprise detection rule with test fixtures, entity scope, and author governance."""

    rule_id: str
    name: str
    description: str
    author: str
    severity: str
    version: str = "1.0.0"
    state: DetectionLifecycleState = DetectionLifecycleState.DRAFT
    conditions: tuple[RuleCondition, ...] = field(default_factory=tuple)
    threshold: RuleThreshold | None = None
    time_window_seconds: int = 300
    mitre_tactics: tuple[str, ...] = field(default_factory=tuple)
    mitre_techniques: tuple[str, ...] = field(default_factory=tuple)
    entity_scope: tuple[str, ...] = field(default_factory=tuple)
    tenant_id: str | None = None
    positive_fixtures: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    negative_fixtures: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    boundary_fixtures: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    expected_behavior: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_legacy_detection_rule(self) -> DetectionRule:
        """Export as standard Phase 8 DetectionRule for underlying engine execution."""
        from ulpf_intelligence.models.provenance import AlertSeverity, RuleState

        return DetectionRule(
            rule_id=self.rule_id,
            name=self.name,
            description=self.description,
            severity=AlertSeverity(self.severity) if self.severity in AlertSeverity.__members__ else AlertSeverity.MEDIUM,
            conditions=self.conditions,
            threshold=self.threshold,
            version=self.version,
            state=RuleState.ACTIVE if self.state == DetectionLifecycleState.ACTIVE else RuleState.DRAFT,
            tenant_id=self.tenant_id,
            mitre_tactics=self.mitre_tactics,
            mitre_techniques=self.mitre_techniques,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "author": self.author,
            "severity": self.severity,
            "version": self.version,
            "state": self.state.value,
            "time_window_seconds": self.time_window_seconds,
            "mitre_tactics": list(self.mitre_tactics),
            "mitre_techniques": list(self.mitre_techniques),
            "entity_scope": list(self.entity_scope),
            "tenant_id": self.tenant_id,
            "positive_fixtures_count": len(self.positive_fixtures),
            "negative_fixtures_count": len(self.negative_fixtures),
            "boundary_fixtures_count": len(self.boundary_fixtures),
            "expected_behavior": self.expected_behavior,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class AdvancedRuleRegistry:
    """Thread-safe, version-governed detection rule registry enforcing DRAFT -> REVIEW -> APPROVED -> ACTIVE."""

    def __init__(self) -> None:
        self._rules: dict[tuple[str, str], AdvancedDetectionRule] = {}
        self._active: dict[str, str] = {}  # rule_id -> version
        self._history: dict[str, list[str]] = {}  # rule_id -> [v1, v2, ...]
        self._lock = threading.Lock()

    def register_rule(self, rule: AdvancedDetectionRule) -> AdvancedDetectionRule:
        """Register a new or updated rule definition."""
        with self._lock:
            key = (rule.rule_id, rule.version)
            if key in self._rules:
                raise ConflictDetectionError(f"Rule {rule.rule_id} version {rule.version} already exists")

            self._rules[key] = rule
            self._history.setdefault(rule.rule_id, []).append(rule.version)
            return rule

    def approve_rule(self, rule_id: str, version: str) -> AdvancedDetectionRule:
        """Transition rule from DRAFT/REVIEW to APPROVED."""
        with self._lock:
            key = (rule_id, version)
            rule = self._rules.get(key)
            if not rule:
                raise ConflictDetectionError(f"Rule {rule_id} v{version} not found")

            updated = dataclasses.replace(rule, state=DetectionLifecycleState.APPROVED, updated_at=datetime.now(UTC).isoformat())
            self._rules[key] = updated
            return updated

    def activate_rule(self, rule_id: str, version: str) -> AdvancedDetectionRule:
        """Promote an approved rule into ACTIVE execution."""
        with self._lock:
            key = (rule_id, version)
            rule = self._rules.get(key)
            if not rule:
                raise ConflictDetectionError(f"Rule {rule_id} v{version} not found")

            updated = dataclasses.replace(rule, state=DetectionLifecycleState.ACTIVE, updated_at=datetime.now(UTC).isoformat())
            self._rules[key] = updated
            self._active[rule_id] = version
            return updated

    def rollback_rule(self, rule_id: str) -> AdvancedDetectionRule:
        """Roll back an active rule to its prior version."""
        with self._lock:
            history = self._history.get(rule_id, [])
            if len(history) < 2:
                raise ConflictDetectionError(f"Cannot rollback rule {rule_id}: no previous version exists")

            curr_ver = self._active.get(rule_id, history[-1])
            curr_idx = history.index(curr_ver)
            if curr_idx <= 0:
                raise ConflictDetectionError(f"Rule {rule_id} is already at its earliest version")

            prior_version = history[curr_idx - 1]
            prior_rule = self._rules[(rule_id, prior_version)]
            active_prior = dataclasses.replace(prior_rule, state=DetectionLifecycleState.ACTIVE, updated_at=datetime.now(UTC).isoformat())
            self._rules[(rule_id, prior_version)] = active_prior
            self._active[rule_id] = prior_version
            return active_prior

    def get_active_rules(self, tenant_id: str | None = None) -> list[AdvancedDetectionRule]:
        with self._lock:
            active_rules: list[AdvancedDetectionRule] = []
            for rule_id, ver in self._active.items():
                rule = self._rules.get((rule_id, ver))
                if rule and rule.state == DetectionLifecycleState.ACTIVE:
                    if tenant_id is None or rule.tenant_id is None or rule.tenant_id == tenant_id:
                        active_rules.append(rule)
            return active_rules
