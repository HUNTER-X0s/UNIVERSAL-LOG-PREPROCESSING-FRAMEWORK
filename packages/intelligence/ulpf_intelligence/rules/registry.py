"""Detection Rule Governance and Versioned Registry for ULPF Phase 8."""

from __future__ import annotations

import threading

from ulpf_intelligence.errors import RuleValidationError
from ulpf_intelligence.models.provenance import RuleState
from ulpf_intelligence.rules.dsl import DetectionRule


class RuleRegistry:
    """Thread-safe versioned registry for detection rules with lifecycle governance."""

    def __init__(self) -> None:
        # (rule_id, version) -> DetectionRule
        self._rules: dict[tuple[str, str], DetectionRule] = {}
        # rule_id -> active version string
        self._active_versions: dict[str, str] = {}
        # rule_id -> list of historical versions in order
        self._version_history: dict[str, list[str]] = {}
        self._lock = threading.Lock()

    def register_rule(self, rule: DetectionRule, author: str | None = None) -> None:
        """Register a new rule or new version of an existing rule."""
        rule.validate()
        with self._lock:
            key = (rule.rule_id, rule.version)
            if key in self._rules:
                raise RuleValidationError(f"Rule '{rule.rule_id}' version '{rule.version}' already exists")

            self._rules[key] = rule
            if rule.rule_id not in self._version_history:
                self._version_history[rule.rule_id] = []
            self._version_history[rule.rule_id].append(rule.version)

            if rule.state == RuleState.ACTIVE:
                self._active_versions[rule.rule_id] = rule.version

    def approve_rule(
        self,
        rule_id: str,
        version: str | None = None,
        reviewer: str | None = None,
    ) -> DetectionRule:
        """Transition a rule from DRAFT/VALIDATED to REVIEWED/APPROVED."""
        with self._lock:
            v = version or self._active_versions.get(rule_id) or self._version_history.get(rule_id, ["1.0.0"])[-1]
            key = (rule_id, v)
            rule = self._rules.get(key)
            if not rule:
                raise RuleValidationError(f"Rule '{rule_id}' v{v} not found")

            approved_rule = DetectionRule(
                rule_id=rule.rule_id,
                version=rule.version,
                name=rule.name,
                description=rule.description,
                severity=rule.severity,
                conditions=rule.conditions,
                threshold=rule.threshold,
                state=RuleState.REVIEWED,
                tenant_id=rule.tenant_id,
                mitre_attack=rule.mitre_attack,
                confidence=rule.confidence,
                base_risk=rule.base_risk,
                tags=rule.tags,
            )
            self._rules[key] = approved_rule
            return approved_rule

    def activate_rule(
        self,
        rule_id: str,
        version: str | None = None,
    ) -> DetectionRule:
        """Activate a specific approved version of a rule."""
        with self._lock:
            v = version or self._active_versions.get(rule_id) or self._version_history.get(rule_id, ["1.0.0"])[-1]
            key = (rule_id, v)
            rule = self._rules.get(key)
            if not rule:
                raise RuleValidationError(f"Rule '{rule_id}' v{v} not found")

            activated_rule = DetectionRule(
                rule_id=rule.rule_id,
                version=rule.version,
                name=rule.name,
                description=rule.description,
                severity=rule.severity,
                conditions=rule.conditions,
                threshold=rule.threshold,
                state=RuleState.ACTIVE,
                tenant_id=rule.tenant_id,
                mitre_attack=rule.mitre_attack,
                confidence=rule.confidence,
                base_risk=rule.base_risk,
                tags=rule.tags,
            )
            self._rules[key] = activated_rule
            self._active_versions[rule_id] = v
            return activated_rule

    def deactivate_rule(
        self,
        rule_id: str,
        version: str | None = None,
    ) -> DetectionRule:
        """Deactivate a rule, marking state as DEPRECATED."""
        with self._lock:
            v = version or self._active_versions.get(rule_id) or self._version_history.get(rule_id, ["1.0.0"])[-1]
            key = (rule_id, v)
            rule = self._rules.get(key)
            if not rule:
                raise RuleValidationError(f"Rule '{rule_id}' v{v} not found")

            dep_rule = DetectionRule(
                rule_id=rule.rule_id,
                version=rule.version,
                name=rule.name,
                description=rule.description,
                severity=rule.severity,
                conditions=rule.conditions,
                threshold=rule.threshold,
                state=RuleState.DEPRECATED,
                tenant_id=rule.tenant_id,
                mitre_attack=rule.mitre_attack,
                confidence=rule.confidence,
                base_risk=rule.base_risk,
                tags=rule.tags,
            )
            self._rules[key] = dep_rule
            if self._active_versions.get(rule_id) == v:
                del self._active_versions[rule_id]
            return dep_rule

    def get_rule_state(self, rule_id: str, version: str | None = None) -> RuleState:
        """Get lifecycle state of a rule."""
        rule = self.get_rule(rule_id, version)
        if not rule:
            raise RuleValidationError(f"Rule '{rule_id}' not found")
        return rule.state

    def list_rules(self) -> list[DetectionRule]:
        """List all unique registered rules (latest version)."""
        with self._lock:
            res: list[DetectionRule] = []
            for rule_id, history in self._version_history.items():
                if history:
                    latest_ver = history[-1]
                    r = self._rules.get((rule_id, latest_ver))
                    if r:
                        res.append(r)
            return res

    def rollback_rule(self, rule_id: str) -> DetectionRule:
        """Roll back an active rule to its immediately preceding version."""
        with self._lock:
            history = self._version_history.get(rule_id, [])
            if len(history) < 2:
                raise RuleValidationError(f"Cannot rollback rule '{rule_id}': no prior version exists")

            curr_ver = self._active_versions.get(rule_id)
            try:
                curr_idx = history.index(curr_ver) if curr_ver else len(history) - 1
            except ValueError:
                curr_idx = len(history) - 1

            if curr_idx <= 0:
                raise RuleValidationError(f"Cannot rollback rule '{rule_id}': already at oldest version")

            target_version = history[curr_idx - 1]
            old_rule = self._rules[(rule_id, target_version)]
            reverted = DetectionRule(
                rule_id=old_rule.rule_id,
                version=old_rule.version,
                name=old_rule.name,
                description=old_rule.description,
                severity=old_rule.severity,
                conditions=old_rule.conditions,
                threshold=old_rule.threshold,
                state=RuleState.ACTIVE,
                tenant_id=old_rule.tenant_id,
                mitre_attack=old_rule.mitre_attack,
                confidence=old_rule.confidence,
                base_risk=old_rule.base_risk,
                tags=old_rule.tags,
            )
            self._rules[(rule_id, target_version)] = reverted
            self._active_versions[rule_id] = target_version
            return reverted

    def get_rule(self, rule_id: str, version: str | None = None) -> DetectionRule | None:
        """Retrieve a rule by id and version (or current active/latest version)."""
        with self._lock:
            v = version or self._active_versions.get(rule_id)
            if not v:
                history = self._version_history.get(rule_id)
                if history:
                    v = history[-1]
            if not v:
                return None
            return self._rules.get((rule_id, v))

    def get_active_rules(self, tenant_id: str | None = None) -> list[DetectionRule]:
        """Return all currently active rules matching optional tenant scope."""
        with self._lock:
            rules: list[DetectionRule] = []
            for rule_id, ver in self._active_versions.items():
                r = self._rules.get((rule_id, ver))
                if r and r.state == RuleState.ACTIVE:
                    if r.tenant_id is None or r.tenant_id == tenant_id:
                        rules.append(r)
            return rules
