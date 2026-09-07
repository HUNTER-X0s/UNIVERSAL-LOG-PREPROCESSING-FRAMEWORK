"""Phase 8 — Relational Rule Repository.

Durable storage for detection rules backed by RelationalDatabase.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from ulpf_storage.database.relational import RelationalDatabase

from ulpf_intelligence.models.provenance import AlertSeverity, RuleState
from ulpf_intelligence.rules.dsl import DetectionRule, RuleCondition, RuleOperator, RuleThreshold


class RuleRepository:
    """Repository for persisting and loading DetectionRule definitions."""

    def __init__(self, db: RelationalDatabase) -> None:
        self._db = db

    def save(self, rule: DetectionRule, state: RuleState = RuleState.DRAFT) -> None:
        """Insert or update a rule definition and its lifecycle state."""
        sql = """
            INSERT OR REPLACE INTO intelligence_rules (
                rule_id, rule_version, name, description, severity,
                state, rule_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        now = datetime.now(UTC).isoformat()
        params = (
            rule.rule_id,
            rule.version,
            rule.name,
            rule.description,
            rule.severity.value,
            state.value,
            json.dumps(rule.to_dict()),
            now,
            now,
        )
        self._db.execute(sql, params)

    def update_state(self, rule_id: str, state: RuleState) -> bool:
        """Update the lifecycle state of a rule."""
        now = datetime.now(UTC).isoformat()
        sql = "UPDATE intelligence_rules SET state = ?, updated_at = ? WHERE rule_id = ?"
        self._db.execute(sql, (state.value, now, rule_id))
        return True

    def get(self, rule_id: str) -> tuple[DetectionRule, RuleState] | None:
        """Retrieve a rule and its current state."""
        sql = "SELECT * FROM intelligence_rules WHERE rule_id = ?"
        rows = self._db.execute(sql, (rule_id,))
        if not rows:
            return None
        return self._row_to_rule(rows[0])

    def list(self, state: RuleState | None = None) -> list[tuple[DetectionRule, RuleState]]:
        """List rules, optionally filtered by state."""
        if state is not None:
            sql = "SELECT * FROM intelligence_rules WHERE state = ? ORDER BY rule_id ASC"
            rows = self._db.execute(sql, (state.value,))
        else:
            sql = "SELECT * FROM intelligence_rules ORDER BY rule_id ASC"
            rows = self._db.execute(sql, ())
        return [self._row_to_rule(r) for r in rows]

    @staticmethod
    def _row_to_rule(row: dict[str, Any]) -> tuple[DetectionRule, RuleState]:
        data = json.loads(row["rule_json"])
        conditions = [
            RuleCondition(
                field=c["field"],
                operator=RuleOperator(c["operator"]),
                value=c["value"],
            )
            for c in data.get("conditions", [])
        ]
        threshold = None
        if data.get("threshold"):
            th = data["threshold"]
            threshold = RuleThreshold(
                count=th["count"],
                window_seconds=th["window_seconds"],
                group_by_fields=th.get("group_by_fields", []),
            )
        rule = DetectionRule(
            rule_id=data["rule_id"],
            name=data["name"],
            description=data["description"],
            severity=AlertSeverity(data["severity"]),
            conditions=tuple(conditions),
            threshold=threshold,
            mitre_tactics=tuple(data.get("mitre_tactics", [])),
            mitre_techniques=tuple(data.get("mitre_techniques", [])),
            tags=tuple(data.get("tags", [])),
            version=data.get("version", "1.0.0"),
            enabled=data.get("enabled", True),
        )
        return rule, RuleState(row["state"])
