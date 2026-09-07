"""Relational SQLite Repository for Operational Alerts in ULPF Phase 9."""

from __future__ import annotations

import json
from typing import Any

from ulpf_storage.database.relational import SQLiteDatabase

from ulpf_advanced_intelligence.models.alerts import (
    AlertLifecycleStatus,
    AlertRecord,
    AlertTriageSeverity,
)


class AlertRepository:
    """Durable relational persistence for primary alerts and triage decisions."""

    def __init__(self, db: SQLiteDatabase) -> None:
        self._db = db

    def save(self, alert: AlertRecord) -> None:
        sql = """
        INSERT OR REPLACE INTO advanced_alerts (
            alert_id, title, description, severity, status, tenant_id,
            primary_entity_id, entity_ids_json, detection_ids_json,
            anomaly_ids_json, ti_match_ids_json, risk_score, fingerprint,
            created_at, updated_at, assignee, triage_reason, contributing_factors_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            alert.alert_id,
            alert.title,
            alert.description,
            alert.severity.value,
            alert.status.value,
            alert.tenant_id,
            alert.primary_entity_id,
            json.dumps(list(alert.entity_ids)),
            json.dumps(list(alert.detection_ids)),
            json.dumps(list(alert.anomaly_ids)),
            json.dumps(list(alert.ti_match_ids)),
            alert.risk_score,
            alert.fingerprint,
            alert.created_at,
            alert.updated_at,
            alert.assignee,
            alert.triage_reason,
            json.dumps(list(alert.contributing_factors)),
        )
        self._db.execute(sql, params)

    def get(self, alert_id: str) -> AlertRecord | None:
        sql = "SELECT * FROM advanced_alerts WHERE alert_id = ?"
        rows = self._db.execute(sql, (alert_id,))
        if not rows:
            return None
        return self._row_to_alert(rows[0])

    def query(
        self,
        tenant_id: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        limit: int = 100,
    ) -> list[AlertRecord]:
        clauses: list[str] = ["1=1"]
        params: list[Any] = []

        if tenant_id is not None:
            clauses.append("tenant_id = ?")
            params.append(tenant_id)
        if severity is not None:
            clauses.append("severity = ?")
            params.append(severity)
        if status is not None:
            clauses.append("status = ?")
            params.append(status)

        params.append(limit)
        sql = f"SELECT * FROM advanced_alerts WHERE {' AND '.join(clauses)} ORDER BY created_at DESC LIMIT ?"  # noqa: S608
        rows = self._db.execute(sql, tuple(params))
        return [self._row_to_alert(r) for r in rows]

    @staticmethod
    def _row_to_alert(row: dict[str, Any]) -> AlertRecord:
        return AlertRecord(
            alert_id=row["alert_id"],
            title=row["title"],
            description=row["description"],
            severity=AlertTriageSeverity(row["severity"]),
            status=AlertLifecycleStatus(row["status"]),
            tenant_id=row["tenant_id"],
            primary_entity_id=row["primary_entity_id"] or "",
            entity_ids=tuple(json.loads(row["entity_ids_json"] or "[]")),
            detection_ids=tuple(json.loads(row["detection_ids_json"] or "[]")),
            anomaly_ids=tuple(json.loads(row["anomaly_ids_json"] or "[]")),
            ti_match_ids=tuple(json.loads(row["ti_match_ids_json"] or "[]")),
            risk_score=float(row["risk_score"]),
            fingerprint=row["fingerprint"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            assignee=row["assignee"],
            triage_reason=row["triage_reason"] or "",
            contributing_factors=tuple(json.loads(row["contributing_factors_json"] or "[]")),
        )
