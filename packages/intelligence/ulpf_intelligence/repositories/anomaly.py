"""Phase 8 — Relational Anomaly Repository.

Durable storage for statistical anomaly events backed by RelationalDatabase.
"""

from __future__ import annotations

from typing import Any

from ulpf_storage.database.relational import RelationalDatabase

from ulpf_intelligence.models.events import AnomalyEvent
from ulpf_intelligence.models.provenance import AlertSeverity


class AnomalyRepository:
    """Repository for persisting and querying AnomalyEvent instances."""

    def __init__(self, db: RelationalDatabase) -> None:
        self._db = db

    def save(self, anomaly: AnomalyEvent) -> None:
        """Insert or replace an anomaly event."""
        sql = """
            INSERT OR REPLACE INTO intelligence_anomalies (
                anomaly_id, tenant_id, entity_id, metric_name, observed_value,
                baseline_mean, baseline_std, z_score, severity, detected_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            anomaly.anomaly_id,
            anomaly.tenant_id,
            anomaly.entity_id,
            anomaly.metric_name,
            anomaly.observed_value,
            anomaly.baseline_mean,
            anomaly.baseline_std,
            anomaly.z_score,
            anomaly.severity.value,
            anomaly.detected_at,
        )
        self._db.execute(sql, params)

    def get(self, anomaly_id: str, tenant_id: str | None = None) -> AnomalyEvent | None:
        """Retrieve an anomaly event by ID."""
        if tenant_id:
            sql = "SELECT * FROM intelligence_anomalies WHERE anomaly_id = ? AND tenant_id = ?"
            rows = self._db.execute(sql, (anomaly_id, tenant_id))
        else:
            sql = "SELECT * FROM intelligence_anomalies WHERE anomaly_id = ?"
            rows = self._db.execute(sql, (anomaly_id,))

        if not rows:
            return None
        return self._row_to_anomaly(rows[0])

    def list(
        self,
        tenant_id: str,
        entity_id: str | None = None,
        limit: int = 100,
    ) -> list[AnomalyEvent]:
        """List anomaly events for a tenant."""
        if entity_id:
            sql = (
                "SELECT * FROM intelligence_anomalies WHERE tenant_id = ? AND entity_id = ? "
                "ORDER BY detected_at DESC LIMIT ?"
            )
            rows = self._db.execute(sql, (tenant_id, entity_id, limit))
        else:
            sql = (
                "SELECT * FROM intelligence_anomalies WHERE tenant_id = ? "
                "ORDER BY detected_at DESC LIMIT ?"
            )
            rows = self._db.execute(sql, (tenant_id, limit))
        return [self._row_to_anomaly(r) for r in rows]

    @staticmethod
    def _row_to_anomaly(row: dict[str, Any]) -> AnomalyEvent:
        return AnomalyEvent(
            anomaly_id=row["anomaly_id"],
            tenant_id=row["tenant_id"],
            entity_id=row["entity_id"],
            metric_name=row["metric_name"],
            observed_value=float(row["observed_value"]),
            baseline_mean=float(row["baseline_mean"]),
            baseline_std=float(row["baseline_std"]),
            z_score=float(row["z_score"]),
            severity=AlertSeverity(row["severity"]),
            detected_at=row["detected_at"],
        )
