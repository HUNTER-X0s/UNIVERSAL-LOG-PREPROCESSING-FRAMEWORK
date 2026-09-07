"""Phase 8 — Relational Correlation Repository.

Durable storage for correlation groups backed by RelationalDatabase.
"""

from __future__ import annotations

import json
from typing import Any

from ulpf_storage.database.relational import RelationalDatabase

from ulpf_intelligence.models.events import CorrelationGroup


class CorrelationRepository:
    """Repository for persisting and querying CorrelationGroup instances."""

    def __init__(self, db: RelationalDatabase) -> None:
        self._db = db

    def save(self, group: CorrelationGroup) -> None:
        """Insert or replace a correlation group."""
        sql = """
            INSERT OR REPLACE INTO intelligence_correlations (
                group_id, tenant_id, title, correlation_type, detection_ids,
                primary_entity_id, aggregated_risk, status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            group.group_id,
            group.tenant_id,
            group.title,
            group.correlation_type,
            json.dumps(group.detection_ids),
            group.primary_entity_id,
            group.aggregated_risk,
            group.status,
            group.created_at,
            group.updated_at,
        )
        self._db.execute(sql, params)

    def get(self, group_id: str, tenant_id: str | None = None) -> CorrelationGroup | None:
        """Retrieve a correlation group by ID."""
        if tenant_id:
            sql = "SELECT * FROM intelligence_correlations WHERE group_id = ? AND tenant_id = ?"
            rows = self._db.execute(sql, (group_id, tenant_id))
        else:
            sql = "SELECT * FROM intelligence_correlations WHERE group_id = ?"
            rows = self._db.execute(sql, (group_id,))

        if not rows:
            return None
        return self._row_to_group(rows[0])

    def list(self, tenant_id: str, limit: int = 100) -> list[CorrelationGroup]:
        """List correlation groups for a tenant."""
        sql = "SELECT * FROM intelligence_correlations WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ?"
        rows = self._db.execute(sql, (tenant_id, limit))
        return [self._row_to_group(r) for r in rows]

    @staticmethod
    def _row_to_group(row: dict[str, Any]) -> CorrelationGroup:
        return CorrelationGroup(
            group_id=row["group_id"],
            tenant_id=row["tenant_id"],
            title=row["title"],
            correlation_type=row["correlation_type"],
            detection_ids=json.loads(row["detection_ids"]),
            primary_entity_id=row["primary_entity_id"],
            aggregated_risk=float(row["aggregated_risk"]),
            status=row["status"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
