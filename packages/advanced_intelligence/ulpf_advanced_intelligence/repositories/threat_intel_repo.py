"""Relational SQLite Repository for Threat Intelligence Indicators in ULPF Phase 9."""

from __future__ import annotations

import json
from typing import Any

from ulpf_storage.database.relational import SQLiteDatabase

from ulpf_advanced_intelligence.models.threat_intel import (
    ObservableType,
    ThreatIntelConfidence,
    ThreatIntelIndicator,
    ThreatIntelLifecycleState,
    ThreatIntelStatus,
)


class ThreatIntelRepository:
    """Durable relational persistence for Threat Intelligence indicators."""

    def __init__(self, db: SQLiteDatabase) -> None:
        self._db = db

    def save(self, indicator: ThreatIntelIndicator) -> None:
        """Insert or replace an indicator record."""
        sql = """
        INSERT OR REPLACE INTO advanced_ti_indicators (
            indicator_id, type, normalized_value, source, source_version,
            confidence_json, first_seen, last_seen, valid_from, valid_until,
            status, lifecycle_state, provenance, integrity_hash, tenant_id,
            created_at, tags_json, description
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            indicator.indicator_id,
            indicator.type.value,
            indicator.normalized_value,
            indicator.source,
            indicator.source_version,
            json.dumps(indicator.confidence.to_dict()),
            indicator.first_seen,
            indicator.last_seen,
            indicator.valid_from,
            indicator.valid_until,
            indicator.status.value,
            indicator.lifecycle_state.value,
            indicator.provenance,
            indicator.integrity_hash,
            indicator.tenant_id,
            indicator.created_at,
            json.dumps(list(indicator.tags)),
            indicator.description,
        )
        self._db.execute(sql, params)

    def get(self, indicator_id: str) -> ThreatIntelIndicator | None:
        sql = "SELECT * FROM advanced_ti_indicators WHERE indicator_id = ?"
        rows = self._db.execute(sql, (indicator_id,))
        if not rows:
            return None
        return self._row_to_indicator(rows[0])

    def query(
        self,
        tenant_id: str | None = None,
        type_str: str | None = None,
        limit: int = 100,
    ) -> list[ThreatIntelIndicator]:
        clauses: list[str] = ["1=1"]
        params: list[Any] = []

        if tenant_id is not None:
            clauses.append("(tenant_id = ? OR tenant_id IS NULL)")
            params.append(tenant_id)
        if type_str is not None:
            clauses.append("type = ?")
            params.append(type_str)

        params.append(limit)
        sql = f"SELECT * FROM advanced_ti_indicators WHERE {' AND '.join(clauses)} ORDER BY created_at DESC LIMIT ?"  # noqa: S608
        rows = self._db.execute(sql, tuple(params))
        return [self._row_to_indicator(r) for r in rows]

    @staticmethod
    def _row_to_indicator(row: dict[str, Any]) -> ThreatIntelIndicator:
        c_dict = json.loads(row["confidence_json"])
        conf = ThreatIntelConfidence(
            source_confidence=c_dict.get("source_confidence", 0.8),
            indicator_confidence=c_dict.get("indicator_confidence", 0.8),
            match_confidence=c_dict.get("match_confidence", 1.0),
            risk_contribution=c_dict.get("risk_contribution", 25.0),
        )
        tags = tuple(json.loads(row["tags_json"] or "[]"))
        return ThreatIntelIndicator(
            indicator_id=row["indicator_id"],
            type=ObservableType(row["type"]),
            normalized_value=row["normalized_value"],
            source=row["source"],
            source_version=row["source_version"],
            confidence=conf,
            first_seen=row["first_seen"] or "",
            last_seen=row["last_seen"] or "",
            valid_from=row["valid_from"] or "",
            valid_until=row["valid_until"] or "",
            status=ThreatIntelStatus(row["status"]),
            lifecycle_state=ThreatIntelLifecycleState(row["lifecycle_state"]),
            provenance=row["provenance"],
            integrity_hash=row["integrity_hash"],
            tenant_id=row["tenant_id"],
            created_at=row["created_at"],
            tags=tags,
            description=row["description"] or "",
        )
