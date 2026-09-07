"""Phase 8 — Relational Detection Repository.

Durable storage for detection events backed by SQLiteDatabase/RelationalDatabase.
"""

from __future__ import annotations

import json
from typing import Any

from ulpf_storage.database.relational import RelationalDatabase

from ulpf_intelligence.models.events import DetectionEvent, DetectionEvidence
from ulpf_intelligence.models.provenance import AlertSeverity, AlertStatus, IntelligenceProvenance


class DetectionRepository:
    """Repository for persisting and querying DetectionEvent instances."""

    def __init__(self, db: RelationalDatabase) -> None:
        self._db = db

    def save(self, detection: DetectionEvent) -> None:
        """Insert or replace a detection event."""
        sql = """
            INSERT OR REPLACE INTO intelligence_detections (
                detection_id, tenant_id, rule_id, rule_version, severity,
                title, description, status, entity_ids, evidence,
                provenance, mitre_tactics, mitre_techniques, detected_at, indexed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            detection.detection_id,
            detection.tenant_id,
            detection.rule_id,
            detection.rule_version,
            detection.severity.value,
            detection.title,
            detection.description,
            detection.status.value,
            json.dumps(detection.entity_ids),
            json.dumps(detection.evidence.to_dict()),
            json.dumps(detection.provenance.to_dict()),
            json.dumps(detection.mitre_tactics),
            json.dumps(detection.mitre_techniques),
            detection.detected_at,
            detection.indexed_at,
        )
        self._db.execute(sql, params)

    def get(self, detection_id: str, tenant_id: str | None = None) -> DetectionEvent | None:
        """Retrieve a detection event by ID and optional tenant scope."""
        if tenant_id:
            sql = "SELECT * FROM intelligence_detections WHERE detection_id = ? AND tenant_id = ?"
            rows = self._db.execute(sql, (detection_id, tenant_id))
        else:
            sql = "SELECT * FROM intelligence_detections WHERE detection_id = ?"
            rows = self._db.execute(sql, (detection_id,))

        if not rows:
            return None
        return self._row_to_detection(rows[0])

    def list(
        self,
        tenant_id: str,
        limit: int = 100,
        severity: AlertSeverity | None = None,
        rule_id: str | None = None,
    ) -> list[DetectionEvent]:
        """List detections for a tenant with optional filtering."""
        clauses = ["tenant_id = ?"]
        params: list[Any] = [tenant_id]

        if severity is not None:
            clauses.append("severity = ?")
            params.append(severity.value)

        if rule_id is not None:
            clauses.append("rule_id = ?")
            params.append(rule_id)

        params.append(limit)
        sql = f"SELECT * FROM intelligence_detections WHERE {' AND '.join(clauses)} ORDER BY detected_at DESC LIMIT ?"  # noqa: S608
        rows = self._db.execute(sql, tuple(params))
        return [self._row_to_detection(r) for r in rows]

    def count(self, tenant_id: str) -> int:
        """Count total detections for a tenant."""
        sql = "SELECT COUNT(*) as cnt FROM intelligence_detections WHERE tenant_id = ?"
        rows = self._db.execute(sql, (tenant_id,))
        return int(rows[0]["cnt"]) if rows else 0

    @staticmethod
    def _row_to_detection(row: dict[str, Any]) -> DetectionEvent:
        evidence_dict = json.loads(row["evidence"])
        evidence = DetectionEvidence(
            matched_event_ids=evidence_dict.get("matched_event_ids", []),
            raw_hashes=evidence_dict.get("raw_hashes", []),
            trigger_field=evidence_dict.get("trigger_field", ""),
            trigger_value=evidence_dict.get("trigger_value"),
            observed_count=evidence_dict.get("observed_count", 1),
            time_window_seconds=evidence_dict.get("time_window_seconds", 0),
        )
        prov_dict = json.loads(row["provenance"])
        provenance = IntelligenceProvenance(
            source_events=prov_dict.get("source_events", []),
            source_rules=prov_dict.get("source_rules", []),
            source_models=prov_dict.get("source_models", []),
            derivation_method=prov_dict.get("derivation_method", "DETERMINISTIC"),
            generated_by=prov_dict.get("generated_by", "DETECTION_ENGINE"),
            generated_at=prov_dict.get("generated_at", ""),
            is_derived=prov_dict.get("is_derived", True),
            is_mutable=prov_dict.get("is_mutable", False),
        )
        return DetectionEvent(
            detection_id=row["detection_id"],
            tenant_id=row["tenant_id"],
            rule_id=row["rule_id"],
            rule_version=row["rule_version"],
            severity=AlertSeverity(row["severity"]),
            title=row["title"],
            description=row["description"],
            status=AlertStatus(row["status"]),
            entity_ids=json.loads(row["entity_ids"]),
            evidence=evidence,
            provenance=provenance,
            mitre_tactics=json.loads(row["mitre_tactics"]),
            mitre_techniques=json.loads(row["mitre_techniques"]),
            detected_at=row["detected_at"],
            indexed_at=row["indexed_at"],
        )
