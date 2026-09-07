"""Phase 8 — Relational Case Repository.

Durable storage for investigation cases, analyst notes, and timelines backed by RelationalDatabase.
"""

from __future__ import annotations

import json
from typing import Any

from ulpf_storage.database.relational import RelationalDatabase

from ulpf_intelligence.models.events import AnalystNote, InvestigationCase, TimelineEntry
from ulpf_intelligence.models.provenance import AlertSeverity, CaseStatus


class CaseRepository:
    """Repository for persisting and querying InvestigationCase instances."""

    def __init__(self, db: RelationalDatabase) -> None:
        self._db = db

    def save(self, case: InvestigationCase) -> None:
        """Insert or replace an investigation case."""
        sql = """
            INSERT OR REPLACE INTO intelligence_cases (
                case_id, tenant_id, title, severity, status,
                assignee, detection_ids, entity_ids, timeline, notes,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        timeline_json = json.dumps([t.to_dict() for t in case.timeline])
        notes_json = json.dumps([n.to_dict() for n in case.notes])

        params = (
            case.case_id,
            case.tenant_id,
            case.title,
            case.severity.value,
            case.status.value,
            case.assignee,
            json.dumps(case.detection_ids),
            json.dumps(case.entity_ids),
            timeline_json,
            notes_json,
            case.created_at,
            case.updated_at,
        )
        self._db.execute(sql, params)

    def get(self, case_id: str, tenant_id: str | None = None) -> InvestigationCase | None:
        """Retrieve an investigation case by ID."""
        if tenant_id:
            sql = "SELECT * FROM intelligence_cases WHERE case_id = ? AND tenant_id = ?"
            rows = self._db.execute(sql, (case_id, tenant_id))
        else:
            sql = "SELECT * FROM intelligence_cases WHERE case_id = ?"
            rows = self._db.execute(sql, (case_id,))

        if not rows:
            return None
        return self._row_to_case(rows[0])

    def list(
        self,
        tenant_id: str,
        status: CaseStatus | None = None,
        limit: int = 100,
    ) -> list[InvestigationCase]:
        """List investigation cases for a tenant with optional status filter."""
        clauses = ["tenant_id = ?"]
        params: list[Any] = [tenant_id]

        if status is not None:
            clauses.append("status = ?")
            params.append(status.value)

        params.append(limit)
        sql = f"SELECT * FROM intelligence_cases WHERE {' AND '.join(clauses)} ORDER BY updated_at DESC LIMIT ?"  # noqa: S608
        rows = self._db.execute(sql, tuple(params))
        return [self._row_to_case(r) for r in rows]

    @staticmethod
    def _row_to_case(row: dict[str, Any]) -> InvestigationCase:
        raw_timeline = json.loads(row["timeline"])
        timeline = [
            TimelineEntry(
                entry_id=t["entry_id"],
                timestamp=t["timestamp"],
                event_type=t["event_type"],
                source_id=t["source_id"],
                summary=t["summary"],
                details=t.get("details", {}),
            )
            for t in raw_timeline
        ]
        raw_notes = json.loads(row["notes"])
        notes = [
            AnalystNote(
                note_id=n["note_id"],
                author=n["author"],
                content=n["content"],
                created_at=n["created_at"],
            )
            for n in raw_notes
        ]
        return InvestigationCase(
            case_id=row["case_id"],
            tenant_id=row["tenant_id"],
            title=row["title"],
            severity=AlertSeverity(row["severity"]),
            status=CaseStatus(row["status"]),
            assignee=row["assignee"],
            detection_ids=json.loads(row["detection_ids"]),
            entity_ids=json.loads(row["entity_ids"]),
            timeline=timeline,
            notes=notes,
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
