"""ULPF Phase 7 — Durable Semantic Event Repository backed by relational database.

Enforces:
- Rule B3: Parameterized queries only
- Rule 4: Multi-attribute filtering (source, vendor, risk, fingerprint)
"""

from __future__ import annotations

import json
from typing import Any

from ulpf_runtime.errors import PersistenceError

from ulpf_storage.database.relational import DatabaseError, SQLiteDatabase
from ulpf_storage.interfaces import SemanticEventRepository, StoredSemanticEvent


class DurableSemanticEventRepository(SemanticEventRepository):
    """Production SemanticEvent repository backed by SQLite."""

    def __init__(self, db: SQLiteDatabase) -> None:
        self._db = db

    def put(self, event: StoredSemanticEvent) -> None:
        try:
            with self._db.transaction():
                self._db.execute(
                    """INSERT OR REPLACE INTO semantic_events
                       (semantic_event_id, uce_event_id, raw_sha256, mapping_version,
                        semantic_version, payload_json, fingerprint, risk_level, risk_score,
                        entities_json, indicators_json, classification_json, stored_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        event.semantic_event_id,
                        event.uce_event_id,
                        event.raw_sha256,
                        event.mapping_version,
                        event.semantic_version,
                        json.dumps(event.payload, separators=(",", ":")),
                        event.fingerprint,
                        event.risk_level,
                        event.risk_score,
                        json.dumps(event.entities, separators=(",", ":")),
                        json.dumps(event.indicators, separators=(",", ":")),
                        json.dumps(event.classification, separators=(",", ":")),
                        event.stored_at,
                    ),
                )
        except DatabaseError as exc:
            raise PersistenceError(f"Semantic event persistence failed: {exc}") from exc

    def get(self, semantic_event_id: str) -> StoredSemanticEvent | None:
        rows = self._db.execute(
            "SELECT * FROM semantic_events WHERE semantic_event_id = ?",
            (semantic_event_id,),
        )
        if not rows:
            return None
        return self._row_to_event(rows[0])

    def query(
        self,
        source_id: str | None = None,
        vendor: str | None = None,
        risk_level: str | None = None,
        fingerprint: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[StoredSemanticEvent]:
        # Build parameterized WHERE clauses for deterministic fields
        clauses: list[str] = []
        params: list[Any] = []

        if risk_level is not None:
            clauses.append("risk_level = ?")
            params.append(risk_level)
        if fingerprint is not None:
            clauses.append("fingerprint = ?")
            params.append(fingerprint)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT * FROM semantic_events {where} ORDER BY stored_at LIMIT ? OFFSET ?"  # noqa: S608
        params.extend([limit, offset])

        rows = self._db.execute(sql, tuple(params))
        events = [self._row_to_event(r) for r in rows]

        # Post-filter for vendor (stored inside JSON classification_json)
        if vendor is not None:
            events = [e for e in events if e.classification.get("vendor") == vendor]

        # Post-filter for source_id (stored inside JSON payload)
        if source_id is not None:
            events = [e for e in events if e.payload.get("source_id") == source_id]

        return events

    @staticmethod
    def _row_to_event(row: dict[str, Any]) -> StoredSemanticEvent:
        return StoredSemanticEvent(
            semantic_event_id=row["semantic_event_id"],
            uce_event_id=row["uce_event_id"],
            raw_sha256=row["raw_sha256"],
            mapping_version=row["mapping_version"],
            semantic_version=row["semantic_version"],
            payload=json.loads(row["payload_json"]),
            fingerprint=row["fingerprint"],
            risk_level=row["risk_level"],
            risk_score=float(row["risk_score"]),
            entities=json.loads(row["entities_json"]),
            indicators=json.loads(row["indicators_json"]),
            classification=json.loads(row["classification_json"]),
            stored_at=row["stored_at"],
        )
