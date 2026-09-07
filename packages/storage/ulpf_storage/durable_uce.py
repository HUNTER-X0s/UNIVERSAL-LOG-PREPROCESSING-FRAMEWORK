"""ULPF Phase 7 — Durable UCE Repository backed by relational database.

Enforces:
- Rule B2: Write-once immutability; database-level trigger rejects UPDATE
- Rule B3: Parameterized queries only
- Rule 1: UCE remains canonical source of truth
"""

from __future__ import annotations

import json
from typing import Any

from ulpf_runtime.errors import PersistenceError

from ulpf_storage.database.relational import DatabaseError, SQLiteDatabase
from ulpf_storage.interfaces import UCERecord, UCERepository


class DurableUCERepository(UCERepository):
    """Production UCE repository backed by SQLite with write-once enforcement.

    The schema-level trigger (trg_uce_no_update) rejects any UPDATE so
    immutability is enforced at the database layer, not just application code.
    """

    def __init__(self, db: SQLiteDatabase) -> None:
        self._db = db

    def put(self, record: UCERecord) -> None:
        if self.exists(record.uce_event_id):
            raise PersistenceError(
                f"UCE {record.uce_event_id} already exists. In-place mutation prohibited."
            )
        try:
            with self._db.transaction():
                self._db.execute(
                    """INSERT INTO uce_records
                       (uce_event_id, raw_event_id, raw_sha256, payload_json,
                        schema_version, source_id, captured_at, stored_at, metadata_json)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        record.uce_event_id,
                        record.raw_event_id,
                        record.raw_sha256,
                        json.dumps(record.payload, separators=(",", ":")),
                        record.schema_version,
                        record.source_id,
                        record.captured_at,
                        record.stored_at,
                        json.dumps(record.metadata, separators=(",", ":")),
                    ),
                )
        except DatabaseError as exc:
            raise PersistenceError(f"UCE persistence failed: {exc}") from exc

    def get(self, uce_event_id: str) -> UCERecord | None:
        rows = self._db.execute(
            "SELECT * FROM uce_records WHERE uce_event_id = ?", (uce_event_id,)
        )
        if not rows:
            return None
        return self._row_to_record(rows[0])

    def exists(self, uce_event_id: str) -> bool:
        try:
            rows = self._db.execute(
                "SELECT 1 FROM uce_records WHERE uce_event_id = ? LIMIT 1",
                (uce_event_id,),
            )
            return len(rows) > 0
        except DatabaseError as exc:
            raise PersistenceError(f"UCE exists check failed: {exc}") from exc

    def query_by_raw_id(self, raw_event_id: str) -> list[UCERecord]:
        rows = self._db.execute(
            "SELECT * FROM uce_records WHERE raw_event_id = ? ORDER BY stored_at",
            (raw_event_id,),
        )
        return [self._row_to_record(r) for r in rows]

    @staticmethod
    def _row_to_record(row: dict[str, Any]) -> UCERecord:
        return UCERecord(
            uce_event_id=row["uce_event_id"],
            raw_event_id=row["raw_event_id"],
            raw_sha256=row["raw_sha256"],
            payload=json.loads(row["payload_json"]),
            schema_version=row["schema_version"],
            source_id=row["source_id"],
            captured_at=row["captured_at"],
            stored_at=row["stored_at"],
            metadata=json.loads(row["metadata_json"]),
        )
