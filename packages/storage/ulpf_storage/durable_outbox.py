"""ULPF Phase 7 — Durable Outbox Repository backed by relational database.

Enforces:
- Rule B5: Durable outbox survives process restart (SQLite-backed)
- Rule B6: Atomic status transitions
- Rule 10: Outbox intents never silently lost
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from ulpf_runtime.errors import PersistenceError
from ulpf_runtime.models import DeliveryIntent

from ulpf_storage.database.relational import DatabaseError, SQLiteDatabase
from ulpf_storage.interfaces import OutboxRepository


class DurableOutboxRepository(OutboxRepository):
    """Production outbox repository backed by SQLite; survives process restart."""

    def __init__(self, db: SQLiteDatabase) -> None:
        self._db = db

    def save_intent(self, intent: DeliveryIntent) -> None:
        try:
            with self._db.transaction():
                self._db.execute(
                    """INSERT OR IGNORE INTO outbox_records
                       (intent_id, event_id, sink_name, payload_type, payload_json,
                        created_at, attempt_count, max_attempts, status,
                        last_attempt_at, last_error)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        intent.intent_id,
                        intent.event_id,
                        intent.sink_name,
                        intent.payload_type,
                        json.dumps(intent.payload, separators=(",", ":")),
                        intent.created_at,
                        intent.attempt_count,
                        intent.max_attempts,
                        intent.status,
                        intent.last_attempt_at,
                        intent.last_error,
                    ),
                )
        except DatabaseError as exc:
            raise PersistenceError(f"Outbox persistence failed: {exc}") from exc

    def get_pending(self, limit: int = 100) -> list[DeliveryIntent]:
        rows = self._db.execute(
            "SELECT * FROM outbox_records WHERE status = 'PENDING' "
            "ORDER BY created_at LIMIT ?",
            (limit,),
        )
        return [self._row_to_intent(r) for r in rows]

    def mark_delivered(self, intent_id: str) -> None:
        try:
            with self._db.transaction():
                self._db.execute(
                    """UPDATE outbox_records
                       SET status = 'DELIVERED',
                           last_attempt_at = ?,
                           attempt_count = attempt_count + 1,
                           last_error = NULL
                       WHERE intent_id = ?""",
                    (datetime.now(UTC).isoformat(), intent_id),
                )
        except DatabaseError as exc:
            raise PersistenceError(f"Outbox mark-delivered failed: {exc}") from exc

    def mark_failed(self, intent_id: str, error: str) -> None:
        try:
            with self._db.transaction():
                # Increment attempt count and compute new status atomically
                self._db.execute(
                    """UPDATE outbox_records
                       SET attempt_count = attempt_count + 1,
                           last_attempt_at = ?,
                           last_error = ?,
                           status = CASE
                               WHEN attempt_count + 1 >= max_attempts THEN 'DLQ'
                               ELSE 'PENDING'
                           END
                       WHERE intent_id = ?""",
                    (datetime.now(UTC).isoformat(), error, intent_id),
                )
        except DatabaseError as exc:
            raise PersistenceError(f"Outbox mark-failed failed: {exc}") from exc

    @staticmethod
    def _row_to_intent(row: dict[str, Any]) -> DeliveryIntent:
        return DeliveryIntent(
            intent_id=row["intent_id"],
            event_id=row["event_id"],
            sink_name=row["sink_name"],
            payload_type=row["payload_type"],
            payload=json.loads(row["payload_json"]),
            created_at=row["created_at"],
            attempt_count=int(row["attempt_count"]),
            max_attempts=int(row["max_attempts"]),
            status=row["status"],
            last_attempt_at=row.get("last_attempt_at"),
            last_error=row.get("last_error"),
        )
