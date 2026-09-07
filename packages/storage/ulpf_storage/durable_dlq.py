"""ULPF Phase 7 — Durable Dead Letter Queue Manager backed by relational database.

Enforces:
- Rule 11: DLQ entries never silently dropped; persisted durably
- Rule B6: Database-backed DLQ survives process restart
"""

from __future__ import annotations

from typing import Any

from ulpf_runtime.errors import PersistenceError

from ulpf_storage.database.relational import DatabaseError, SQLiteDatabase


class DurableDLQEntry:
    """A durable dead-letter queue entry."""

    __slots__ = (
        "entry_id",
        "raw_event_id",
        "reason",
        "error_detail",
        "raw_payload_hex",
        "source_id",
        "queued_at",
        "retry_count",
        "status",
    )

    def __init__(
        self,
        entry_id: str,
        raw_event_id: str,
        reason: str,
        error_detail: str,
        raw_payload_hex: str,
        source_id: str,
        queued_at: str,
        retry_count: int = 0,
        status: str = "QUEUED",
    ) -> None:
        self.entry_id = entry_id
        self.raw_event_id = raw_event_id
        self.reason = reason
        self.error_detail = error_detail
        self.raw_payload_hex = raw_payload_hex
        self.source_id = source_id
        self.queued_at = queued_at
        self.retry_count = retry_count
        self.status = status


class DurableDLQManager:
    """Durable DLQ backed by a dedicated table in the relational database."""

    _INIT_SQL = """CREATE TABLE IF NOT EXISTS dlq_entries (
        entry_id        TEXT    PRIMARY KEY,
        raw_event_id    TEXT    NOT NULL,
        reason          TEXT    NOT NULL,
        error_detail    TEXT    NOT NULL,
        raw_payload_hex TEXT    NOT NULL,
        source_id       TEXT    NOT NULL,
        queued_at       TEXT    NOT NULL,
        retry_count     INTEGER NOT NULL DEFAULT 0,
        status          TEXT    NOT NULL DEFAULT 'QUEUED'
    )"""

    def __init__(self, db: SQLiteDatabase) -> None:
        self._db = db
        # Ensure DLQ table exists (created outside migration system for simplicity)
        with self._db.transaction():
            self._db.execute(self._INIT_SQL)

    def enqueue(self, entry: DurableDLQEntry) -> None:
        try:
            with self._db.transaction():
                self._db.execute(
                    """INSERT OR IGNORE INTO dlq_entries
                       (entry_id, raw_event_id, reason, error_detail, raw_payload_hex,
                        source_id, queued_at, retry_count, status)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        entry.entry_id,
                        entry.raw_event_id,
                        entry.reason,
                        entry.error_detail,
                        entry.raw_payload_hex,
                        entry.source_id,
                        entry.queued_at,
                        entry.retry_count,
                        entry.status,
                    ),
                )
        except DatabaseError as exc:
            raise PersistenceError(f"DLQ enqueue failed: {exc}") from exc

    def get_queued(self, limit: int = 100) -> list[DurableDLQEntry]:
        rows = self._db.execute(
            "SELECT * FROM dlq_entries WHERE status = 'QUEUED' ORDER BY queued_at LIMIT ?",
            (limit,),
        )
        return [self._row_to_entry(r) for r in rows]

    def count(self) -> int:
        rows = self._db.execute("SELECT COUNT(*) AS cnt FROM dlq_entries WHERE status = 'QUEUED'")
        return int(rows[0]["cnt"]) if rows else 0

    def mark_replayed(self, entry_id: str) -> None:
        try:
            with self._db.transaction():
                self._db.execute(
                    "UPDATE dlq_entries SET status = 'REPLAYED' WHERE entry_id = ?",
                    (entry_id,),
                )
        except DatabaseError as exc:
            raise PersistenceError(f"DLQ mark-replayed failed: {exc}") from exc

    def mark_poison(self, entry_id: str) -> None:
        """Mark an entry as permanently poisoned (will not be retried)."""
        try:
            with self._db.transaction():
                self._db.execute(
                    "UPDATE dlq_entries SET status = 'POISON' WHERE entry_id = ?",
                    (entry_id,),
                )
        except DatabaseError as exc:
            raise PersistenceError(f"DLQ mark-poison failed: {exc}") from exc

    @staticmethod
    def _row_to_entry(row: dict[str, Any]) -> DurableDLQEntry:
        return DurableDLQEntry(
            entry_id=row["entry_id"],
            raw_event_id=row["raw_event_id"],
            reason=row["reason"],
            error_detail=row["error_detail"],
            raw_payload_hex=row["raw_payload_hex"],
            source_id=row["source_id"],
            queued_at=row["queued_at"],
            retry_count=int(row["retry_count"]),
            status=row["status"],
        )
