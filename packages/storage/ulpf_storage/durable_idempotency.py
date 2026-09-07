"""ULPF Phase 7 — Durable Idempotency Guard backed by relational database.

Enforces:
- Rule 12: Fingerprint deduplication backed by unique database UNIQUE constraint
- Rule B7: Idempotency survives process restart
- No silent acceptance of duplicate events
"""

from __future__ import annotations

from datetime import UTC, datetime

from ulpf_storage.database.relational import SQLiteDatabase


class DuplicateEventError(Exception):
    """Raised when a duplicate fingerprint is detected."""


class DurableIdempotencyGuard:
    """Durable fingerprint-based idempotency guard backed by SQLite.

    The unique constraint on the idempotency_keys table enforces deduplication
    at the database layer, making it crash-safe and restart-safe.
    """

    def __init__(self, db: SQLiteDatabase) -> None:
        self._db = db

    def check_and_register(self, fingerprint: str, event_id: str) -> bool:
        """Attempt to register a fingerprint atomically.

        Returns True if this is a new (unique) event.
        Raises DuplicateEventError if the fingerprint already exists.
        """
        try:
            with self._db.transaction():
                self._db.execute(
                    """INSERT INTO idempotency_keys (fingerprint, event_id, first_seen_at)
                       VALUES (?, ?, ?)""",
                    (fingerprint, event_id, datetime.now(UTC).isoformat()),
                )
            return True
        except Exception as exc:
            # SQLite UNIQUE constraint violation surfaces as an OperationalError
            # or IntegrityError depending on the driver version
            exc_str = str(exc).lower()
            if "unique" in exc_str or "constraint" in exc_str:
                raise DuplicateEventError(
                    f"Duplicate fingerprint detected: {fingerprint}"
                ) from exc
            raise

    def is_known(self, fingerprint: str) -> bool:
        """Return True if the fingerprint has already been seen."""
        rows = self._db.execute(
            "SELECT 1 FROM idempotency_keys WHERE fingerprint = ? LIMIT 1",
            (fingerprint,),
        )
        return len(rows) > 0

    def count(self) -> int:
        """Return total number of registered idempotency keys."""
        rows = self._db.execute("SELECT COUNT(*) AS cnt FROM idempotency_keys")
        return int(rows[0]["cnt"]) if rows else 0
