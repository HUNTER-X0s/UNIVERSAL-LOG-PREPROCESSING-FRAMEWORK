"""Idempotency and duplicate detection for ULPF Phase 6.

Enforces:
- Rule 26: At-least-once delivery must not cause uncontrolled semantic duplication.
- Rule 21/22: Distinguish transport duplicates from distinct events with identical content.
"""

import hashlib
import threading
from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass(frozen=True)
class IdempotencyRecord:
    """Stored execution record for a deduplication key."""

    key: str
    event_id: str
    raw_sha256: str
    first_seen_at: str
    attempt_count: int = 1
    last_state: str = "PROCESSED"
    semantic_event_id: str | None = None


class IdempotencyGuard:
    """Bounded, thread-safe deduplication guard.

    Prevents duplicate processing under at-least-once transport semantics.
    Enforces bounded memory size with FIFO eviction when max entries is reached.
    """

    def __init__(self, max_entries: int = 50_000) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        self._max_entries = max_entries
        self._records: dict[str, IdempotencyRecord] = {}
        self._order: list[str] = []
        self._lock = threading.Lock()

    @staticmethod
    def generate_key(
        source_id: str, raw_sha256: str, transport_message_id: str | None = None
    ) -> str:
        """Generate a deterministic transport idempotency key.

        Uses transport_message_id if provided; otherwise combines source_id + raw_sha256.
        """
        raw_key = f"{source_id}:{raw_sha256}:{transport_message_id or ''}"
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    def check_and_record(
        self,
        key: str,
        event_id: str,
        raw_sha256: str,
    ) -> tuple[bool, IdempotencyRecord | None]:
        """Check if an event was already processed.

        Returns:
            (is_duplicate, existing_record)
            If False, the key is recorded as pending/processed.
        """
        with self._lock:
            if key in self._records:
                existing = self._records[key]
                updated = IdempotencyRecord(
                    key=existing.key,
                    event_id=existing.event_id,
                    raw_sha256=existing.raw_sha256,
                    first_seen_at=existing.first_seen_at,
                    attempt_count=existing.attempt_count + 1,
                    last_state=existing.last_state,
                    semantic_event_id=existing.semantic_event_id,
                )
                self._records[key] = updated
                return True, updated

            # Evict oldest entry if bounded limit reached
            if len(self._records) >= self._max_entries and self._order:
                oldest_key = self._order.pop(0)
                self._records.pop(oldest_key, None)

            record = IdempotencyRecord(
                key=key,
                event_id=event_id,
                raw_sha256=raw_sha256,
                first_seen_at=datetime.now(UTC).isoformat(),
                attempt_count=1,
                last_state="PROCESSING",
            )
            self._records[key] = record
            self._order.append(key)
            return False, None

    def update_result(self, key: str, semantic_event_id: str, state: str = "PROCESSED") -> None:
        """Update result on successful processing."""
        with self._lock:
            if key in self._records:
                cur = self._records[key]
                self._records[key] = IdempotencyRecord(
                    key=cur.key,
                    event_id=cur.event_id,
                    raw_sha256=cur.raw_sha256,
                    first_seen_at=cur.first_seen_at,
                    attempt_count=cur.attempt_count,
                    last_state=state,
                    semantic_event_id=semantic_event_id,
                )

    def size(self) -> int:
        with self._lock:
            return len(self._records)

    def clear(self) -> None:
        with self._lock:
            self._records.clear()
            self._order.clear()
