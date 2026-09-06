"""Dead Letter Queue (DLQ) contract and manager for ULPF Phase 6.

Enforces:
- Rule 8: No silent data loss
- Rule 23/24: Poison-event handling without stream stalling
- Raw evidence references remain accessible
"""

import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass(frozen=True)
class DLQRecord:
    """Immutable dead letter record containing full forensic error context."""

    dlq_id: str
    original_event_id: str
    stage: str
    error_type: str
    error_message: str
    retry_count: int
    timestamp: str
    source_id: str
    raw_sha256: str
    correlation_id: str | None = None
    mapping_version: str | None = None
    raw_evidence_ref: str | None = None
    payload_preview: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    replayed: bool = False


class DLQManager:
    """Thread-safe Dead Letter Queue coordinator with bounded in-memory capacity."""

    def __init__(self, max_capacity: int = 10_000) -> None:
        if max_capacity <= 0:
            raise ValueError("max_capacity must be positive")
        self._max_capacity = max_capacity
        self._records: dict[str, DLQRecord] = {}
        self._order: list[str] = []
        self._lock = threading.Lock()

    def record_failure(
        self,
        original_event_id: str,
        stage: str,
        error: Exception,
        retry_count: int,
        source_id: str,
        raw_sha256: str,
        correlation_id: str | None = None,
        mapping_version: str | None = None,
        raw_evidence_ref: str | None = None,
        payload_preview: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> DLQRecord:
        """Route an unrecoverable or exhausted event to DLQ with full forensic context."""
        with self._lock:
            dlq_id = f"dlq-{original_event_id}-{int(datetime.now(UTC).timestamp() * 1000)}"

            # Evict oldest if max capacity reached
            if len(self._records) >= self._max_capacity and self._order:
                oldest_id = self._order.pop(0)
                self._records.pop(oldest_id, None)

            # Sanitize preview length to prevent memory bloat
            preview = (
                (payload_preview[:500] + "...")
                if payload_preview and len(payload_preview) > 500
                else payload_preview
            )

            rec = DLQRecord(
                dlq_id=dlq_id,
                original_event_id=original_event_id,
                stage=stage,
                error_type=type(error).__name__,
                error_message=str(error),
                retry_count=retry_count,
                timestamp=datetime.now(UTC).isoformat(),
                source_id=source_id,
                raw_sha256=raw_sha256,
                correlation_id=correlation_id,
                mapping_version=mapping_version,
                raw_evidence_ref=raw_evidence_ref,
                payload_preview=preview,
                metadata=metadata or {},
                replayed=False,
            )
            self._records[dlq_id] = rec
            self._order.append(dlq_id)
            return rec

    def get(self, dlq_id: str) -> DLQRecord | None:
        with self._lock:
            return self._records.get(dlq_id)

    def mark_replayed(self, dlq_id: str) -> bool:
        with self._lock:
            if dlq_id in self._records:
                cur = self._records[dlq_id]
                self._records[dlq_id] = DLQRecord(
                    dlq_id=cur.dlq_id,
                    original_event_id=cur.original_event_id,
                    stage=cur.stage,
                    error_type=cur.error_type,
                    error_message=cur.error_message,
                    retry_count=cur.retry_count,
                    timestamp=cur.timestamp,
                    source_id=cur.source_id,
                    raw_sha256=cur.raw_sha256,
                    correlation_id=cur.correlation_id,
                    mapping_version=cur.mapping_version,
                    raw_evidence_ref=cur.raw_evidence_ref,
                    payload_preview=cur.payload_preview,
                    metadata=cur.metadata,
                    replayed=True,
                )
                return True
            return False

    def list_records(self, limit: int = 100, offset: int = 0) -> list[DLQRecord]:
        with self._lock:
            keys = self._order[offset : offset + limit]
            return [self._records[k] for k in keys if k in self._records]

    def count(self) -> int:
        with self._lock:
            return len(self._records)
