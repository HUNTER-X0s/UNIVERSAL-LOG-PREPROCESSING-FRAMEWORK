"""In-memory storage repository implementations for ULPF Phase 6.

Enforces:
- Rule 1: UCE remains canonical source of truth; updates forbidden
- Rule 2: Raw evidence immutable; overwrite forbidden
- Fast local test execution and air-gapped dev runtime
"""

import hashlib
import threading
from datetime import UTC, datetime
from typing import Any

from ulpf_runtime.errors import PersistenceError, StorageIntegrityError
from ulpf_runtime.models import AuditActionRecord, DeliveryIntent

from ulpf_storage.interfaces import (
    AuditRepository,
    OutboxRepository,
    RawEvidenceRecord,
    RawEvidenceRepository,
    SemanticEventRepository,
    StoredSemanticEvent,
    UCERecord,
    UCERepository,
)


class MemoryRawEvidenceRepository(RawEvidenceRepository):
    """In-memory raw evidence store with cryptographic verification."""

    def __init__(self) -> None:
        self._records: dict[str, RawEvidenceRecord] = {}
        self._payloads: dict[str, bytes] = {}
        self._lock = threading.Lock()

    def put(
        self,
        raw_event_id: str,
        payload: bytes,
        source_id: str,
        format_str: str,
        metadata: dict[str, Any] | None = None,
    ) -> RawEvidenceRecord:
        with self._lock:
            if raw_event_id in self._records:
                raise PersistenceError(
                    f"Raw evidence {raw_event_id} already exists. Overwrite forbidden."
                )

            sha256_hex = hashlib.sha256(payload).hexdigest()
            record = RawEvidenceRecord(
                raw_event_id=raw_event_id,
                sha256=sha256_hex,
                captured_at=datetime.now(UTC).isoformat(),
                source_id=source_id,
                format=format_str,
                byte_length=len(payload),
                storage_path=f"memory://raw/{raw_event_id}",
                metadata=metadata or {},
            )
            self._records[raw_event_id] = record
            self._payloads[raw_event_id] = payload
            return record

    def get(self, raw_event_id: str) -> tuple[RawEvidenceRecord, bytes]:
        with self._lock:
            if raw_event_id not in self._records:
                raise PersistenceError(f"Raw evidence {raw_event_id} not found")
            rec = self._records[raw_event_id]
            payload = self._payloads[raw_event_id]

            actual_sha = hashlib.sha256(payload).hexdigest()
            if actual_sha != rec.sha256:
                raise StorageIntegrityError(f"Integrity check failed for {raw_event_id}")

            return rec, payload

    def exists(self, raw_event_id: str) -> bool:
        with self._lock:
            return raw_event_id in self._records

    def verify(self, raw_event_id: str) -> bool:
        try:
            self.get(raw_event_id)
            return True
        except (PersistenceError, StorageIntegrityError):
            return False

    def get_metadata(self, raw_event_id: str) -> RawEvidenceRecord | None:
        with self._lock:
            return self._records.get(raw_event_id)


class MemoryUCERepository(UCERepository):
    """In-memory UCE store with strict write-once semantics."""

    def __init__(self) -> None:
        self._records: dict[str, UCERecord] = {}
        self._raw_index: dict[str, list[str]] = {}
        self._lock = threading.Lock()

    def put(self, record: UCERecord) -> None:
        with self._lock:
            if record.uce_event_id in self._records:
                raise PersistenceError(
                    f"UCE {record.uce_event_id} already exists. In-place mutation prohibited."
                )
            self._records[record.uce_event_id] = record
            self._raw_index.setdefault(record.raw_event_id, []).append(record.uce_event_id)

    def get(self, uce_event_id: str) -> UCERecord | None:
        with self._lock:
            return self._records.get(uce_event_id)

    def exists(self, uce_event_id: str) -> bool:
        with self._lock:
            return uce_event_id in self._records

    def query_by_raw_id(self, raw_event_id: str) -> list[UCERecord]:
        with self._lock:
            ids = self._raw_index.get(raw_event_id, [])
            return [self._records[i] for i in ids if i in self._records]


class MemorySemanticEventRepository(SemanticEventRepository):
    """In-memory SemanticEvent repository with multi-attribute filtering."""

    def __init__(self) -> None:
        self._events: dict[str, StoredSemanticEvent] = {}
        self._order: list[str] = []
        self._lock = threading.Lock()

    def put(self, event: StoredSemanticEvent) -> None:
        with self._lock:
            self._events[event.semantic_event_id] = event
            if event.semantic_event_id not in self._order:
                self._order.append(event.semantic_event_id)

    def get(self, semantic_event_id: str) -> StoredSemanticEvent | None:
        with self._lock:
            return self._events.get(semantic_event_id)

    def query(
        self,
        source_id: str | None = None,
        vendor: str | None = None,
        risk_level: str | None = None,
        fingerprint: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[StoredSemanticEvent]:
        with self._lock:
            matched: list[StoredSemanticEvent] = []
            for eid in self._order:
                ev = self._events[eid]
                if risk_level and ev.risk_level != risk_level:
                    continue
                if fingerprint and ev.fingerprint != fingerprint:
                    continue
                if vendor and ev.classification.get("vendor") != vendor:
                    continue
                matched.append(ev)

            return matched[offset : offset + limit]


class MemoryOutboxRepository(OutboxRepository):
    """In-memory outbox delivery intent store."""

    def __init__(self) -> None:
        self._intents: dict[str, DeliveryIntent] = {}
        self._lock = threading.Lock()

    def save_intent(self, intent: DeliveryIntent) -> None:
        with self._lock:
            self._intents[intent.intent_id] = intent

    def get_pending(self, limit: int = 100) -> list[DeliveryIntent]:
        with self._lock:
            pending = [i for i in self._intents.values() if i.status == "PENDING"]
            return pending[:limit]

    def mark_delivered(self, intent_id: str) -> None:
        with self._lock:
            if intent_id in self._intents:
                cur = self._intents[intent_id]
                self._intents[intent_id] = DeliveryIntent(
                    intent_id=cur.intent_id,
                    event_id=cur.event_id,
                    sink_name=cur.sink_name,
                    payload_type=cur.payload_type,
                    payload=cur.payload,
                    created_at=cur.created_at,
                    attempt_count=cur.attempt_count + 1,
                    max_attempts=cur.max_attempts,
                    status="DELIVERED",
                    last_attempt_at=datetime.now(UTC).isoformat(),
                    last_error=None,
                )

    def mark_failed(self, intent_id: str, error: str) -> None:
        with self._lock:
            if intent_id in self._intents:
                cur = self._intents[intent_id]
                new_attempts = cur.attempt_count + 1
                new_status = "DLQ" if new_attempts >= cur.max_attempts else "PENDING"
                self._intents[intent_id] = DeliveryIntent(
                    intent_id=cur.intent_id,
                    event_id=cur.event_id,
                    sink_name=cur.sink_name,
                    payload_type=cur.payload_type,
                    payload=cur.payload,
                    created_at=cur.created_at,
                    attempt_count=new_attempts,
                    max_attempts=cur.max_attempts,
                    status=new_status,
                    last_attempt_at=datetime.now(UTC).isoformat(),
                    last_error=error,
                )


class MemoryAuditRepository(AuditRepository):
    """In-memory administrative action audit trail."""

    def __init__(self) -> None:
        self._actions: list[AuditActionRecord] = []
        self._lock = threading.Lock()

    def record_action(self, action: AuditActionRecord) -> None:
        with self._lock:
            self._actions.append(action)

    def list_actions(self, limit: int = 100, offset: int = 0) -> list[AuditActionRecord]:
        with self._lock:
            return self._actions[offset : offset + limit]
