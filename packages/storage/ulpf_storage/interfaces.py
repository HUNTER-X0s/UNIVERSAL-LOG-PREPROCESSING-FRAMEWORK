"""Storage repository interfaces and contracts for ULPF Phase 6.

Enforces:
- Rule 1: UCE remains canonical source of truth
- Rule 2: Raw evidence remains immutable
- Rule 8/9/10: No silent data loss or overwrites
- Rule 13/14: Repository interfaces / ports
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from ulpf_runtime.models import AuditActionRecord, DeliveryIntent


@dataclass(frozen=True)
class RawEvidenceRecord:
    """Forensic metadata for stored raw evidence."""

    raw_event_id: str
    sha256: str
    captured_at: str
    source_id: str
    format: str
    byte_length: int
    storage_path: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class UCERecord:
    """Stored immutable UCE canonical event."""

    uce_event_id: str
    raw_event_id: str
    raw_sha256: str
    payload: dict[str, Any]
    schema_version: str
    source_id: str
    captured_at: str
    stored_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class StoredSemanticEvent:
    """Stored semantic event with extracted intelligence and lineage."""

    semantic_event_id: str
    uce_event_id: str
    raw_sha256: str
    mapping_version: str | None
    semantic_version: str
    payload: dict[str, Any]
    fingerprint: str
    risk_level: str
    risk_score: float
    entities: list[dict[str, Any]]
    indicators: list[dict[str, Any]]
    classification: dict[str, Any]
    stored_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


class RawEvidenceRepository(ABC):
    """Port for immutable raw evidence persistence and integrity verification."""

    @abstractmethod
    def put(
        self,
        raw_event_id: str,
        payload: bytes,
        source_id: str,
        format_str: str,
        metadata: dict[str, Any] | None = None,
    ) -> RawEvidenceRecord: ...

    @abstractmethod
    def get(self, raw_event_id: str) -> tuple[RawEvidenceRecord, bytes]: ...

    @abstractmethod
    def exists(self, raw_event_id: str) -> bool: ...

    @abstractmethod
    def verify(self, raw_event_id: str) -> bool:
        """Verify stored raw evidence against its recorded SHA-256."""
        ...

    @abstractmethod
    def get_metadata(self, raw_event_id: str) -> RawEvidenceRecord | None: ...


class UCERepository(ABC):
    """Port for canonical UCE persistence. Updates prohibited; write-once."""

    @abstractmethod
    def put(self, record: UCERecord) -> None: ...

    @abstractmethod
    def get(self, uce_event_id: str) -> UCERecord | None: ...

    @abstractmethod
    def exists(self, uce_event_id: str) -> bool: ...

    @abstractmethod
    def query_by_raw_id(self, raw_event_id: str) -> list[UCERecord]: ...


class SemanticEventRepository(ABC):
    """Port for SemanticEvent persistence with multi-dimensional querying."""

    @abstractmethod
    def put(self, event: StoredSemanticEvent) -> None: ...

    @abstractmethod
    def get(self, semantic_event_id: str) -> StoredSemanticEvent | None: ...

    @abstractmethod
    def query(
        self,
        source_id: str | None = None,
        vendor: str | None = None,
        risk_level: str | None = None,
        fingerprint: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[StoredSemanticEvent]: ...


class OutboxRepository(ABC):
    """Port for reliable downstream delivery intents."""

    @abstractmethod
    def save_intent(self, intent: DeliveryIntent) -> None: ...

    @abstractmethod
    def get_pending(self, limit: int = 100) -> list[DeliveryIntent]: ...

    @abstractmethod
    def mark_delivered(self, intent_id: str) -> None: ...

    @abstractmethod
    def mark_failed(self, intent_id: str, error: str) -> None: ...


class AuditRepository(ABC):
    """Port for administrative and operational audit trail persistence."""

    @abstractmethod
    def record_action(self, action: AuditActionRecord) -> None: ...

    @abstractmethod
    def list_actions(self, limit: int = 100, offset: int = 0) -> list[AuditActionRecord]: ...
