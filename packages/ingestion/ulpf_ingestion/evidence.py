"""Bounded local evidence sinks for Phase 2 development and deterministic tests."""

import json
import os
import stat
import tempfile
from hashlib import sha256
from pathlib import Path
from threading import Lock
from types import MappingProxyType
from uuid import UUID

from ulpf_ingestion.models import (
    EvidenceRecord,
    RawEventEnvelope,
    RawEvidenceReference,
    StoredRawEvent,
)


class EvidenceError(RuntimeError):
    """Base class for local evidence-store failures."""


class EvidenceCapacityError(EvidenceError):
    """The bounded local store cannot accept another complete payload."""


class EvidenceIntegrityError(EvidenceError):
    """Stored bytes do not match their receipt fingerprint."""


class EvidenceNotFoundError(EvidenceError):
    """No stored evidence matches the requested event ID."""


def _validated_event_id(event_id: str) -> str:
    """Accept only generated UUID event IDs before forming a filesystem path."""
    return str(UUID(event_id))


class InMemoryRawEventSink:
    """Test-only bounded sink. It never evicts an accepted event."""

    def __init__(self, maximum_events: int = 100, maximum_bytes: int = 1_048_576) -> None:
        self._maximum_events = maximum_events
        self._maximum_bytes = maximum_bytes
        self._events: dict[str, StoredRawEvent] = {}
        self._payloads: dict[str, bytes] = {}
        self._used_bytes = 0
        self._lock = Lock()

    def store(self, envelope: RawEventEnvelope) -> StoredRawEvent:
        """Retain exact bytes until explicitly discarded with the whole test sink."""
        with self._lock:
            if len(self._events) >= self._maximum_events:
                raise EvidenceCapacityError("In-memory evidence event capacity is exhausted.")
            if self._used_bytes + envelope.payload_length > self._maximum_bytes:
                raise EvidenceCapacityError("In-memory evidence byte capacity is exhausted.")
            artifact = RawEvidenceReference(
                uri=f"memory-evidence://raw/{envelope.event_id}",
                sha256=envelope.payload_sha256,
                byte_length=envelope.payload_length,
            )
            stored = StoredRawEvent(
                envelope=envelope,
                artifact=artifact,
                raw_event_contract=MappingProxyType(envelope.raw_event_contract(artifact)),
            )
            self._events[envelope.event_id] = stored
            self._payloads[envelope.event_id] = envelope.payload
            self._used_bytes += envelope.payload_length
            return stored

    def retrieve(self, event_id: str) -> EvidenceRecord:
        """Return exact test bytes after independently checking their SHA-256 value."""
        with self._lock:
            stored = self._events.get(event_id)
            payload = self._payloads.get(event_id)
        if stored is None or payload is None:
            raise EvidenceNotFoundError("Evidence record was not found.")
        if sha256(payload).hexdigest() != stored.artifact.sha256:
            raise EvidenceIntegrityError("Evidence hash verification failed.")
        receipt = {
            "event_id": stored.envelope.event_id,
            "receipt_id": stored.envelope.receipt_id,
            "request_id": stored.envelope.request_id,
            "correlation_id": stored.envelope.correlation_id,
            "trace_id": stored.envelope.trace_id,
        }
        return EvidenceRecord(payload, stored.raw_event_contract, MappingProxyType(receipt))


class LocalFileRawEventSink:
    """Local development fallback, never a substitute for the approved object store."""

    def __init__(self, root: Path, maximum_events: int, maximum_bytes: int) -> None:
        self._root = root
        self._maximum_events = maximum_events
        self._maximum_bytes = maximum_bytes
        self._lock = Lock()
        self._event_count: int | None = None
        self._used_bytes: int | None = None

    def store(self, envelope: RawEventEnvelope) -> StoredRawEvent:
        """Atomically write payload then receipt metadata; never overwrite an event."""
        event_id = _validated_event_id(envelope.event_id)
        with self._lock:
            self._ensure_usage_loaded()
            event_count = self._event_count
            used_bytes = self._used_bytes
            if event_count is None or used_bytes is None:
                raise EvidenceError("Local evidence usage state is unavailable.")
            if event_count >= self._maximum_events:
                raise EvidenceCapacityError("Local evidence event capacity is exhausted.")
            if used_bytes + envelope.payload_length > self._maximum_bytes:
                raise EvidenceCapacityError("Local evidence byte capacity is exhausted.")

            payload_path, metadata_path = self._paths(event_id)
            if payload_path.exists() or metadata_path.exists():
                raise EvidenceError("Generated evidence event ID already exists.")

            artifact = RawEvidenceReference(
                uri=f"local-evidence://raw/{event_id}",
                sha256=envelope.payload_sha256,
                byte_length=envelope.payload_length,
            )
            raw_event_contract = envelope.raw_event_contract(artifact)
            self._write_atomically(payload_path, envelope.payload)
            metadata = {
                "raw_event_contract": raw_event_contract,
                "receipt": {
                    "event_id": event_id,
                    "receipt_id": envelope.receipt_id,
                    "request_id": envelope.request_id,
                    "correlation_id": envelope.correlation_id,
                    "trace_id": envelope.trace_id,
                    "transport": {
                        "protocol": envelope.transport.protocol.value,
                        "intake_id": envelope.transport.intake_id,
                        "peer_address": envelope.transport.peer_address,
                        "listener_address": envelope.transport.listener_address,
                    },
                },
            }
            self._write_atomically(
                metadata_path,
                json.dumps(metadata, separators=(",", ":"), sort_keys=True).encode("utf-8"),
            )
            self._event_count = event_count + 1
            self._used_bytes = used_bytes + envelope.payload_length
            return StoredRawEvent(
                envelope=envelope,
                artifact=artifact,
                raw_event_contract=MappingProxyType(raw_event_contract),
            )

    def retrieve(self, event_id: str) -> EvidenceRecord:
        """Read an opaque payload and verify it before returning it to a caller."""
        normalized_id = _validated_event_id(event_id)
        payload_path, metadata_path = self._paths(normalized_id)
        if not payload_path.is_file() or not metadata_path.is_file():
            raise EvidenceNotFoundError("Evidence record was not found.")
        payload = payload_path.read_bytes()
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            raw_event_contract = metadata["raw_event_contract"]
            receipt = metadata["receipt"]
            expected_hash = raw_event_contract["payload"]["sha256"]
            expected_length = raw_event_contract["payload"]["byte_length"]
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise EvidenceIntegrityError("Evidence metadata is invalid.") from exc
        if len(payload) != expected_length or sha256(payload).hexdigest() != expected_hash:
            raise EvidenceIntegrityError("Evidence hash verification failed.")
        return EvidenceRecord(
            payload=payload,
            raw_event_contract=MappingProxyType(raw_event_contract),
            receipt_metadata=MappingProxyType(receipt),
        )

    def _ensure_usage_loaded(self) -> None:
        """Load bounded store usage once; metadata records define accepted receipts."""
        if self._event_count is not None:
            return
        self._root.mkdir(parents=True, exist_ok=True)
        records = list(self._root.glob("*.json"))
        used_bytes = 0
        for metadata_path in records:
            payload_path = metadata_path.with_suffix(".raw")
            if payload_path.is_file():
                used_bytes += payload_path.stat().st_size
        self._event_count = len(records)
        self._used_bytes = used_bytes

    def _paths(self, event_id: str) -> tuple[Path, Path]:
        """Return opaque, generated raw and receipt paths below the configured root."""
        return self._root / f"{event_id}.raw", self._root / f"{event_id}.json"

    def _write_atomically(self, destination: Path, content: bytes) -> None:
        """Write and fsync a new local evidence artifact without in-place mutation."""
        self._root.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".receipt-", suffix=".tmp", dir=self._root
        )
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as temporary_file:
                temporary_file.write(content)
                temporary_file.flush()
                os.fsync(temporary_file.fileno())
            os.replace(temporary_path, destination)
            destination.chmod(stat.S_IREAD)
        except Exception:
            if temporary_path.exists():
                temporary_path.unlink()
            raise
