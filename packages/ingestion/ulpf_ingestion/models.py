"""Opaque raw-capture models that precede parsing and normalization."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType


class TransportProtocol(StrEnum):
    """Transport labels with bounded operational cardinality."""

    HTTP = "http"
    TCP = "tcp"
    UDP = "udp"
    FILE = "file"


class IntakeStatus(StrEnum):
    """States that Phase 2 can truthfully expose."""

    CAPTURED = "captured"
    REJECTED = "rejected"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class SourceContext:
    """Transport-derived source resolution without payload inspection."""

    source_id: str = "unknown"
    known: bool = False


@dataclass(frozen=True, slots=True)
class TransportMetadata:
    """Bounded context supplied by an adapter, never parsed from payload bytes."""

    protocol: TransportProtocol
    intake_id: str
    peer_address: str | None = None
    listener_address: str | None = None
    content_type: str | None = None
    details: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "details", MappingProxyType(dict(self.details)))

    def contract_transport(self) -> dict[str, object]:
        """Return only fields supported by the frozen RawEvent transport contract."""
        transport: dict[str, object] = {
            "protocol": self.protocol.value,
            "listener_id": self.intake_id,
        }
        if self.peer_address is not None:
            transport["peer_address"] = self.peer_address
        if self.content_type is not None:
            transport["headers"] = {"content-type": self.content_type}
        return transport


@dataclass(frozen=True, slots=True)
class RawCaptureInput:
    """An opaque payload plus receipt context supplied by one transport adapter."""

    payload: bytes = field(repr=False)
    transport: TransportMetadata
    request_id: str
    correlation_id: str
    trace_id: str


@dataclass(frozen=True, slots=True)
class RawEventEnvelope:
    """Internal receipt envelope; payload bytes remain authoritative evidence."""

    contract_version: str
    event_id: str
    receipt_id: str
    source: SourceContext
    received_at: datetime
    transport: TransportMetadata
    payload: bytes = field(repr=False)
    payload_sha256: str
    request_id: str
    correlation_id: str
    trace_id: str
    status: IntakeStatus = IntakeStatus.CAPTURED

    @property
    def payload_length(self) -> int:
        """Return the exact number of stored bytes."""
        return len(self.payload)

    def raw_event_contract(self, artifact: "RawEvidenceReference") -> dict[str, object]:
        """Project the receipt into the existing frozen RawEvent JSON Schema."""
        payload: dict[str, object] = {
            "uri": artifact.uri,
            "sha256": artifact.sha256,
            "byte_length": artifact.byte_length,
            "encoding": "binary",
        }
        if self.transport.content_type is not None:
            payload["media_type"] = self.transport.content_type
        document: dict[str, object] = {
            "contract_version": self.contract_version,
            "raw_event_id": self.event_id,
            "source_id": self.source.source_id,
            "received_at": self.received_at.astimezone(UTC).isoformat(),
            "ingested_at": self.received_at.astimezone(UTC).isoformat(),
            "payload": payload,
            "transport": self.transport.contract_transport(),
            "integrity": {
                "payload_sha256": self.payload_sha256,
                "capture_status": "complete",
            },
            "labels": {
                "source_resolution": "known" if self.source.known else "unresolved",
                "receipt_id": self.receipt_id,
            },
        }
        return document


@dataclass(frozen=True, slots=True)
class RawEvidenceReference:
    """Immutable-reference-shaped evidence location returned by a sink."""

    uri: str
    sha256: str
    byte_length: int


@dataclass(frozen=True, slots=True)
class StoredRawEvent:
    """Result of an evidence write, before any future queue handoff."""

    envelope: RawEventEnvelope
    artifact: RawEvidenceReference
    raw_event_contract: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    """Byte-for-byte evidence retrieval result used by tests and development tooling."""

    payload: bytes = field(repr=False)
    raw_event_contract: Mapping[str, object]
    receipt_metadata: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class CaptureAcknowledgement:
    """Accurate HTTP/client acknowledgement for a completed evidence receipt."""

    event_id: str
    receipt_id: str
    received_at: datetime
    status: IntakeStatus
    request_id: str
    correlation_id: str
    trace_id: str
