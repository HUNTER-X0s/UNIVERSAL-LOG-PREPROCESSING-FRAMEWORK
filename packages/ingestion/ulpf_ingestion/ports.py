"""Ports that keep raw capture independent from transports and future streaming."""

from typing import Protocol

from ulpf_ingestion.models import (
    EvidenceRecord,
    RawEventEnvelope,
    SourceContext,
    StoredRawEvent,
    TransportMetadata,
)


class SourceResolver(Protocol):
    """Resolve configured transport identity without inspecting raw payloads."""

    def resolve(self, transport: TransportMetadata) -> SourceContext:
        """Return a known or explicitly unresolved source context."""


class RawEventSink(Protocol):
    """Persist an opaque receipt before it is acknowledged to a source."""

    def store(self, envelope: RawEventEnvelope) -> StoredRawEvent:
        """Store exact bytes and receipt metadata, or raise without acknowledgement."""

    def retrieve(self, event_id: str) -> EvidenceRecord:
        """Retrieve bytes and verify their stored integrity fingerprint."""
