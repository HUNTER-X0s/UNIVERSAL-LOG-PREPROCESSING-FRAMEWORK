"""Central raw-capture service; it never interprets payload content."""

from datetime import UTC, datetime
from hashlib import sha256
from uuid import uuid4

from ulpf_contracts.registry import ContractRegistry
from ulpf_platform.logging import get_logger

from ulpf_ingestion.metrics import IntakeMetrics
from ulpf_ingestion.models import (
    CaptureAcknowledgement,
    RawCaptureInput,
    RawEventEnvelope,
    SourceContext,
    TransportMetadata,
)
from ulpf_ingestion.ports import RawEventSink, SourceResolver


class IntakeError(RuntimeError):
    """Base error with a safe code for a refused or failed raw receipt."""

    code = "intake_capture_failure"


class PayloadTooLargeError(IntakeError):
    """Raised before a payload can be accepted in full."""

    code = "intake_payload_too_large"


class CaptureContractError(IntakeError):
    """Raised when a stored receipt cannot satisfy the frozen RawEvent contract."""

    code = "intake_capture_failure"


class UnknownSourceResolver:
    """Safe default: unknown sources are captured without payload-based inference."""

    def resolve(self, transport: TransportMetadata) -> SourceContext:
        """Return an explicit unresolved source for every transport."""
        del transport
        return SourceContext()


class RawCaptureService:
    """Assign IDs, hash exact bytes, persist evidence, and form a raw receipt."""

    def __init__(
        self,
        sink: RawEventSink,
        metrics: IntakeMetrics,
        maximum_event_bytes: int,
        source_resolver: SourceResolver | None = None,
        registry: ContractRegistry | None = None,
    ) -> None:
        self._sink = sink
        self._metrics = metrics
        self._maximum_event_bytes = maximum_event_bytes
        self._source_resolver = source_resolver or UnknownSourceResolver()
        self._registry = registry or ContractRegistry()
        self._logger = get_logger("ingestion.capture")

    def capture(self, capture_input: RawCaptureInput) -> CaptureAcknowledgement:
        """Capture one opaque payload or reject it without truncation."""
        payload = capture_input.payload
        if len(payload) > self._maximum_event_bytes:
            self._metrics.increment("rejected", capture_input.transport.protocol)
            raise PayloadTooLargeError("Payload exceeds the configured event limit.")

        received_at = datetime.now(UTC)
        envelope = RawEventEnvelope(
            contract_version="1.0.0",
            event_id=str(uuid4()),
            receipt_id=str(uuid4()),
            source=self._source_resolver.resolve(capture_input.transport),
            received_at=received_at,
            transport=capture_input.transport,
            payload=payload,
            payload_sha256=sha256(payload).hexdigest(),
            request_id=capture_input.request_id,
            correlation_id=capture_input.correlation_id,
            trace_id=capture_input.trace_id,
        )
        try:
            stored = self._sink.store(envelope)
        except Exception:
            self._metrics.increment("failed", capture_input.transport.protocol)
            self._logger.exception(
                "raw_capture_failed",
                extra={"component": "ingestion.capture", "error_code": "intake_capture_failure"},
            )
            raise

        validation = self._registry.validate("raw-event.v1.schema.json", stored.raw_event_contract)
        if not validation.valid:
            self._metrics.increment("failed", capture_input.transport.protocol)
            self._logger.error(
                "raw_capture_contract_invalid",
                extra={"component": "ingestion.capture", "error_code": "intake_capture_failure"},
            )
            raise CaptureContractError("Captured receipt does not satisfy the raw-event contract.")

        self._metrics.increment("captured", capture_input.transport.protocol)
        self._logger.info(
            "raw_event_captured",
            extra={"component": "ingestion.capture", "event_id": envelope.event_id},
        )
        return CaptureAcknowledgement(
            event_id=envelope.event_id,
            receipt_id=envelope.receipt_id,
            received_at=received_at,
            status=envelope.status,
            request_id=envelope.request_id,
            correlation_id=envelope.correlation_id,
            trace_id=envelope.trace_id,
        )
