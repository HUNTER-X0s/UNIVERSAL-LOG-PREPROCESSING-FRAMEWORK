"""Operational data models and audit records for ULPF Phase 6."""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from ulpf_runtime.lifecycle import EventLifecycleState


@dataclass(frozen=True)
class EventEnvelope:
    """Operational envelope encapsulating an event moving through the platform."""

    event_id: str
    raw_event_id: str
    raw_sha256: str
    source_id: str
    format: str
    payload: str | bytes
    captured_at: str
    correlation_id: str
    tenant_id: str = "default"
    metadata: dict[str, Any] = field(default_factory=dict)
    state: EventLifecycleState = EventLifecycleState.RECEIVED


@dataclass(frozen=True)
class ProcessingAttemptRecord:
    """Operational audit record of an individual processing attempt."""

    attempt_id: str
    event_id: str
    stage: str
    worker_id: str
    mapping_version: str | None
    started_at: str
    completed_at: str
    status: str  # SUCCESS, FAILED, RETRIED
    error_code: str | None = None
    error_message: str | None = None
    duration_ms: float = 0.0


@dataclass(frozen=True)
class DeliveryIntent:
    """Outbox delivery intent to guarantee downstream delivery without silent loss."""

    intent_id: str
    event_id: str
    sink_name: str
    payload_type: str  # OCSF, OTEL, SIEM_JSON, DATA_LAKE
    payload: dict[str, Any]
    created_at: str
    attempt_count: int = 0
    max_attempts: int = 3
    status: str = "PENDING"  # PENDING, DELIVERED, FAILED, DLQ
    last_attempt_at: str | None = None
    last_error: str | None = None


@dataclass(frozen=True)
class AuditActionRecord:
    """Administrative action audit trail record."""

    audit_id: str
    actor: str
    action: str
    target: str
    previous_state: str | None
    new_state: str
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    reason: str | None = None
    correlation_id: str | None = None
    checksum: str | None = None
