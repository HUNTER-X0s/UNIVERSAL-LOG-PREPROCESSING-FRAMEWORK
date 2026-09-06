"""Delivery sink interfaces for ULPF Phase 6.

Enforces:
- Rule 14: Clean adapter boundary for external destinations
- Rule 57/58: Fan-out architecture with failure isolation between destinations
- Rule 62: Explicit delivery semantics (at-least-once, no silent failure)
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass(frozen=True)
class DeliveryBatch:
    """Batch of records targeted for a downstream sink."""

    sink_name: str
    records: list[dict[str, Any]]
    batch_id: str
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


@dataclass(frozen=True)
class DeliveryResult:
    """Outcome of a downstream delivery attempt."""

    sink_name: str
    batch_id: str
    delivered_count: int
    failed_count: int
    success: bool
    error_message: str | None = None
    duration_ms: float = 0.0


class DeliverySink(ABC):
    """Port for sending projected telemetry to downstream sinks."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the sink (e.g. ocsf, otel, siem, datalake)."""
        ...

    @abstractmethod
    def deliver(self, batch: DeliveryBatch) -> DeliveryResult:
        """Deliver batch to downstream destination. Must isolate failures and never crash."""
        ...

    @abstractmethod
    def health_check(self) -> bool:
        """Check if sink destination is reachable/healthy."""
        ...
