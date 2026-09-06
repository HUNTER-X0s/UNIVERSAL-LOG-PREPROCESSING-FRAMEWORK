"""Streaming interfaces and message contracts for ULPF Phase 6.

Enforces:
- Rule 13: Interfaces/ports for all infrastructure components
- Rule 14: Clean adapter boundary
- Rule 17: Deterministic partitioning
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass(frozen=True)
class StreamMessage:
    """Immutable envelope for a message in a stream topic/partition."""

    message_id: str
    partition: int
    offset: int
    key: str
    payload: bytes
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    headers: dict[str, str] = field(default_factory=dict)


class EventPublisher(ABC):
    """Port for publishing events to a stream topic."""

    @abstractmethod
    def publish(
        self, topic: str, key: str, payload: bytes, headers: dict[str, str] | None = None
    ) -> StreamMessage:
        """Publish a message to a topic using key for deterministic partitioning."""
        ...


class EventConsumer(ABC):
    """Port for consuming events from a stream topic."""

    @abstractmethod
    def poll(self, timeout_sec: float = 1.0, max_records: int = 100) -> list[StreamMessage]:
        """Poll for available messages up to max_records."""
        ...

    @abstractmethod
    def ack(self, message: StreamMessage) -> None:
        """Acknowledge successful message processing."""
        ...

    @abstractmethod
    def nack(self, message: StreamMessage, requeue: bool = True) -> None:
        """Negative acknowledge; optionally requeue or discard."""
        ...

    @abstractmethod
    def seek(self, partition: int, offset: int) -> None:
        """Seek consumer offset for a partition."""
        ...


class EventStream(EventPublisher, EventConsumer, ABC):
    """Unified stream abstraction combining publisher and consumer capabilities."""

    @abstractmethod
    def get_lag(self, partition: int) -> int:
        """Return unconsumed message lag for a partition."""
        ...

    @abstractmethod
    def close(self) -> None:
        """Gracefully flush and close stream resources."""
        ...
