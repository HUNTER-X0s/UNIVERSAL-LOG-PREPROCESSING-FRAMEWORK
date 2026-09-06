"""Deterministic event lifecycle states and transitions for ULPF Phase 6."""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from ulpf_runtime.errors import UlpfOperationalError


class EventLifecycleState(str, Enum):
    """Explicit lifecycle states for telemetry processing.

    Transitions must be explicit; generic 'success' or ambiguous states are forbidden.
    """

    RECEIVED = "RECEIVED"
    CAPTURED = "CAPTURED"
    BUFFERED = "BUFFERED"
    PROCESSING = "PROCESSING"
    NORMALIZED = "NORMALIZED"
    SEMANTIC_READY = "SEMANTIC_READY"
    PERSISTED = "PERSISTED"
    DELIVERED = "DELIVERED"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    FAILED = "FAILED"
    DLQ = "DLQ"
    REPLAYED = "REPLAYED"


_VALID_TRANSITIONS: dict[EventLifecycleState, set[EventLifecycleState]] = {
    EventLifecycleState.RECEIVED: {
        EventLifecycleState.CAPTURED,
        EventLifecycleState.FAILED,
    },
    EventLifecycleState.CAPTURED: {
        EventLifecycleState.BUFFERED,
        EventLifecycleState.FAILED,
    },
    EventLifecycleState.BUFFERED: {
        EventLifecycleState.PROCESSING,
        EventLifecycleState.FAILED,
    },
    EventLifecycleState.PROCESSING: {
        EventLifecycleState.NORMALIZED,
        EventLifecycleState.FAILED,
        EventLifecycleState.DLQ,
    },
    EventLifecycleState.NORMALIZED: {
        EventLifecycleState.SEMANTIC_READY,
        EventLifecycleState.FAILED,
        EventLifecycleState.DLQ,
    },
    EventLifecycleState.SEMANTIC_READY: {
        EventLifecycleState.PERSISTED,
        EventLifecycleState.FAILED,
        EventLifecycleState.DLQ,
    },
    EventLifecycleState.PERSISTED: {
        EventLifecycleState.DELIVERED,
        EventLifecycleState.ACKNOWLEDGED,
        EventLifecycleState.FAILED,
    },
    EventLifecycleState.DELIVERED: {
        EventLifecycleState.ACKNOWLEDGED,
        EventLifecycleState.FAILED,
    },
    EventLifecycleState.ACKNOWLEDGED: set(),  # Terminal success
    EventLifecycleState.FAILED: {
        EventLifecycleState.PROCESSING,  # Retry
        EventLifecycleState.DLQ,  # Retries exhausted
    },
    EventLifecycleState.DLQ: {
        EventLifecycleState.REPLAYED,  # Safe historical replay from DLQ
    },
    EventLifecycleState.REPLAYED: {
        EventLifecycleState.PROCESSING,  # Replay entering processor with pinned version
    },
}


class InvalidLifecycleTransitionError(UlpfOperationalError):
    """Raised when an illegal event state transition is attempted."""

    def __init__(self, from_state: EventLifecycleState, to_state: EventLifecycleState) -> None:
        super().__init__(
            f"Illegal event transition from {from_state.value} to {to_state.value}",
            error_code="INVALID_LIFECYCLE_TRANSITION",
            details={"from_state": from_state.value, "to_state": to_state.value},
        )


@dataclass(frozen=True)
class StateTransitionRecord:
    """Immutable audit record of a state transition."""

    from_state: EventLifecycleState
    to_state: EventLifecycleState
    timestamp: str
    reason: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class EventLifecycleTracker:
    """Tracks and validates an event's lifecycle state."""

    def __init__(self, initial_state: EventLifecycleState = EventLifecycleState.RECEIVED) -> None:
        self._current_state = initial_state
        self._history: list[StateTransitionRecord] = [
            StateTransitionRecord(
                from_state=initial_state,
                to_state=initial_state,
                timestamp=datetime.now(UTC).isoformat(),
                reason="initialization",
            )
        ]

    @property
    def current_state(self) -> EventLifecycleState:
        return self._current_state

    @property
    def history(self) -> list[StateTransitionRecord]:
        return list(self._history)

    def transition_to(
        self,
        new_state: EventLifecycleState,
        reason: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        allowed = _VALID_TRANSITIONS.get(self._current_state, set())
        if new_state not in allowed:
            raise InvalidLifecycleTransitionError(self._current_state, new_state)

        record = StateTransitionRecord(
            from_state=self._current_state,
            to_state=new_state,
            timestamp=datetime.now(UTC).isoformat(),
            reason=reason,
            metadata=metadata or {},
        )
        self._current_state = new_state
        self._history.append(record)
