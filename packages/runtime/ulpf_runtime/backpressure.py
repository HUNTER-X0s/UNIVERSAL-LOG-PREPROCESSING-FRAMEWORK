"""Bounded queue and backpressure controllers for ULPF Phase 6.

Enforces:
- Rule 19: No unbounded queues
- Rule 8: No silent dropping of events
- Explicit rejection or backpressure policies
"""

import threading
from enum import Enum
from typing import Any

from ulpf_runtime.errors import BufferFullError


class BackpressurePolicy(str, Enum):
    """Backpressure reaction policies when buffer threshold is reached."""

    REJECT = "REJECT"  # Explicitly fail incoming intake with BufferFullError
    BLOCK = "BLOCK"  # Block producer until buffer has capacity (bounded timeout)
    DLQ = "DLQ"  # Route overflow directly to DLQ with explicit audit trail


class BackpressureController:
    """Controls ingestion flow according to queue depth and backpressure policy."""

    def __init__(
        self,
        max_capacity: int = 10_000,
        high_watermark: float = 0.85,
        low_watermark: float = 0.50,
        policy: BackpressurePolicy = BackpressurePolicy.REJECT,
        block_timeout_sec: float = 2.0,
    ) -> None:
        if max_capacity <= 0:
            raise ValueError("max_capacity must be positive")
        self._max_capacity = max_capacity
        self._high_watermark_count = int(max_capacity * high_watermark)
        self._low_watermark_count = int(max_capacity * low_watermark)
        self._policy = policy
        self._block_timeout_sec = block_timeout_sec
        self._current_depth = 0
        self._total_accepted = 0
        self._total_rejected = 0
        self._total_dlq_overflow = 0
        self._lock = threading.Lock()
        self._space_available = threading.Condition(self._lock)

    @property
    def max_capacity(self) -> int:
        return self._max_capacity

    @property
    def current_depth(self) -> int:
        with self._lock:
            return self._current_depth

    @property
    def is_high_watermark(self) -> bool:
        with self._lock:
            return self._current_depth >= self._high_watermark_count

    @property
    def statistics(self) -> dict[str, Any]:
        with self._lock:
            return {
                "max_capacity": self._max_capacity,
                "current_depth": self._current_depth,
                "high_watermark_count": self._high_watermark_count,
                "policy": self._policy.value,
                "total_accepted": self._total_accepted,
                "total_rejected": self._total_rejected,
                "total_dlq_overflow": self._total_dlq_overflow,
            }

    def acquire(self) -> bool:
        """Attempt to acquire a slot in the buffer.

        Returns True if acquired.
        Raises BufferFullError if rejected under REJECT policy.
        Returns False if routed to DLQ under DLQ policy.
        """
        with self._lock:
            if self._current_depth < self._max_capacity:
                self._current_depth += 1
                self._total_accepted += 1
                return True

            # Buffer full handling
            if self._policy == BackpressurePolicy.REJECT:
                self._total_rejected += 1
                raise BufferFullError(
                    f"Buffer capacity {self._max_capacity} exceeded. Rejected.",
                    details={"capacity": self._max_capacity, "depth": self._current_depth},
                )
            elif self._policy == BackpressurePolicy.BLOCK:
                # Wait for capacity with timeout
                acquired = self._space_available.wait(self._block_timeout_sec)
                if acquired and self._current_depth < self._max_capacity:
                    self._current_depth += 1
                    self._total_accepted += 1
                    return True
                self._total_rejected += 1
                raise BufferFullError(
                    f"Buffer capacity {self._max_capacity} timeout ({self._block_timeout_sec}s).",
                    details={"capacity": self._max_capacity, "depth": self._current_depth},
                )
            elif self._policy == BackpressurePolicy.DLQ:
                self._total_dlq_overflow += 1
                return False

            return False

    def release(self) -> None:
        """Release a slot when processing completes."""
        with self._lock:
            if self._current_depth > 0:
                self._current_depth -= 1
                self._space_available.notify()
