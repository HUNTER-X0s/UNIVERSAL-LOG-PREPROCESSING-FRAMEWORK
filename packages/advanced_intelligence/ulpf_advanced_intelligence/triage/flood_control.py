"""Alert Storm and Flood Control Controller for ULPF Phase 9."""

from __future__ import annotations

import threading
import time
from typing import Any

from ulpf_advanced_intelligence.models.alerts import FloodControlPolicy


class AlertFloodController:
    """Protects memory and downstream SOC consumers against unbounded alert storms."""

    def __init__(self, policy: FloodControlPolicy | None = None) -> None:
        self.policy = policy or FloodControlPolicy()
        self._sliding_timestamps: list[float] = []
        self._suppressed_count: int = 0
        self._lock = threading.Lock()

    def allow_alert(self) -> tuple[bool, str]:
        """Check if an alert is permitted under current sliding-window limits."""
        now = time.time()
        with self._lock:
            # Evict timestamps older than 60 seconds
            cutoff = now - 60.0
            self._sliding_timestamps = [t for t in self._sliding_timestamps if t > cutoff]

            if len(self._sliding_timestamps) >= self.policy.burst_limit:
                self._suppressed_count += 1
                return False, f"Alert burst limit ({self.policy.burst_limit}/min) exceeded. Suppressed count: {self._suppressed_count}"

            if len(self._sliding_timestamps) >= self.policy.rate_limit_per_minute:
                self._suppressed_count += 1
                return False, f"Alert rate limit ({self.policy.rate_limit_per_minute}/min) exceeded."

            self._sliding_timestamps.append(now)
            return True, "Allowed"

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "current_rate_1m": len(self._sliding_timestamps),
                "total_suppressed": self._suppressed_count,
                "rate_limit": self.policy.rate_limit_per_minute,
                "burst_limit": self.policy.burst_limit,
            }
