"""Operational telemetry metrics for ULPF Phase 6.

Enforces:
- Rule 45: Bounded metric dimensions; never use unrestricted raw fields as labels
- Rule 48: No secret leakage through telemetry
"""

import threading
from dataclasses import dataclass, field
from typing import Any


@dataclass
class MetricSummary:
    name: str
    type: str  # counter, gauge, histogram
    value: float
    labels: dict[str, str] = field(default_factory=dict)


class OperationalMetricsRegistry:
    """Thread-safe, bounded in-memory metrics registry."""

    _ALLOWED_STAGES = {
        "ingest",
        "buffer",
        "parse",
        "uce",
        "semantic",
        "storage",
        "search",
        "delivery",
        "dlq",
    }
    _ALLOWED_RESULTS = {"success", "failure", "rejected", "retried", "dropped"}

    def __init__(self) -> None:
        self._counters: dict[str, float] = {}
        self._gauges: dict[str, float] = {}
        self._latency_samples: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _make_key(self, name: str, stage: str, result: str) -> str:
        safe_stage = stage if stage in self._ALLOWED_STAGES else "other"
        safe_result = result if result in self._ALLOWED_RESULTS else "other"
        return f"{name}|stage={safe_stage}|result={safe_result}"

    def increment_counter(
        self, name: str, value: float = 1.0, stage: str = "ingest", result: str = "success"
    ) -> None:
        key = self._make_key(name, stage, result)
        with self._lock:
            self._counters[key] = self._counters.get(key, 0.0) + value

    def set_gauge(self, name: str, value: float) -> None:
        with self._lock:
            self._gauges[name] = value

    def record_latency(self, name: str, latency_ms: float, max_samples: int = 1000) -> None:
        with self._lock:
            samples = self._latency_samples.setdefault(name, [])
            if len(samples) >= max_samples:
                samples.pop(0)
            samples.append(latency_ms)

    def snapshot(self) -> dict[str, Any]:
        """Return point-in-time metrics snapshot."""
        with self._lock:
            latencies: dict[str, dict[str, float]] = {}
            for name, samples in self._latency_samples.items():
                if samples:
                    sorted_samples = sorted(samples)
                    n = len(sorted_samples)
                    latencies[name] = {
                        "count": float(n),
                        "p50": sorted_samples[int(n * 0.50)],
                        "p95": sorted_samples[min(int(n * 0.95), n - 1)],
                        "p99": sorted_samples[min(int(n * 0.99), n - 1)],
                    }

            return {
                "counters": dict(self._counters),
                "gauges": dict(self._gauges),
                "latencies": latencies,
            }

    def reset(self) -> None:
        with self._lock:
            self._counters.clear()
            self._gauges.clear()
            self._latency_samples.clear()
