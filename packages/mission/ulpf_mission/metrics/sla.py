"""Operational SLA metrics tracker for Phase 10 — MTTD/MTTA/MTTR + latency distribution."""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass, field


@dataclass
class LatencyDistribution:
    """Latency percentile distribution."""

    p50_ms: float
    p95_ms: float
    p99_ms: float
    min_ms: float
    max_ms: float
    sample_count: int


@dataclass
class SLAMetricsSnapshot:
    """Point-in-time snapshot of all operational SLA metrics."""

    mttd_s: float | None       # Mean Time To Detect (seconds)
    mtta_s: float | None       # Mean Time To Acknowledge (seconds)
    mttr_s: float | None       # Mean Time To Resolve (seconds)
    ingest_latency: LatencyDistribution | None
    detection_latency: LatencyDistribution | None
    fusion_latency: LatencyDistribution | None
    timestamp: float = field(default_factory=time.time)


class OperationalMetricsTracker:
    """Tracks MTTD, MTTA, MTTR, and latency distributions.

    All measurements are based on real timestamps; no synthetic inflation.
    """

    def __init__(self) -> None:
        # Detection time series: (event_ts, detection_ts)
        self._detection_pairs: list[tuple[float, float]] = []
        # Acknowledgement pairs: (detection_ts, ack_ts)
        self._ack_pairs: list[tuple[float, float]] = []
        # Resolution pairs: (ack_ts, resolved_ts)
        self._resolution_pairs: list[tuple[float, float]] = []
        # Raw latency samples (ms)
        self._ingest_latencies: list[float] = []
        self._detection_latencies: list[float] = []
        self._fusion_latencies: list[float] = []

    def record_detection(self, event_timestamp: float, detection_timestamp: float) -> None:
        """Record when an event was generated vs when a detection fired."""
        if detection_timestamp >= event_timestamp:
            self._detection_pairs.append((event_timestamp, detection_timestamp))

    def record_acknowledgement(self, detection_timestamp: float, ack_timestamp: float) -> None:
        """Record when a detection was acknowledged by an analyst."""
        if ack_timestamp >= detection_timestamp:
            self._ack_pairs.append((detection_timestamp, ack_timestamp))

    def record_resolution(self, ack_timestamp: float, resolved_timestamp: float) -> None:
        """Record when an acknowledged alert was resolved."""
        if resolved_timestamp >= ack_timestamp:
            self._resolution_pairs.append((ack_timestamp, resolved_timestamp))

    def record_ingest_latency(self, latency_ms: float) -> None:
        self._ingest_latencies.append(latency_ms)

    def record_detection_latency(self, latency_ms: float) -> None:
        self._detection_latencies.append(latency_ms)

    def record_fusion_latency(self, latency_ms: float) -> None:
        self._fusion_latencies.append(latency_ms)

    def snapshot(self) -> SLAMetricsSnapshot:
        """Compute a full SLA metrics snapshot from all recorded observations."""
        mttd = self._mean_delta(self._detection_pairs)
        mtta = self._mean_delta(self._ack_pairs)
        mttr = self._mean_delta(self._resolution_pairs)

        return SLAMetricsSnapshot(
            mttd_s=mttd,
            mtta_s=mtta,
            mttr_s=mttr,
            ingest_latency=self._distribution(self._ingest_latencies),
            detection_latency=self._distribution(self._detection_latencies),
            fusion_latency=self._distribution(self._fusion_latencies),
        )

    @staticmethod
    def _mean_delta(pairs: list[tuple[float, float]]) -> float | None:
        if not pairs:
            return None
        deltas = [b - a for a, b in pairs]
        return round(statistics.mean(deltas), 4)

    @staticmethod
    def _distribution(samples: list[float]) -> LatencyDistribution | None:
        if not samples:
            return None
        sorted_samples = sorted(samples)
        n = len(sorted_samples)

        def _percentile(p: float) -> float:
            idx = int(p / 100.0 * n)
            return round(sorted_samples[min(idx, n - 1)], 4)

        return LatencyDistribution(
            p50_ms=_percentile(50),
            p95_ms=_percentile(95),
            p99_ms=_percentile(99),
            min_ms=round(sorted_samples[0], 4),
            max_ms=round(sorted_samples[-1], 4),
            sample_count=n,
        )
