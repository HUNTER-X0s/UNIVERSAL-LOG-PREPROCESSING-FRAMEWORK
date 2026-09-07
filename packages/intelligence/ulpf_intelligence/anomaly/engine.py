"""Statistical Anomaly Detection Engine for ULPF Phase 8."""

from __future__ import annotations

import math
import threading
import uuid
from datetime import UTC, datetime

from ulpf_intelligence.models.events import AnomalyEvent
from ulpf_intelligence.models.provenance import (
    AlertSeverity,
    _ProvenanceFactory,
)


class RunningStat:
    """Numerically stable online running mean and variance (Welford's algorithm)."""

    def __init__(self) -> None:
        self.count = 0
        self.mean = 0.0
        self.m2 = 0.0

    def update(self, x: float) -> None:
        self.count += 1
        delta = x - self.mean
        self.mean += delta / self.count
        delta2 = x - self.mean
        self.m2 += delta * delta2

    @property
    def variance(self) -> float:
        return self.m2 / (self.count - 1) if self.count > 1 else 0.0

    @property
    def std_dev(self) -> float:
        return math.sqrt(self.variance)


class StatisticalAnomalyEngine:
    """Evaluates metrics against learned entity baselines, detecting statistical deviations."""

    def __init__(
        self,
        z_score_threshold: float = 3.0,
        min_baseline_samples: int = 5,
        default_threshold_z: float | None = None,
    ) -> None:
        self.z_score_threshold = default_threshold_z or z_score_threshold
        self.min_baseline_samples = min_baseline_samples
        # (entity_id, metric_name) -> RunningStat
        self._baselines: dict[tuple[str, str], RunningStat] = {}
        self._lock = threading.Lock()

    def update_baseline(self, entity_id: str, metric_name: str, value: float) -> None:
        """Incrementally update baseline statistics without triggering alert evaluation."""
        with self._lock:
            key = (entity_id, metric_name)
            stat = self._baselines.setdefault(key, RunningStat())
            stat.update(value)

    def evaluate(
        self,
        entity_id: str,
        metric_name: str,
        observed_value: float,
        tenant_id: str | None = None,
        timestamp: str | None = None,
    ) -> AnomalyEvent | None:
        """Convenience method to evaluate an observation against baseline."""
        now_iso = timestamp or datetime.now(UTC).isoformat()
        return self.record_and_evaluate(
            entity_id=entity_id,
            metric_name=metric_name,
            observed_value=observed_value,
            window_start=now_iso,
            window_end=now_iso,
            tenant_id=tenant_id,
        )

    def record_and_evaluate(
        self,
        entity_id: str,
        metric_name: str,
        observed_value: float,
        window_start: str,
        window_end: str,
        contributing_event_ids: tuple[str, ...] = (),
        tenant_id: str | None = None,
    ) -> AnomalyEvent | None:
        """Record an observed metric for an entity and evaluate whether it deviates abnormally."""
        with self._lock:
            key = (entity_id, metric_name)
            stat = self._baselines.setdefault(key, RunningStat())

            # Evaluate against current baseline before updating
            anomaly: AnomalyEvent | None = None

            if stat.count >= self.min_baseline_samples:
                mean = stat.mean
                std = stat.std_dev

                # Avoid division by zero when standard deviation is very small
                effective_std = max(std, 0.01 * mean, 0.001)
                z_score = (observed_value - mean) / effective_std

                if z_score >= self.z_score_threshold:
                    now_iso = datetime.now(UTC).isoformat()

                    # Determine severity based on magnitude of z-score
                    if z_score >= 5.0:
                        sev = AlertSeverity.CRITICAL
                    elif z_score >= 4.0:
                        sev = AlertSeverity.HIGH
                    else:
                        sev = AlertSeverity.MEDIUM

                    anomaly = AnomalyEvent(
                        anomaly_id=f"anom-{uuid.uuid4().hex[:12]}",
                        metric_name=metric_name,
                        entity_id=entity_id,
                        baseline_value=round(mean, 3),
                        observed_value=round(observed_value, 3),
                        deviation_score=round(z_score, 3),
                        window_start=window_start,
                        window_end=window_end,
                        threshold=self.z_score_threshold,
                        severity=sev,
                        confidence=min(1.0, 0.7 + (0.05 * stat.count)),
                        created_at=now_iso,
                        contributing_event_ids=contributing_event_ids,
                        tenant_id=tenant_id,
                        provenance=_ProvenanceFactory.DETECTED,
                        metadata={
                            "method": "z_score",
                            "sample_count": stat.count,
                            "baseline_std": round(std, 3),
                        },
                    )

            # Update running baseline
            stat.update(observed_value)
            return anomaly
