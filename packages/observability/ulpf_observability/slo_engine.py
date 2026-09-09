"""ULPF Operational SRE SLO Model and Error Budget Engine.

Tracks 10 operational and engineering Service Level Objectives (SLOs),
computes error budget burn rates, and evaluates health degradation without
any external telemetry service dependency.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
import time
from typing import Any


class SLOStatus(str, Enum):
    HEALTHY = "HEALTHY"
    BURNING_BUDGET = "BURNING_BUDGET"
    EXHAUSTED = "EXHAUSTED"
    BREACHED = "BREACHED"


class MetricCategory(str, Enum):
    INGESTION = "INGESTION"
    PARSING = "PARSING"
    NORMALIZATION = "NORMALIZATION"
    EVIDENCE = "EVIDENCE"
    DLQ = "DLQ"
    REPLAY = "REPLAY"
    LATENCY = "LATENCY"
    QUEUE = "QUEUE"
    FRESHNESS = "FRESHNESS"
    SYSTEM = "SYSTEM"


@dataclass
class SLODefinition:
    slo_id: str
    name: str
    category: MetricCategory
    target_percentage: float
    window_seconds: float
    description: str
    is_critical: bool = True


@dataclass
class SLOMeasurement:
    slo_id: str
    current_percentage: float
    target_percentage: float
    error_budget_remaining: float
    burn_rate_1h: float
    status: SLOStatus
    is_met: bool
    details: dict[str, Any] = field(default_factory=dict)


class MissionSLOEngine:
    """Production SRE SLO and error budget tracking engine for ULPF."""

    DEFAULT_SLOS = [
        SLODefinition("SLO-INGEST", "Ingestion Acceptance Rate", MetricCategory.INGESTION, 99.9, 3600.0, "Events accepted vs total attempted"),
        SLODefinition("SLO-PARSE", "Parsing Success Rate", MetricCategory.PARSING, 98.0, 3600.0, "Syntactically parsed events vs accepted"),
        SLODefinition("SLO-NORM", "Normalization Success Rate", MetricCategory.NORMALIZATION, 99.0, 3600.0, "Events normalized into canonical UCE schema"),
        SLODefinition("SLO-EVID", "Lossless Evidence Persistence", MetricCategory.EVIDENCE, 100.0, 3600.0, "Raw payloads persisted with verified SHA-256"),
        SLODefinition("SLO-DLQ", "DLQ Retention & Zero Data Loss", MetricCategory.DLQ, 100.0, 3600.0, "Overload overflow records preserved in cryptographically sealed DLQ"),
        SLODefinition("SLO-REPLAY", "Deterministic Replay Rate", MetricCategory.REPLAY, 100.0, 3600.0, "Replayed raw logs reproducing exact UCE digests"),
        SLODefinition("SLO-LATENCY", "P99 Ingestion Latency <= 10ms", MetricCategory.LATENCY, 99.0, 3600.0, "Sub-10ms processing latency under normal load"),
        SLODefinition("SLO-QUEUE", "Queue Depth Boundedness", MetricCategory.QUEUE, 95.0, 3600.0, "Queue depth strictly below overload threshold"),
        SLODefinition("SLO-FRESH", "Event Age / Freshness", MetricCategory.FRESHNESS, 99.0, 3600.0, "Time difference between event-time and ingress < 60s"),
        SLODefinition("SLO-AVAIL", "Core Engine Readiness", MetricCategory.SYSTEM, 99.9, 3600.0, "Engine health probes reporting READY"),
    ]

    def __init__(self, definitions: list[SLODefinition] | None = None) -> None:
        self.definitions = {d.slo_id: d for d in (definitions or self.DEFAULT_SLOS)}
        self._counters: dict[str, dict[str, float]] = {
            d.slo_id: {"success": 0.0, "total": 0.0, "latency_sum": 0.0, "error_count": 0.0}
            for d in self.definitions.values()
        }
        self._start_time = time.time()

    def record_event(self, slo_id: str, success: bool, latency_ms: float = 0.0, weight: float = 1.0) -> None:
        """Record an operation measurement against an SLO."""
        if slo_id not in self._counters:
            return
        c = self._counters[slo_id]
        c["total"] += weight
        if success:
            c["success"] += weight
        else:
            c["error_count"] += weight
        c["latency_sum"] += latency_ms

    def evaluate_slo(self, slo_id: str) -> SLOMeasurement:
        """Evaluate current achievement, remaining budget, and status for an SLO."""
        defn = self.definitions[slo_id]
        c = self._counters[slo_id]
        total = c["total"]
        success = c["success"]

        if total == 0.0:
            current_pct = 100.0
        else:
            current_pct = round((success / total) * 100.0, 3)

        allowed_failure_pct = max(0.001, 100.0 - defn.target_percentage)
        actual_failure_pct = max(0.0, 100.0 - current_pct)
        error_budget_used = actual_failure_pct / allowed_failure_pct
        budget_remaining = round(max(0.0, (1.0 - error_budget_used) * 100.0), 2)

        # Burn rate: consumption speed relative to uniform 1-hour window
        burn_rate = round(actual_failure_pct / allowed_failure_pct, 2)

        if current_pct >= defn.target_percentage:
            status = SLOStatus.HEALTHY
        elif budget_remaining > 50.0:
            status = SLOStatus.BURNING_BUDGET
        elif budget_remaining > 0.0:
            status = SLOStatus.EXHAUSTED
        else:
            status = SLOStatus.BREACHED

        return SLOMeasurement(
            slo_id=slo_id,
            current_percentage=current_pct,
            target_percentage=defn.target_percentage,
            error_budget_remaining=budget_remaining,
            burn_rate_1h=burn_rate,
            status=status,
            is_met=current_pct >= defn.target_percentage,
            details={"total_events": total, "failures": c["error_count"]},
        )

    def evaluate_all(self) -> dict[str, SLOMeasurement]:
        """Evaluate all defined platform SLOs."""
        return {slo_id: self.evaluate_slo(slo_id) for slo_id in self.definitions}

    def get_overall_health(self) -> dict[str, Any]:
        """Summary health posture across all SLOs."""
        evals = self.evaluate_all()
        met_count = sum(1 for m in evals.values() if m.is_met)
        total_count = len(evals)
        breached = [m.slo_id for m in evals.values() if m.status == SLOStatus.BREACHED]

        if len(breached) == 0 and met_count == total_count:
            posture = "HEALTHY"
        elif len(breached) == 0:
            posture = "DEGRADED"
        else:
            posture = "CRITICAL"

        return {
            "timestamp": datetime.now(UTC).isoformat(),
            "overall_posture": posture,
            "slos_met": met_count,
            "slos_total": total_count,
            "breached_slos": breached,
            "details": {k: {"status": v.status.value, "pct": v.current_percentage, "budget_left": v.error_budget_remaining} for k, v in evals.items()},
        }
