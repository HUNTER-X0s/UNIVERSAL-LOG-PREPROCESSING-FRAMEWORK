"""ULPF Phase 14 — Mission Telemetry & Engineering SLO Tracker.

Fulfills Phase 14 Workstreams AS, AT, and AU:
- Operational metrics: intake rate, queue lag, query latency, error budget
- Engineering SLO definitions:
  * Ingestion Latency SLO: 99.0% of events ingested under 10ms
  * Query Latency SLO: 95.0% of investigation queries under 50ms
  * Data Loss SLO: 0.0% uncorroborated event loss
- Real-time error budget tracking.
"""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SLODefinition:
    name: str
    target_percentage: float
    unit: str
    current_compliance: float
    error_budget_remaining: float
    status: str  # "MET", "AT_RISK", "BREACHED"


class MissionSLOTracker:
    """Tracks operational performance metrics against defined engineering SLOs."""

    def __init__(self) -> None:
        self._ingestion_latencies_ms: list[float] = []
        self._query_latencies_ms: list[float] = []
        self._dropped_events_count: int = 0
        self._total_events_count: int = 0

    def record_ingestion(self, latency_ms: float) -> None:
        self._ingestion_latencies_ms.append(latency_ms)
        self._total_events_count += 1
        if len(self._ingestion_latencies_ms) > 10_000:
            self._ingestion_latencies_ms = self._ingestion_latencies_ms[-10_000:]

    def record_query(self, latency_ms: float) -> None:
        self._query_latencies_ms.append(latency_ms)
        if len(self._query_latencies_ms) > 2_000:
            self._query_latencies_ms = self._query_latencies_ms[-2_000:]

    def record_dropped_event(self) -> None:
        self._dropped_events_count += 1

    def compute_slos(self) -> dict[str, SLODefinition]:
        # 1. Ingestion Latency SLO (p99 < 10ms)
        if self._ingestion_latencies_ms:
            under_target = sum(1 for x in self._ingestion_latencies_ms if x <= 10.0)
            compliance = round((under_target / len(self._ingestion_latencies_ms)) * 100, 2)
        else:
            compliance = 100.0
        budget = max(0.0, round(compliance - 99.0, 2)) if compliance >= 99.0 else 0.0
        status_ingest = "MET" if compliance >= 99.0 else ("AT_RISK" if compliance >= 95.0 else "BREACHED")
        slo_ingest = SLODefinition("Ingestion Latency (p99 <= 10ms)", 99.0, "%", compliance, budget, status_ingest)

        # 2. Query Latency SLO (p95 < 50ms)
        if self._query_latencies_ms:
            under_query = sum(1 for x in self._query_latencies_ms if x <= 50.0)
            q_compliance = round((under_query / len(self._query_latencies_ms)) * 100, 2)
        else:
            q_compliance = 100.0
        q_budget = max(0.0, round(q_compliance - 95.0, 2)) if q_compliance >= 95.0 else 0.0
        status_query = "MET" if q_compliance >= 95.0 else ("AT_RISK" if q_compliance >= 90.0 else "BREACHED")
        slo_query = SLODefinition("Query Latency (p95 <= 50ms)", 95.0, "%", q_compliance, q_budget, status_query)

        # 3. Data Loss SLO (0.0% loss)
        loss_rate = (self._dropped_events_count / max(1, self._total_events_count)) * 100.0
        data_preservation = round(100.0 - loss_rate, 4)
        slo_loss = SLODefinition(
            "Lossless Evidence Guarantee",
            100.0,
            "%",
            data_preservation,
            1.0 if loss_rate == 0 else 0.0,
            "MET" if loss_rate == 0 else "BREACHED",
        )

        return {
            "ingestion_latency": slo_ingest,
            "query_latency": slo_query,
            "lossless_evidence": slo_loss,
        }
