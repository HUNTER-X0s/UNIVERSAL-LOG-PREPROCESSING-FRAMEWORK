"""ULPF Phase 14 — Adaptive Source Lifecycle & Explainable Risk Scoring.

Fulfills Phase 14 Workstreams K and L:
- Explicit 10-state source lifecycle model:
  DISCOVERED, PROFILED, ONBOARDING, VALIDATING, APPROVED, ACTIVE,
  DEGRADED, DRIFTING, QUARANTINED, RETIRED
- Audited state transitions with operator rationale
- Explainable risk scoring (no black-box numbers) derived from parse failures,
  schema drift, unknown field ratio, latency, and security relevance.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class SourceLifecycleState(str, Enum):
    """The 10 explicit lifecycle states for any log source."""

    DISCOVERED = "DISCOVERED"
    PROFILED = "PROFILED"
    ONBOARDING = "ONBOARDING"
    VALIDATING = "VALIDATING"
    APPROVED = "APPROVED"
    ACTIVE = "ACTIVE"
    DEGRADED = "DEGRADED"
    DRIFTING = "DRIFTING"
    QUARANTINED = "QUARANTINED"
    RETIRED = "RETIRED"


@dataclass(frozen=True)
class LifecycleAuditEvent:
    """Immutable audit entry for a source state transition."""

    source_id: str
    from_state: SourceLifecycleState
    to_state: SourceLifecycleState
    actor: str
    reason: str
    timestamp: str
    metadata: dict[str, Any] = field(default_factory=dict)


class SourceLifecycleManager:
    """Governs state transitions across the 10 source lifecycle stages."""

    ALLOWED_TRANSITIONS: dict[SourceLifecycleState, set[SourceLifecycleState]] = {
        SourceLifecycleState.DISCOVERED: {SourceLifecycleState.PROFILED, SourceLifecycleState.RETIRED},
        SourceLifecycleState.PROFILED: {SourceLifecycleState.ONBOARDING, SourceLifecycleState.DISCOVERED, SourceLifecycleState.RETIRED},
        SourceLifecycleState.ONBOARDING: {SourceLifecycleState.VALIDATING, SourceLifecycleState.PROFILED, SourceLifecycleState.RETIRED},
        SourceLifecycleState.VALIDATING: {SourceLifecycleState.APPROVED, SourceLifecycleState.ONBOARDING, SourceLifecycleState.RETIRED},
        SourceLifecycleState.APPROVED: {SourceLifecycleState.ACTIVE, SourceLifecycleState.VALIDATING, SourceLifecycleState.RETIRED},
        SourceLifecycleState.ACTIVE: {
            SourceLifecycleState.DEGRADED,
            SourceLifecycleState.DRIFTING,
            SourceLifecycleState.QUARANTINED,
            SourceLifecycleState.RETIRED,
        },
        SourceLifecycleState.DEGRADED: {
            SourceLifecycleState.ACTIVE,
            SourceLifecycleState.QUARANTINED,
            SourceLifecycleState.RETIRED,
        },
        SourceLifecycleState.DRIFTING: {
            SourceLifecycleState.ACTIVE,
            SourceLifecycleState.ONBOARDING,
            SourceLifecycleState.QUARANTINED,
            SourceLifecycleState.RETIRED,
        },
        SourceLifecycleState.QUARANTINED: {
            SourceLifecycleState.VALIDATING,
            SourceLifecycleState.RETIRED,
        },
        SourceLifecycleState.RETIRED: set(),  # Terminal state
    }

    def __init__(self) -> None:
        self._sources: dict[str, SourceLifecycleState] = {}
        self._audit_log: list[LifecycleAuditEvent] = []

    def register_source(
        self,
        source_id: str,
        initial_state: SourceLifecycleState = SourceLifecycleState.DISCOVERED,
        actor: str = "system",
    ) -> SourceLifecycleState:
        """Register a newly discovered source."""
        self._sources[source_id] = initial_state
        self._audit_log.append(
            LifecycleAuditEvent(
                source_id=source_id,
                from_state=SourceLifecycleState.DISCOVERED,
                to_state=initial_state,
                actor=actor,
                reason="Initial registration",
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            )
        )
        return initial_state

    def transition(
        self,
        source_id: str,
        target_state: SourceLifecycleState,
        actor: str,
        reason: str,
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        """Execute and audit a source lifecycle transition if permitted."""
        current = self._sources.get(source_id)
        if current is None:
            raise KeyError(f"Source '{source_id}' is not registered")

        if target_state not in self.ALLOWED_TRANSITIONS.get(current, set()):
            raise ValueError(
                f"Invalid transition for '{source_id}': cannot move from {current.value} to {target_state.value}"
            )

        self._sources[source_id] = target_state
        self._audit_log.append(
            LifecycleAuditEvent(
                source_id=source_id,
                from_state=current,
                to_state=target_state,
                actor=actor,
                reason=reason,
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                metadata=metadata or {},
            )
        )
        return True

    def get_state(self, source_id: str) -> SourceLifecycleState | None:
        return self._sources.get(source_id)

    def get_history(self, source_id: str) -> list[LifecycleAuditEvent]:
        return [e for e in self._audit_log if e.source_id == source_id]


@dataclass(frozen=True)
class SourceRiskReport:
    """Explainable risk assessment with complete factor breakdown."""

    source_id: str
    composite_risk_score: float  # 0.0 (pristine) to 100.0 (critical danger)
    risk_level: str              # LOW, MEDIUM, HIGH, CRITICAL
    factors: dict[str, float]
    explanations: list[str]
    recommended_action: str


class SourceRiskEvaluator:
    """Evaluates multi-factor operational and security risk for any source."""

    @classmethod
    def evaluate(
        cls,
        source_id: str,
        parse_failure_rate: float,       # 0.0 to 1.0
        drift_severity_score: float,     # 0.0 to 1.0
        unknown_field_ratio: float,      # 0.0 to 1.0
        latency_p95_ms: float,           # e.g. 5.0ms
        security_criticality: float = 1.0 # 0.5 (low) to 2.0 (critical perimeter)
    ) -> SourceRiskReport:
        explanations = []

        # 1. Parse Failure Factor (weight: 30)
        f_parse = min(30.0, parse_failure_rate * 30.0 * 2.0)
        if parse_failure_rate > 0.05:
            explanations.append(f"Elevated parse failure rate ({parse_failure_rate*100:.1f}%)")

        # 2. Schema Drift Factor (weight: 25)
        f_drift = min(25.0, drift_severity_score * 25.0)
        if drift_severity_score > 0.3:
            explanations.append(f"Unmanaged schema drift detected (score: {drift_severity_score:.2f})")

        # 3. Unknown Field Ratio (weight: 20)
        f_unknown = min(20.0, unknown_field_ratio * 20.0)
        if unknown_field_ratio > 0.2:
            explanations.append(f"High ratio of unmapped fields ({unknown_field_ratio*100:.1f}%)")

        # 4. Latency Degradation (weight: 15)
        f_latency = min(15.0, max(0.0, (latency_p95_ms - 10.0) / 10.0 * 15.0))
        if latency_p95_ms > 20.0:
            explanations.append(f"High intake latency ({latency_p95_ms:.1f}ms p95)")

        # 5. Baseline Risk
        raw_score = (f_parse + f_drift + f_unknown + f_latency) * security_criticality
        composite = min(100.0, max(0.0, round(raw_score, 1)))

        if composite >= 75.0:
            level = "CRITICAL"
            action = "QUARANTINE_OR_ROLLBACK"
        elif composite >= 50.0:
            level = "HIGH"
            action = "ALERT_OPERATOR_REVIEW"
        elif composite >= 25.0:
            level = "MEDIUM"
            action = "SCHEDULE_CANARY_ANALYSIS"
        else:
            level = "LOW"
            action = "CONTINUE_ACTIVE_OPERATION"

        if not explanations:
            explanations.append("Source operational parameters within pristine tolerance")

        return SourceRiskReport(
            source_id=source_id,
            composite_risk_score=composite,
            risk_level=level,
            factors={
                "parse_failure_risk": round(f_parse, 2),
                "schema_drift_risk": round(f_drift, 2),
                "unknown_fields_risk": round(f_unknown, 2),
                "latency_risk": round(f_latency, 2),
                "criticality_multiplier": security_criticality,
            },
            explanations=explanations,
            recommended_action=action,
        )
