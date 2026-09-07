"""Transparent, Weighted Risk Scoring Engine for ULPF Phase 8."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from ulpf_intelligence.models.events import RiskAssessment
from ulpf_intelligence.models.provenance import (
    AlertSeverity,
    _ProvenanceFactory,
)

RISK_FORMULA_VERSION = "2.0.0"


@dataclass(frozen=True)
class RiskWeights:
    """Configurable weights for transparent risk score computation."""

    severity_weight: float = 0.35
    anomaly_weight: float = 0.25
    sequence_weight: float = 0.25
    confidence_weight: float = 0.15


class RiskScoringEngine:
    """Computes transparent, explainable risk assessments combining multiple telemetry signals."""

    SEVERITY_SCORES: dict[AlertSeverity, float] = {
        AlertSeverity.INFORMATIONAL: 10.0,
        AlertSeverity.LOW: 25.0,
        AlertSeverity.MEDIUM: 50.0,
        AlertSeverity.HIGH: 75.0,
        AlertSeverity.CRITICAL: 95.0,
    }

    def __init__(self, weights: RiskWeights | None = None) -> None:
        self.weights = weights or RiskWeights()

    def calculate_risk(
        self,
        entity_id: str,
        detections: list[dict[str, Any]],
        anomalies: list[dict[str, Any]],
        asset_criticality: str = "HIGH",
        is_external_facing: bool = False,
    ) -> RiskAssessment:
        """Calculate entity risk taking into account detections, anomalies, and criticality."""
        sev = AlertSeverity.LOW
        if any(d.get("severity") == "CRITICAL" for d in detections):
            sev = AlertSeverity.CRITICAL
        elif any(d.get("severity") == "HIGH" for d in detections):
            sev = AlertSeverity.HIGH
        elif any(d.get("severity") == "MEDIUM" for d in detections):
            sev = AlertSeverity.MEDIUM

        max_z = max([float(a.get("z_score", 0.0)) for a in anomalies], default=0.0)
        res = self.evaluate_risk(
            target_id=entity_id,
            target_type="entity",
            severity=sev,
            confidence=1.0,
            anomaly_deviation=max_z,
            sequence_stage_count=len(detections),
        )
        crit_weight = 1.2 if asset_criticality == "CRITICAL" else (1.1 if asset_criticality == "HIGH" else 1.0)
        ext_weight = 1.15 if is_external_facing else 1.0
        final = min(1.0, (res.final_score / 100.0) * crit_weight * ext_weight)
        factors = dict(res.contributing_factors)
        factors["criticality_weight"] = crit_weight
        factors["external_exposure_weight"] = ext_weight
        return RiskAssessment(
            assessment_id=res.assessment_id,
            target_id=entity_id,
            target_type="entity",
            base_score=res.base_score,
            contributing_factors=factors,
            weights_applied=res.weights_applied,
            final_score=round(final * 100.0, 2),
            risk_score=round(final, 4),
            formula_version=res.formula_version,
            calculated_at=res.calculated_at,
            provenance=res.provenance,
        )

    def evaluate_risk(
        self,
        target_id: str,
        target_type: str,
        severity: AlertSeverity,
        confidence: float = 1.0,
        anomaly_deviation: float = 0.0,
        sequence_stage_count: int = 0,
        is_suppressed: bool = False,
    ) -> RiskAssessment:
        """Compute transparent risk score and output detailed assessment breakdown."""
        # Factor 1: Base severity (0-100)
        sev_score = self.SEVERITY_SCORES.get(severity, 25.0)

        # Factor 2: Anomaly deviation (normalized to 0-100, capping z-score at 6.0)
        anom_score = min(100.0, max(0.0, (anomaly_deviation / 6.0) * 100.0))

        # Factor 3: Sequence kill-chain contribution (0-100, based on number of stages)
        seq_score = min(100.0, sequence_stage_count * 25.0)

        # Factor 4: Confidence modifier (0-100)
        conf_score = max(0.0, min(1.0, confidence)) * 100.0

        w = self.weights
        weighted_sum = (
            (sev_score * w.severity_weight)
            + (anom_score * w.anomaly_weight)
            + (seq_score * w.sequence_weight)
            + (conf_score * w.confidence_weight)
        )

        if is_suppressed:
            # Suppressed alerts have risk mitigated to minimum
            final_score = max(5.0, weighted_sum * 0.1)
        else:
            final_score = min(100.0, max(0.0, weighted_sum))

        factors = {
            "severity_factor": sev_score,
            "anomaly_factor": anom_score,
            "sequence_factor": seq_score,
            "confidence_factor": conf_score,
        }

        weights_applied = {
            "severity_weight": w.severity_weight,
            "anomaly_weight": w.anomaly_weight,
            "sequence_weight": w.sequence_weight,
            "confidence_weight": w.confidence_weight,
        }

        return RiskAssessment(
            assessment_id=f"risk-{uuid.uuid4().hex[:12]}",
            target_id=target_id,
            target_type=target_type,
            base_score=round(sev_score, 2),
            contributing_factors=factors,
            weights_applied=weights_applied,
            final_score=round(final_score, 2),
            formula_version=RISK_FORMULA_VERSION,
            calculated_at=datetime.now(UTC).isoformat(),
            provenance=_ProvenanceFactory.SCORED,
        )
