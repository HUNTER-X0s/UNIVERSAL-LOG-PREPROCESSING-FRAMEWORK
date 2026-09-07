"""Automated, Explainable Alert Triage Classifier for ULPF Phase 9."""

from __future__ import annotations

from ulpf_advanced_intelligence.models.alerts import (
    AlertTriageSeverity,
)


class AlertTriageClassifier:
    """Classifies alerts into normalized severity tiers based on risk scores, TI matches, and asset impact."""

    @classmethod
    def classify(
        cls,
        risk_score: float,
        has_critical_ti: bool = False,
        asset_criticality: str = "MEDIUM",
        is_external_facing: bool = False,
        is_multi_stage: bool = False,
    ) -> tuple[AlertTriageSeverity, str]:
        """Produce an explainable triage classification and rationale."""
        reasons: list[str] = [f"Base risk score: {risk_score:.1f}"]

        # Critical Escalation Overrides
        if has_critical_ti and (asset_criticality == "CRITICAL" or is_multi_stage):
            return AlertTriageSeverity.CRITICAL, "Critical priority: active multi-stage attack or critical asset matched high-confidence TI"

        if has_critical_ti:
            reasons.append("High-confidence Threat Intelligence match")

        if asset_criticality == "CRITICAL":
            reasons.append("High-value target asset (CRITICAL)")

        if is_multi_stage:
            reasons.append("Coordinated multi-stage progression")

        if risk_score >= 85.0:
            severity = AlertTriageSeverity.CRITICAL
        elif risk_score >= 65.0:
            severity = AlertTriageSeverity.HIGH
        elif risk_score >= 40.0:
            severity = AlertTriageSeverity.MEDIUM
        elif risk_score >= 20.0:
            severity = AlertTriageSeverity.LOW
        else:
            severity = AlertTriageSeverity.INFORMATIONAL

        reason_str = "; ".join(reasons)
        return severity, reason_str
