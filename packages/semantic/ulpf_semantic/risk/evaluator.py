"""Deterministic Risk Evaluator for ULPF Phase 4.

Calculates risk score (0-100) and risk level deterministically based on
observable event indicators, severity, action, and outcome without external ML.
"""

from typing import Any

from ulpf_semantic.models import RiskContext


class RiskEvaluator:
    """Evaluates objective risk metrics based on observable event attributes."""

    @staticmethod
    def evaluate(
        severity: int,
        action: str,
        result_status: str,
        is_security_event: bool,
        has_public_indicators: bool,
        uce_event: dict[str, Any],
    ) -> RiskContext:
        """Compute deterministic risk context."""
        base_score = float(severity * 10)  # Severity 0-10 maps to 0-100
        reasons: list[str] = []

        if severity >= 8:
            reasons.append("HIGH_OBSERVED_SEVERITY")
        elif severity >= 5:
            reasons.append("MEDIUM_OBSERVED_SEVERITY")

        # Adjust for security findings / restrictive actions
        if is_security_event:
            reasons.append("SECURITY_FINDING_EVENT")
            if action in ("drop", "deny", "block"):
                base_score = max(base_score, 60.0)
                reasons.append("RESTRICTIVE_POLICY_ACTION")

        if result_status in ("FAILURE", "DENIED", "BLOCKED"):
            reasons.append("BLOCKED_OR_FAILED_OUTCOME")
            base_score = max(base_score, 50.0)

        if has_public_indicators:
            reasons.append("EXTERNAL_INDICATOR_OBSERVED")
            base_score = min(100.0, base_score + 10.0)

        # Map to Risk Level
        score = min(100.0, max(0.0, base_score))
        if score >= 80.0:
            level = "CRITICAL"
        elif score >= 60.0:
            level = "HIGH"
        elif score >= 40.0:
            level = "MEDIUM"
        elif score >= 20.0:
            level = "LOW"
        else:
            level = "INFORMATIONAL"

        return RiskContext(
            risk_level=level,
            risk_score=score,
            reason_codes=tuple(reasons),
            confidence=0.95,
        )
