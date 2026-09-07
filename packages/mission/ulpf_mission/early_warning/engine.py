"""Early warning engine for Phase 10 — detects pre-incident threat acceleration."""

from __future__ import annotations

import time

from ulpf_mission.models.early_warning import (
    EarlyWarningAssessment,
    EarlyWarningIndicatorType,
    EarlyWarningSignal,
)


class EarlyWarningEngine:
    """Detects pre-incident threat acceleration patterns.

    All detection logic is deterministic and threshold-based;
    no external ML models or network calls are required.
    """

    # Ratio thresholds (observed / baseline) that constitute a signal
    _ACCELERATION_THRESHOLD: float = 1.5   # 50% above baseline
    _SURGE_THRESHOLD: float = 2.0          # 2× baseline
    _BURST_THRESHOLD: float = 3.0          # 3× baseline

    def analyze(
        self,
        *,
        # Failure / error rates
        current_failure_rate: float,
        baseline_failure_rate: float,
        # Source diversity (unique source IPs per window)
        current_source_count: int,
        baseline_source_count: int,
        # Destination diversity
        current_dest_count: int,
        baseline_dest_count: int,
        # TI match velocity (matches per window)
        current_ti_velocity: int,
        baseline_ti_velocity: int,
        # Anomaly count in window
        current_anomaly_count: int,
        baseline_anomaly_count: int,
        # Privilege escalation events in window
        privilege_escalation_events: int,
        baseline_priv_events: int,
        # Lateral movement events in window
        lateral_movement_events: int,
        baseline_lateral_events: int,
        evidence_ids: list[str] | None = None,
    ) -> EarlyWarningAssessment:
        """Run all indicator checks and return an aggregated assessment."""
        ev_ids = evidence_ids or []
        signals: list[EarlyWarningSignal] = []

        def _ratio(observed: float, base: float) -> float:
            return observed / max(0.001, base)

        # --- Failure rate acceleration
        fr_ratio = _ratio(current_failure_rate, baseline_failure_rate)
        if fr_ratio >= self._ACCELERATION_THRESHOLD:
            signals.append(
                EarlyWarningSignal(
                    indicator_type=EarlyWarningIndicatorType.FAILURE_RATE_ACCELERATION,
                    description="Error/failure rate is accelerating above baseline.",
                    confidence=min(1.0, (fr_ratio - 1.0) / 3.0),
                    observed_value=current_failure_rate,
                    baseline_value=baseline_failure_rate,
                    deviation_ratio=fr_ratio,
                    evidence_ids=ev_ids,
                )
            )

        # --- Source diversity surge
        src_ratio = _ratio(current_source_count, max(1, baseline_source_count))
        if src_ratio >= self._SURGE_THRESHOLD:
            signals.append(
                EarlyWarningSignal(
                    indicator_type=EarlyWarningIndicatorType.SOURCE_DIVERSITY_SURGE,
                    description="Unique source count has surged, indicating potential scanning.",
                    confidence=min(1.0, (src_ratio - 1.0) / 4.0),
                    observed_value=float(current_source_count),
                    baseline_value=float(baseline_source_count),
                    deviation_ratio=src_ratio,
                    evidence_ids=ev_ids,
                )
            )

        # --- Destination diversity surge
        dst_ratio = _ratio(current_dest_count, max(1, baseline_dest_count))
        if dst_ratio >= self._SURGE_THRESHOLD:
            signals.append(
                EarlyWarningSignal(
                    indicator_type=EarlyWarningIndicatorType.DESTINATION_DIVERSITY_SURGE,
                    description="Unique destination count has surged, possible lateral movement.",
                    confidence=min(1.0, (dst_ratio - 1.0) / 4.0),
                    observed_value=float(current_dest_count),
                    baseline_value=float(baseline_dest_count),
                    deviation_ratio=dst_ratio,
                    evidence_ids=ev_ids,
                )
            )

        # --- TI match velocity
        ti_ratio = _ratio(current_ti_velocity, max(1, baseline_ti_velocity))
        if ti_ratio >= self._SURGE_THRESHOLD:
            signals.append(
                EarlyWarningSignal(
                    indicator_type=EarlyWarningIndicatorType.TI_MATCH_VELOCITY,
                    description="Threat intelligence match rate is accelerating.",
                    confidence=min(1.0, (ti_ratio - 1.0) / 4.0),
                    observed_value=float(current_ti_velocity),
                    baseline_value=float(baseline_ti_velocity),
                    deviation_ratio=ti_ratio,
                    evidence_ids=ev_ids,
                )
            )

        # --- Anomaly burst
        an_ratio = _ratio(current_anomaly_count, max(1, baseline_anomaly_count))
        if an_ratio >= self._BURST_THRESHOLD:
            signals.append(
                EarlyWarningSignal(
                    indicator_type=EarlyWarningIndicatorType.ANOMALY_BURST,
                    description="Anomaly count has burst beyond 3× baseline.",
                    confidence=min(1.0, (an_ratio - 1.0) / 5.0),
                    observed_value=float(current_anomaly_count),
                    baseline_value=float(baseline_anomaly_count),
                    deviation_ratio=an_ratio,
                    evidence_ids=ev_ids,
                )
            )

        # --- Privilege escalation pattern
        priv_ratio = _ratio(privilege_escalation_events, max(1, baseline_priv_events))
        if priv_ratio >= self._SURGE_THRESHOLD:
            signals.append(
                EarlyWarningSignal(
                    indicator_type=EarlyWarningIndicatorType.PRIVILEGE_ESCALATION_PATTERN,
                    description="Privilege escalation events are elevated above baseline.",
                    confidence=min(1.0, (priv_ratio - 1.0) / 3.0),
                    observed_value=float(privilege_escalation_events),
                    baseline_value=float(baseline_priv_events),
                    deviation_ratio=priv_ratio,
                    evidence_ids=ev_ids,
                )
            )

        # --- Lateral movement pattern
        lat_ratio = _ratio(lateral_movement_events, max(1, baseline_lateral_events))
        if lat_ratio >= self._SURGE_THRESHOLD:
            signals.append(
                EarlyWarningSignal(
                    indicator_type=EarlyWarningIndicatorType.LATERAL_MOVEMENT_PATTERN,
                    description="Lateral movement indicators are elevated above baseline.",
                    confidence=min(1.0, (lat_ratio - 1.0) / 3.0),
                    observed_value=float(lateral_movement_events),
                    baseline_value=float(baseline_lateral_events),
                    deviation_ratio=lat_ratio,
                    evidence_ids=ev_ids,
                )
            )

        # Aggregate
        if signals:
            overall_confidence = min(1.0, sum(s.confidence for s in signals) / len(signals))
            threat_score = min(100.0, len(signals) * 15.0 + overall_confidence * 25.0)
        else:
            overall_confidence = 0.0
            threat_score = 0.0

        action = (
            "ESCALATE: Immediate analyst review required."
            if threat_score >= 50.0
            else "MONITOR: Continue passive observation."
        )

        return EarlyWarningAssessment(
            signals=signals,
            overall_confidence=round(overall_confidence, 4),
            threat_acceleration_score=round(threat_score, 2),
            recommended_action=action,
            timestamp=time.time(),
        )
