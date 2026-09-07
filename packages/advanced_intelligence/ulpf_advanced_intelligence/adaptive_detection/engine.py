"""Adaptive Composite Detection Engine for ULPF Phase 9."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from ulpf_advanced_intelligence.content.lifecycle import AdvancedDetectionRule
from ulpf_advanced_intelligence.models.alerts import (
    AlertLifecycleStatus,
    AlertRecord,
    AlertTriageSeverity,
)
from ulpf_advanced_intelligence.models.behavior import EntityBehaviorProfile
from ulpf_advanced_intelligence.models.threat_intel import ThreatIntelAssessment, ThreatIntelStatus
from ulpf_intelligence.models.events import AnomalyEvent, DetectionEvent, DetectionEvidence
from ulpf_intelligence.models.provenance import AlertSeverity, AlertStatus, IntelligenceProvenance


class AdaptiveDetectionEngine:
    """Evaluates multi-layer composite detection rules with full factor transparency."""

    @classmethod
    def evaluate(
        cls,
        event: dict[str, Any],
        rules: list[AdvancedDetectionRule],
        ti_assessment: ThreatIntelAssessment | None = None,
        behavior_profile: EntityBehaviorProfile | None = None,
        anomaly: AnomalyEvent | None = None,
        asset_criticality: str = "MEDIUM",
        is_external_facing: bool = False,
    ) -> list[tuple[DetectionEvent, AlertRecord]]:
        """Evaluate event across rules and intelligence context to produce detection events and alerts."""
        results: list[tuple[DetectionEvent, AlertRecord]] = []
        event_id = str(event.get("event_id") or event.get("id") or f"evt-{uuid.uuid4().hex[:8]}")
        tenant_id = event.get("tenant_id")
        entity_id = str(event.get("src_ip") or event.get("host") or event.get("username") or "unknown-entity")

        for rule in rules:
            if not cls._matches_rule(rule, event):
                continue

            factors: list[str] = [f"RULE_MATCH:{rule.rule_id}"]
            base_risk = 40.0
            severity = AlertTriageSeverity.MEDIUM

            # Factor 1: Threat Intelligence boost
            ti_match_ids: list[str] = []
            if ti_assessment and ti_assessment.matches:
                for m in ti_assessment.matches:
                    ti_match_ids.append(m.indicator_id)
                    factors.append(f"TI_MATCH:{m.source}:{m.matched_value}")
                base_risk += ti_assessment.total_risk_contribution
                if ti_assessment.highest_severity_status in (ThreatIntelStatus.MALICIOUS, ThreatIntelStatus.BLOCKED):
                    severity = AlertTriageSeverity.CRITICAL

            # Factor 2: Behavioral Profile deviation
            if behavior_profile:
                if behavior_profile.drift_state.value == "DRIFTING":
                    base_risk += 15.0
                    factors.append("BEHAVIOR_BASELINE_DRIFTING")
                elif behavior_profile.drift_state.value in ("CHANGED", "RESET_REQUIRED"):
                    base_risk += 25.0
                    factors.append(f"BEHAVIOR_BASELINE_{behavior_profile.drift_state.value}")

                # Check off-hours
                event_time_str = event.get("timestamp") or event.get("captured_at")
                if event_time_str:
                    try:
                        dt = datetime.fromisoformat(str(event_time_str))
                        if dt.hour not in behavior_profile.normal_hours:
                            base_risk += 10.0
                            factors.append(f"OFF_HOURS_ACTIVITY:{dt.hour}h")
                    except (ValueError, TypeError):
                        pass

            # Factor 3: Statistical Anomaly
            anomaly_ids: list[str] = []
            if anomaly:
                anomaly_ids.append(anomaly.anomaly_id)
                factors.append(f"STATISTICAL_ANOMALY:z={anomaly.z_score:.2f}")
                base_risk += min(30.0, anomaly.z_score * 8.0)

            # Factor 4: Asset criticality and exposure multipliers
            if asset_criticality == "CRITICAL":
                base_risk *= 1.3
                factors.append("CRITICAL_ASSET_MULTIPLIER:1.3x")
            elif asset_criticality == "HIGH":
                base_risk *= 1.15
                factors.append("HIGH_ASSET_MULTIPLIER:1.15x")

            if is_external_facing:
                base_risk *= 1.2
                factors.append("EXTERNAL_FACING_MULTIPLIER:1.2x")

            final_risk = min(100.0, round(base_risk, 2))

            # Assign triage severity according to final composite risk
            if final_risk >= 85.0:
                severity = AlertTriageSeverity.CRITICAL
            elif final_risk >= 70.0:
                severity = AlertTriageSeverity.HIGH
            elif final_risk >= 45.0:
                severity = AlertTriageSeverity.MEDIUM
            elif final_risk >= 20.0:
                severity = AlertTriageSeverity.LOW
            else:
                severity = AlertTriageSeverity.INFORMATIONAL

            # Build DetectionEvent
            det_id = f"det-adv-{uuid.uuid4().hex[:10]}"
            ev_evidence = DetectionEvidence(
                matched_event_ids=(event_id,),
                raw_hashes=(str(event.get("raw_hash", "")),),
                trigger_field=rule.conditions[0].field if rule.conditions else "event",
                trigger_value=str(rule.conditions[0].value) if rule.conditions else "matched",
            )
            detection_event = DetectionEvent(
                detection_id=det_id,
                tenant_id=tenant_id,
                rule_id=rule.rule_id,
                rule_version=rule.version,
                severity=AlertSeverity.HIGH if severity in (AlertTriageSeverity.HIGH, AlertTriageSeverity.CRITICAL) else AlertSeverity.MEDIUM,
                title=rule.name,
                description=rule.description,
                status=AlertStatus.NEW,
                entity_ids=(entity_id,),
                evidence=ev_evidence,
                provenance=IntelligenceProvenance(
                    source_events=[event_id],
                    source_rules=[rule.rule_id],
                    derivation_method="ADAPTIVE_COMPOSITE",
                    generated_by="ADAPTIVE_DETECTION_ENGINE",
                ),
                mitre_tactics=tuple(rule.mitre_tactics),
                mitre_techniques=tuple(rule.mitre_techniques),
            )

            # Build AlertRecord
            alert_id = f"alert-{uuid.uuid4().hex[:10]}"
            alert_record = AlertRecord(
                alert_id=alert_id,
                title=f"[Alert] {rule.name}",
                description=f"{rule.description} on {entity_id}",
                severity=severity,
                status=AlertLifecycleStatus.NEW,
                tenant_id=tenant_id,
                primary_entity_id=entity_id,
                entity_ids=(entity_id,),
                detection_ids=(det_id,),
                anomaly_ids=tuple(anomaly_ids),
                ti_match_ids=tuple(ti_match_ids),
                risk_score=final_risk,
                triage_reason=f"Composite evaluation triggered with score {final_risk}",
                contributing_factors=tuple(factors),
            )

            results.append((detection_event, alert_record))

        return results

    @staticmethod
    def _matches_rule(rule: AdvancedDetectionRule, event: dict[str, Any]) -> bool:
        if not rule.conditions:
            return True
        return all(cond.evaluate(event) for cond in rule.conditions)
