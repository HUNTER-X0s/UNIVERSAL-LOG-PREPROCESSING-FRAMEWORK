"""Deterministic Detection Engine for ULPF Phase 8."""

from __future__ import annotations

import threading
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from ulpf_intelligence.models.events import (
    DetectionEvent,
    DetectionEvidence,
    IntelligenceExplanation,
)
from ulpf_intelligence.models.provenance import AlertSeverity, AlertStatus, IntelligenceProvenance
from ulpf_intelligence.rules.registry import RuleRegistry


class DetectionEngine:
    """Evaluates canonical events against versioned rules, generating explainable detections."""

    def __init__(
        self,
        registry: RuleRegistry | None = None,
        rule_registry: RuleRegistry | None = None,
    ) -> None:
        self.registry = rule_registry or registry or RuleRegistry()
        # (rule_id, group_by_value) -> list of (timestamp_epoch, raw_event_id)
        self._threshold_windows: dict[tuple[str, str], list[tuple[float, str]]] = {}
        self._lock = threading.Lock()

    def evaluate(
        self,
        event_payload: dict[str, Any],
        event_id: str,
        tenant_id: str = "default",
        timestamp: str | None = None,
        raw_hash: str = "",
    ) -> list[DetectionEvent]:
        """Convenience method evaluating an event payload."""
        return self.evaluate_event(
            event_dict=event_payload,
            raw_event_id=event_id,
            uce_event_id=f"uce-{event_id}",
            source_id="perimeter",
            tenant_id=tenant_id,
            raw_hash=raw_hash,
        )

    def evaluate_event(
        self,
        event_dict: dict[str, Any],
        raw_event_id: str,
        uce_event_id: str,
        source_id: str,
        semantic_event_id: str | None = None,
        tenant_id: str | None = None,
        raw_hash: str = "",
    ) -> list[DetectionEvent]:
        """Evaluate a single event against all active rules and return triggered detections."""
        detections: list[DetectionEvent] = []
        active_rules = self.registry.get_active_rules(tenant_id=tenant_id)
        now_iso = datetime.now(UTC).isoformat()
        now_epoch = time.time()

        for rule in active_rules:
            # 1. Evaluate static conditions
            conditions_met = all(cond.evaluate(event_dict) for cond in rule.conditions)
            if not conditions_met:
                continue

            # 2. Check threshold / frequency window
            observed_count = 1
            contributing_ids = [raw_event_id]
            if rule.threshold is not None:
                group_field = rule.threshold.group_by if hasattr(rule.threshold, "group_by") else None
                if not group_field and hasattr(rule.threshold, "group_by_fields") and rule.threshold.group_by_fields:
                    group_field = rule.threshold.group_by_fields[0]
                group_val = str(event_dict.get(group_field, "all")) if group_field else "all"

                with self._lock:
                    key = (rule.rule_id, group_val)
                    window_cutoff = now_epoch - rule.threshold.window_seconds
                    records = self._threshold_windows.setdefault(key, [])
                    records = [r for r in records if r[0] > window_cutoff]
                    records.append((now_epoch, raw_event_id))
                    self._threshold_windows[key] = records

                    if len(records) < rule.threshold.count:
                        continue

                    # Threshold breached
                    contributing_ids = [r[1] for r in records]
                    observed_count = len(records)
                    # Reset after trigger
                    self._threshold_windows[key] = []

            # 3. Extract relevant entities
            entity_ids: list[str] = []
            for candidate_key in ("src_ip", "dst_ip", "user", "username", "host", "domain", "process"):
                if candidate_key in event_dict:
                    val = str(event_dict[candidate_key])
                    if val and val != "None":
                        entity_ids.append(val)

            # 4. Build evidence and explanation
            evidence = DetectionEvidence(
                matched_event_ids=tuple(contributing_ids),
                raw_hashes=(raw_hash,) if raw_hash else (),
                trigger_field=next(
                    (c.field for c in rule.conditions if event_dict.get(c.field) is not None), ""
                ),
                trigger_value=event_dict.get(
                    next((c.field for c in rule.conditions if event_dict.get(c.field) is not None), ""),
                    None,
                ),
                observed_count=observed_count,
                time_window_seconds=rule.threshold.window_seconds if rule.threshold else 0,
                source_id=source_id,
                captured_at=now_iso,
            )

            mitre_mapping = {
                "tactics": list(rule.mitre_tactics) if hasattr(rule, "mitre_tactics") else [],
                "techniques": list(rule.mitre_techniques) if hasattr(rule, "mitre_techniques") else [],
            }

            who_parts = [str(eid) for eid in entity_ids]
            explanation = IntelligenceExplanation(
                what=rule.name,
                when=now_iso,
                where=source_id,
                who=", ".join(who_parts) if who_parts else "unknown",
                why=f"Matched rule '{rule.name}' (v{rule.version}): {rule.description}",
                rule_id=rule.rule_id,
                rule_version=rule.version,
                threshold=rule.threshold.count if rule.threshold else 1,
                observed_value=observed_count,
                contributing_event_ids=tuple(contributing_ids),
                confidence=rule.confidence,
                mitre_mapping=mitre_mapping,
            )

            prov = IntelligenceProvenance(
                source_events=contributing_ids,
                source_rules=[rule.rule_id],
                derivation_method="DETERMINISTIC",
                generated_by="DETECTION_ENGINE",
                is_derived=True,
            )

            severity = rule.severity
            if isinstance(severity, str):
                severity = AlertSeverity(severity)

            detection = DetectionEvent(
                detection_id=f"det-{uuid.uuid4().hex[:12]}",
                rule_id=rule.rule_id,
                rule_version=rule.version,
                title=rule.name,
                description=rule.description,
                severity=severity,
                confidence=rule.confidence,
                risk_score=getattr(rule, "base_risk", 50.0),
                status=AlertStatus.NEW,
                created_at=now_iso,
                detected_at=now_iso,
                indexed_at=now_iso,
                tenant_id=tenant_id,
                entity_ids=tuple(entity_ids),
                evidence=evidence,
                explanation=explanation,
                mitre_attack_technique=getattr(rule, "mitre_attack", None),
                mitre_tactics=tuple(getattr(rule, "mitre_tactics", [])),
                mitre_techniques=tuple(getattr(rule, "mitre_techniques", [])),
                provenance=prov,
            )
            detections.append(detection)

        return detections
