"""Deterministic Explainability Engine for ULPF Phase 8."""

from __future__ import annotations

from typing import Any

from ulpf_intelligence.models.events import IntelligenceExplanation


class ExplainabilityEngine:
    """Generates deterministic, structured explanations answering WHAT, WHEN, WHERE, WHO, WHY."""

    def generate_explanation(
        self,
        rule: Any,
        event_payload: dict[str, Any],
        matched_event_ids: list[str],
        raw_hashes: list[str],
        observed_count: int = 1,
    ) -> IntelligenceExplanation:
        """Generate structured explanation from rule and event context."""
        who = str(event_payload.get("user") or event_payload.get("src_ip") or "unknown")
        where = str(event_payload.get("host") or event_payload.get("dst_ip") or "perimeter")
        what = rule.name
        when = str(event_payload.get("timestamp") or "2026-09-07T12:00:00Z")
        why = f"Triggered by pattern matching rule criteria: {event_payload.get('command', '')}"
        tactics = list(getattr(rule, "mitre_tactics", []))
        techniques = list(getattr(rule, "mitre_techniques", []))
        return IntelligenceExplanation(
            what=what,
            when=when,
            where=where,
            who=who,
            why=why,
            rule_id=rule.rule_id,
            rule_version=rule.version,
            observed_value=observed_count,
            contributing_event_ids=tuple(matched_event_ids),
            confidence=getattr(rule, "confidence", 1.0),
            mitre_mapping={"tactics": tactics, "techniques": techniques},
        )

    @staticmethod
    def build_explanation(
        what: str,
        when: str,
        where: str,
        who: str,
        rule_id: str,
        rule_version: str,
        threshold: Any = None,
        observed_value: Any = None,
        contributing_event_ids: tuple[str, ...] = (),
        assumptions: tuple[str, ...] = (),
        confidence: float = 1.0,
        custom_reason: str | None = None,
    ) -> IntelligenceExplanation:
        """Construct an explainable, machine-and-human readable decision record."""
        if custom_reason:
            why = custom_reason
        elif threshold is not None and observed_value is not None:
            why = (
                f"Observed value ({observed_value}) breached configured threshold "
                f"({threshold}) under rule '{rule_id}' (v{rule_version})."
            )
        else:
            why = f"Matched explicit criteria defined in detection rule '{rule_id}' (v{rule_version})."

        return IntelligenceExplanation(
            what=what,
            when=when,
            where=where,
            who=who,
            why=why,
            rule_id=rule_id,
            rule_version=rule_version,
            threshold=threshold,
            observed_value=observed_value,
            contributing_event_ids=contributing_event_ids,
            assumptions=assumptions,
            confidence=confidence,
        )
