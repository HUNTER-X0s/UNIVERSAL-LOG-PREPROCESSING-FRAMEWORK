"""Offline Local Analyst Advisory Assistant for ULPF Phase 8."""

from __future__ import annotations

from typing import Any

from ulpf_intelligence.models.events import InvestigationCase


class LocalAnalystAdvisor:
    """Provides offline analyst assistance and summaries, strictly marked as advisory AI_GENERATED."""

    @staticmethod
    def generate_case_summary(case: InvestigationCase) -> dict[str, Any]:
        """Generate an explainable, structured incident summary for an analyst."""
        entity_count = len(case.entity_ids)
        event_count = len(case.event_ids)
        detection_count = len(case.detection_ids)

        summary_text = (
            f"Case '{case.title}' ({case.case_id}) currently in state {case.status.value} "
            f"with priority {case.priority.value}. Incident encompasses {event_count} contributing "
            f"events, {detection_count} detections, and {entity_count} affected entities. "
            f"Key entities under investigation: {', '.join(case.entity_ids[:5]) if case.entity_ids else 'None'}."
        )

        res = {
            "case_id": case.case_id,
            "title": case.title,
            "status": case.status.value,
            "summary": f"Incident Analysis for {case.title}: {summary_text}",
            "suggested_actions": [
                "Inspect high-severity detections for root-cause rule breach",
                "Review chronological timeline for lateral movement progression",
                "Verify affected entity exposure in relationship graph",
            ],
            "recommended_actions": [
                "Inspect high-severity detections for root-cause rule breach",
                "Review chronological timeline for lateral movement progression",
                "Verify affected entity exposure in relationship graph",
            ],
            "attribution": "AI_GENERATED",
            "provenance_tag": "AI_GENERATED",
            "is_advisory_only": True,
        }
        return res

    @classmethod
    def summarize_case(cls, case: InvestigationCase) -> dict[str, Any]:
        """Convenience alias for generate_case_summary."""
        return cls.generate_case_summary(case)

    @staticmethod
    def suggest_hunting_query(entity: str) -> dict[str, Any]:
        """Suggest structured parameters for hunting query around a flagged entity."""
        return {
            "entity": entity,
            "suggested_filters": {"action": "DENY"},
            "time_window_hours": 24,
            "attribution": "AI_GENERATED",
            "is_advisory_only": True,
        }
