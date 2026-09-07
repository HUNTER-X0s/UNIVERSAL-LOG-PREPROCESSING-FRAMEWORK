"""Air-Gapped Offline SOC Analyst Advisor and Prompt-Injection Defense for ULPF Phase 9."""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any

from ulpf_advanced_intelligence.models.alerts import AlertRecord
from ulpf_advanced_intelligence.models.workflows import ActionApprovalState, SOARAction
from ulpf_intelligence.models.events import InvestigationCase

_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"system\s*prompt\s*override", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+in\s+developer\s+mode", re.IGNORECASE),
]


class AdvancedAnalystAdvisor:
    """Offline deterministic advisor providing explainable investigation guidance and proposed actions."""

    MODEL_ID = "OFFLINE_DETERMINISTIC_ADVISOR"
    VERSION = "2.0.0"

    @classmethod
    def sanitize_untrusted_input(cls, text: str) -> str:
        """Strip dangerous prompt-injection tokens from log payloads before analysis."""
        clean = text
        for pat in _INJECTION_PATTERNS:
            clean = pat.sub("[REDACTED_SUSPICIOUS_TOKEN]", clean)
        return clean

    @classmethod
    def advise_case(
        cls,
        case: InvestigationCase,
        alerts: list[AlertRecord] | None = None,
    ) -> dict[str, Any]:
        """Generate offline, deterministic triage recommendations and proposed actions."""
        now_iso = datetime.now(UTC).isoformat()
        primary_entity = case.entity_ids[0] if case.entity_ids else "unknown"

        steps: list[str] = [
            f"Review network telemetry for canonical entity '{primary_entity}'",
            "Verify local Threat Intelligence indicator status",
            "Examine off-hours authentication transitions",
        ]

        if alerts and any(a.severity.value == "CRITICAL" for a in alerts):
            steps.insert(0, "URGENT: Critical alerts detected. Escalate case to SOC Lead immediately.")

        # Propose safe, non-destructive SOAR action
        proposed_action = SOARAction(
            action_id=f"act-{uuid.uuid4().hex[:8]}",
            action_type="ADD_TAG",
            target=case.case_id,
            parameters={"tag": "NEEDS_SOC_TIER2_REVIEW"},
            approval_state=ActionApprovalState.PROPOSED,
            proposed_by=cls.MODEL_ID,
            tenant_id=case.tenant_id,
        )

        return {
            "ai_generated": True,
            "advisory_only": True,
            "model": cls.MODEL_ID,
            "model_version": cls.VERSION,
            "generated_at": now_iso,
            "case_id": case.case_id,
            "primary_entity": primary_entity,
            "recommended_investigation_steps": steps,
            "missing_evidence_checklist": [
                "Endpoint host logs",
                "Perimeter firewall session tables",
                "DNS resolver query logs",
            ],
            "proposed_soar_actions": [proposed_action.to_dict()],
        }
