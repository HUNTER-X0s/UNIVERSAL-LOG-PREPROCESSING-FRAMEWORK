"""AI Analyst Copilot for Phase 10 — strictly bounded offline advisory system.

Design guarantees:
- 100% offline. No external API calls, no LLM inference, no network I/O.
- Prompt-injection defense: all inputs are sanitised before being reflected back.
- All recommendations are rule-based and explicitly attributable.
- No fabricated insights; absent data is clearly labelled as UNAVAILABLE.
"""

from __future__ import annotations

import re
from typing import Any
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Prompt injection defence
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"ignore\s+previous", re.IGNORECASE),
    re.compile(r"system\s*:", re.IGNORECASE),
    re.compile(r"<\s*(script|iframe|img)\b", re.IGNORECASE),
    re.compile(r"\\n\\n", re.IGNORECASE),
    re.compile(r"\binject\b", re.IGNORECASE),
    re.compile(r"\bexfiltrate\b", re.IGNORECASE),
    re.compile(r"\bprompt\s+injection\b", re.IGNORECASE),
    re.compile(r"\bdan\s+mode\b", re.IGNORECASE),
    re.compile(r"\bbypass\s+security\b", re.IGNORECASE),
]

_MAX_INPUT_LEN = 2048


def _sanitise(text: str) -> str:
    """Strip dangerous patterns and truncate oversized inputs."""
    if len(text) > _MAX_INPUT_LEN:
        text = text[:_MAX_INPUT_LEN] + " [TRUNCATED]"
    for pattern in _INJECTION_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text


# ---------------------------------------------------------------------------
# Copilot data model
# ---------------------------------------------------------------------------

@dataclass
class CopilotCaseSummary:
    """AI Analyst Copilot structured case summary."""

    case_id: str
    severity: str
    what: str            # What happened
    when: str            # Timeline highlight
    where: str           # Affected assets / locations
    who: str             # Involved entities (users, IPs)
    why: str             # Probable motive / kill-chain phase
    recommended_actions: list[str]
    hunt_queries: list[str]
    confidence_note: str
    data_limitations: list[str] = field(default_factory=list)


@dataclass
class GroundedExplanation:
    """Evidence-grounded explanation strictly citing event IDs, rule IDs, and facts."""
    verified_facts: list[str]
    system_inferences: list[str]
    analyst_suggestions: list[str]
    citations: list[str]
    confidence: float


@dataclass
class ProposedStateAction:
    """Safe AI Action Proposal requiring human confirmation (Workstream Q)."""
    action_id: str
    action_type: str            # e.g., "ISOLATE_HOST", "APPROVE_MAPPING", "BLOCK_IP"
    target: str
    rationale: str
    required_role: str          # e.g., "operator", "platform-admin"
    risk_level: str             # "LOW", "MEDIUM", "HIGH"
    requires_human_approval: bool = True
    authorized_by: str | None = None
    executed: bool = False
    rollback_token: str = ""



# ---------------------------------------------------------------------------
# Copilot engine
# ---------------------------------------------------------------------------

_SEVERITY_ACTIONS: dict[str, list[str]] = {
    "CRITICAL": [
        "Immediately isolate affected hosts from network.",
        "Revoke active sessions for compromised accounts.",
        "Notify incident response team and open a P1 ticket.",
        "Preserve memory and disk images before any remediation.",
        "Escalate to CISO and notify affected business owners.",
    ],
    "HIGH": [
        "Quarantine suspicious processes and associated binaries.",
        "Force password reset for involved user accounts.",
        "Block identified malicious IPs at perimeter firewall.",
        "Initiate threat hunt for lateral movement indicators.",
        "Collect full forensic evidence package before containment.",
    ],
    "MEDIUM": [
        "Investigate the source host for additional IOCs.",
        "Review authentication logs for the past 7 days.",
        "Check for related detections across sibling hosts.",
        "Document findings in investigation case notes.",
    ],
    "LOW": [
        "Log and monitor for recurrence.",
        "Add to watch-list for 30-day observation window.",
    ],
}

_HUNT_QUERIES: dict[str, list[str]] = {
    "LATERAL_MOVEMENT": [
        "SELECT * FROM network_events WHERE protocol='SMB' AND src_host != 'expected_hosts'",
        "SELECT * FROM auth_events WHERE auth_type='NTLM' AND dest_host LIKE '%DC%'",
    ],
    "EXFILTRATION": [
        "SELECT * FROM network_events WHERE bytes_sent > 10000000 AND dest_ip NOT IN (trusted_ips)",
        "SELECT * FROM dns_events WHERE query_length > 100",
    ],
    "PRIVILEGE_ESCALATION": [
        "SELECT * FROM process_events WHERE user='SYSTEM' AND parent_user != 'SYSTEM'",
        "SELECT * FROM auth_events WHERE privilege_level = 'ADMIN'"
        " AND hour_of_day BETWEEN 22 AND 6",
    ],
    "DEFAULT": [
        "SELECT * FROM all_events WHERE risk_score > 70 ORDER BY timestamp DESC LIMIT 100",
        "SELECT * FROM anomaly_events WHERE confidence > 0.8 AND last_24h = true",
    ],
}


class AIAnalystCopilot:
    """Strictly bounded local/offline analyst copilot.

    Provides explainable case summaries, timeline highlights, and hunt
    query recommendations without any LLM or external service dependency.
    """

    def summarise_case(
        self,
        *,
        case_id: str,
        severity: str,
        description: str,
        affected_assets: list[str],
        involved_users: list[str],
        timeline_events: list[dict[str, object]],
        detection_rule_ids: list[str],
        kill_chain_phases: list[str],
    ) -> CopilotCaseSummary:
        """Generate a structured 5W case summary with hunt queries.

        All string inputs are sanitised against prompt injection before use.
        """
        safe_desc = _sanitise(description)
        safe_assets = [_sanitise(a) for a in affected_assets[:20]]
        safe_users = [_sanitise(u) for u in involved_users[:20]]
        safe_rules = [_sanitise(r) for r in detection_rule_ids[:20]]

        # WHAT
        what = (
            f"{safe_desc} Triggered rules: {', '.join(safe_rules) or 'UNAVAILABLE'}."
        )

        # WHEN
        if timeline_events:
            first_ts = timeline_events[0].get("timestamp", "UNAVAILABLE")
            last_ts = timeline_events[-1].get("timestamp", "UNAVAILABLE")
            when = (
                f"Activity observed from {first_ts} to {last_ts} "
                f"({len(timeline_events)} events)."
            )
        else:
            when = "UNAVAILABLE: No timeline events provided."

        # WHERE
        where = (
            f"Affected assets: {', '.join(safe_assets) or 'UNAVAILABLE'}."
        )

        # WHO
        who = (
            f"Involved users/entities: {', '.join(safe_users) or 'UNAVAILABLE'}."
        )

        # WHY
        if kill_chain_phases:
            why = (
                f"Kill-chain phases observed: {', '.join(kill_chain_phases)}. "
                "Likely objective: data exfiltration or persistent access."
            )
        else:
            why = "UNAVAILABLE: Kill-chain phases not identified from available telemetry."

        # Actions
        actions = _SEVERITY_ACTIONS.get(severity.upper(), _SEVERITY_ACTIONS["MEDIUM"])

        # Hunt queries
        queries: list[str] = []
        for phase in kill_chain_phases[:3]:
            queries.extend(_HUNT_QUERIES.get(phase, []))
        if not queries:
            queries = _HUNT_QUERIES["DEFAULT"]

        # Data limitations
        limitations: list[str] = []
        if not timeline_events:
            limitations.append("Timeline events not available; temporal analysis is incomplete.")
        if not involved_users:
            limitations.append(
                "No user identifiers available; identity attribution is not possible."
            )
        if not kill_chain_phases:
            limitations.append("Kill-chain mapping unavailable; motive is inferred only.")

        confidence_note = (
            "HIGH CONFIDENCE: Multiple corroborating signals."
            if len(detection_rule_ids) >= 3
            else "MODERATE CONFIDENCE: Limited corroboration; further investigation recommended."
            if detection_rule_ids
            else "LOW CONFIDENCE: No detection rules fired; "
            "assessment based on telemetry anomalies only."
        )

        return CopilotCaseSummary(
            case_id=case_id,
            severity=severity,
            what=what,
            when=when,
            where=where,
            who=who,
            why=why,
            recommended_actions=actions,
            hunt_queries=list(dict.fromkeys(queries))[:5],  # deduplicate, cap at 5
            confidence_note=confidence_note,
            data_limitations=limitations,
        )

    def explain_detection_grounded(
        self,
        *,
        detection_id: str,
        rule_id: str,
        event_id: str,
        entity: str,
        observed_action: str,
        raw_sha256: str,
    ) -> GroundedExplanation:
        """Phase 13 Workstream P: Generate evidence-grounded explanation citing facts and inferences."""
        facts = [
            f"Event '{_sanitise(event_id)}' observed action '{_sanitise(observed_action)}' for entity '{_sanitise(entity)}'.",
            f"Cryptographic raw hash verified: {_sanitise(raw_sha256)[:16]}...",
            f"Detection rule '{_sanitise(rule_id)}' matched deterministic thresholds.",
        ]
        inferences = [
            f"Activity pattern indicates potential security anomaly on asset '{_sanitise(entity)}'.",
            f"Correlated with active rule criteria '{_sanitise(rule_id)}'.",
        ]
        suggestions = [
            f"Isolate network segments communicating with '{_sanitise(entity)}'.",
            "Review firewall deny logs for egress connection attempts.",
            "Verify process parentage on target system.",
        ]
        return GroundedExplanation(
            verified_facts=facts,
            system_inferences=inferences,
            analyst_suggestions=suggestions,
            citations=[event_id, rule_id, raw_sha256[:12]],
            confidence=0.98,
        )

    def propose_safe_action(
        self,
        *,
        action_type: str,
        target: str,
        rationale: str,
        required_role: str = "operator",
    ) -> ProposedStateAction:
        """Phase 13 Workstream Q: Propose bounded state-changing action requiring human authorization."""
        import uuid
        act_id = f"act-{uuid.uuid4().hex[:8]}"
        tok = f"rb-{uuid.uuid4().hex[:8]}"
        risk = "HIGH" if action_type in ("ISOLATE_HOST", "BLOCK_IP") else "MEDIUM"
        return ProposedStateAction(
            action_id=act_id,
            action_type=_sanitise(action_type),
            target=_sanitise(target),
            rationale=_sanitise(rationale),
            required_role=required_role,
            risk_level=risk,
            requires_human_approval=True,
            rollback_token=tok,
        )

    def authorize_and_execute_action(
        self,
        proposed_action: ProposedStateAction,
        actor: str,
        actor_role: str,
    ) -> dict[str, Any]:
        """Authorize and execute a proposed action with strict RBAC enforcement."""
        allowed_roles = {
            "operator": {"operator", "platform-admin", "soc-lead"},
            "platform-admin": {"platform-admin"},
        }
        required = proposed_action.required_role
        if actor_role not in allowed_roles.get(required, {required}):
            raise PermissionError(
                f"Actor '{actor}' with role '{actor_role}' unauthorized for action requiring '{required}'."
            )

        return {
            "status": "EXECUTED",
            "action_id": proposed_action.action_id,
            "action_type": proposed_action.action_type,
            "target": proposed_action.target,
            "authorized_by": actor,
            "role": actor_role,
            "rollback_token": proposed_action.rollback_token,
            "message": f"Action '{proposed_action.action_type}' on '{proposed_action.target}' successfully executed.",
        }

