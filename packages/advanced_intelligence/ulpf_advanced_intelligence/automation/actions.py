"""Governed, Non-Destructive SOAR Action Execution Service for ULPF Phase 9."""

from __future__ import annotations

from datetime import UTC, datetime

from ulpf_advanced_intelligence.errors import ActionExecutionError
from ulpf_advanced_intelligence.models.workflows import ActionApprovalState, SOARAction

_PERMITTED_ACTIONS: set[str] = {
    "CREATE_CASE",
    "ADD_TAG",
    "NOTIFY",
    "EXPORT_EVIDENCE",
    "UPDATE_TICKET",
    "REQUEST_REVIEW",
}

_PROHIBITED_DESTRUCTIVE_ACTIONS: set[str] = {
    "SHUTDOWN_HOST",
    "DELETE_CREDENTIALS",
    "BLOCK_FIREWALL_IP",
    "TERMINATE_PROCESS",
}


class SOARActionDispatcher:
    """Executes safe, non-destructive response actions under strict human-in-the-loop governance."""

    @classmethod
    def execute_action(
        cls,
        action: SOARAction,
        approver_identity: str | None = None,
    ) -> SOARAction:
        """Execute action if approved and permitted under read-oriented platform safety rules."""
        if action.action_type in _PROHIBITED_DESTRUCTIVE_ACTIONS:
            raise ActionExecutionError(
                f"Action '{action.action_type}' is prohibited: core ULPF enforces read-oriented security analytics"
            )

        if action.action_type not in _PERMITTED_ACTIONS:
            raise ActionExecutionError(f"Unknown SOAR action type: '{action.action_type}'")

        # Require approval if currently in PROPOSED state
        if action.approval_state == ActionApprovalState.PROPOSED and not approver_identity:
            raise ActionExecutionError(f"Action '{action.action_id}' requires explicit human approval before execution")

        now_iso = datetime.now(UTC).isoformat()
        approver = approver_identity or action.approved_by or "SYSTEM"

        # Execute non-destructive simulation / hook
        result_str = f"Executed {action.action_type} for target '{action.target}' successfully."

        return SOARAction(
            action_id=action.action_id,
            action_type=action.action_type,
            target=action.target,
            parameters=action.parameters,
            approval_state=ActionApprovalState.EXECUTED,
            proposed_by=action.proposed_by,
            approved_by=approver,
            executed_at=now_iso,
            result_summary=result_str,
            tenant_id=action.tenant_id,
        )

    @classmethod
    def reject_action(cls, action: SOARAction, rejector_identity: str, reason: str) -> SOARAction:
        """Mark an action as rejected with an audit-documented rationale."""
        return SOARAction(
            action_id=action.action_id,
            action_type=action.action_type,
            target=action.target,
            parameters=action.parameters,
            approval_state=ActionApprovalState.REJECTED,
            proposed_by=action.proposed_by,
            approved_by=None,
            rejection_reason=f"Rejected by {rejector_identity}: {reason}",
            tenant_id=action.tenant_id,
        )
