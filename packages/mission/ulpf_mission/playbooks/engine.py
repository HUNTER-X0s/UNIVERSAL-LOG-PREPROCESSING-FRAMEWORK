"""Response playbook engine for Phase 10 — dry-run safe execution."""

from __future__ import annotations

from typing import Any

from ulpf_mission.models.playbooks import (
    DryRunResult,
    DryRunStepResult,
    PlaybookDefinition,
    PlaybookExecutionStatus,
    PlaybookStep,
    PlaybookStepType,
)

# Permissions granted to the playbook engine in simulation mode by default
_DEFAULT_PERMISSIONS: set[str] = {
    "notify",
    "notification:send",
    "collect_evidence",
    "storage:write",
    "document",
    "escalate",
}

# Standard built-in playbooks
_STANDARD_PLAYBOOKS: dict[str, PlaybookDefinition] = {
    "PB-HOST-ISOLATION": PlaybookDefinition(
        playbook_id="PB-HOST-ISOLATION",
        name="Emergency Host Isolation",
        trigger_conditions=["CRITICAL_ALERT", "RANSOMWARE_INDICATOR"],
        steps=[
            PlaybookStep(
                step_id="step-01",
                name="Isolate Host from Local Subnet",
                step_type=PlaybookStepType.QUARANTINE,
                description="Trigger EDR agent network quarantine",
                required_permission="edr:isolate",
                estimated_impact="Target host loses network connectivity except to SOC controllers",
            ),
            PlaybookStep(
                step_id="step-02",
                name="Block Perimeter Communications",
                step_type=PlaybookStepType.BLOCK_IP,
                description="Inject drop rule at perimeter firewall",
                required_permission="firewall:write",
                estimated_impact="All inbound/outbound external sessions dropped",
            ),
            PlaybookStep(
                step_id="step-03",
                name="Notify Incident Response Lead",
                step_type=PlaybookStepType.NOTIFY,
                description="Send urgent notification to on-call security team",
                required_permission="notification:send",
                estimated_impact="On-call engineer alerted with host context",
            ),
        ],
    ),
    "PB-CREDENTIAL-REVOCATION": PlaybookDefinition(
        playbook_id="PB-CREDENTIAL-REVOCATION",
        name="Revoke Compromised Credentials",
        trigger_conditions=["CREDENTIAL_THEFT", "IMPOSSIBLE_TRAVEL"],
        steps=[
            PlaybookStep(
                step_id="step-01",
                name="Invalidate Active Kerberos / NTLM Sessions",
                step_type=PlaybookStepType.DISABLE_ACCOUNT,
                description="Force account logout across all domain controllers",
                required_permission="ad:write",
                estimated_impact="User sessions terminated immediately",
            ),
            PlaybookStep(
                step_id="step-02",
                name="Send Password Reset Link",
                step_type=PlaybookStepType.NOTIFY,
                description="Notify user to perform out-of-band password reset",
                required_permission="notification:send",
                estimated_impact="User notified via alternate contact channel",
            ),
        ],
    ),
}


class ResponsePlaybookEngine:
    """Executes response playbooks in dry-run mode.

    Dry-run is the ONLY mode. No state mutations occur; all actions are
    simulated and projected impacts are reported for analyst review.
    """

    def __init__(self) -> None:
        self._playbooks = dict(_STANDARD_PLAYBOOKS)

    def register(self, playbook: PlaybookDefinition) -> None:
        """Register a custom playbook definition."""
        self._playbooks[playbook.playbook_id] = playbook

    def dry_run(
        self,
        playbook: PlaybookDefinition | str,
        *,
        granted_permissions: set[str] | None = None,
        user_permissions: list[str] | set[str] | None = None,
        parameters: dict[str, Any] | None = None,
    ) -> DryRunResult:
        """Simulate playbook execution without mutating any system state.

        Args:
            playbook: PlaybookDefinition or registered playbook ID string.
            granted_permissions: set of permission strings granted to the engine.
            user_permissions: alias for granted_permissions.
            parameters: runtime parameters (target host, IP, user).
        """
        pb: PlaybookDefinition
        if isinstance(playbook, str):
            if playbook in self._playbooks:
                pb = self._playbooks[playbook]
            else:
                pb = PlaybookDefinition(
                    playbook_id=playbook,
                    name=f"Playbook {playbook}",
                    trigger_conditions=["MANUAL"],
                    steps=[
                        PlaybookStep(
                            step_id="step-custom-01",
                            name=f"Execute simulated actions on {playbook}",
                            step_type=PlaybookStepType.CUSTOM,
                            description=f"Automated action for {playbook}",
                            required_permission="firewall:write",
                            estimated_impact="Simulated impact assessment",
                        )
                    ],
                )
        else:
            pb = playbook

        perms_in = user_permissions or granted_permissions or _DEFAULT_PERMISSIONS
        permissions = {p.lower() for p in perms_in}

        step_results: list[DryRunStepResult] = []
        blocking_issues: list[str] = []
        warnings: list[str] = []

        for step in pb.steps:
            req_perm = step.required_permission.lower()

            if req_perm in permissions or req_perm.split(":")[0] in permissions:
                perm_check = "GRANTED"
                status = PlaybookExecutionStatus.SIMULATED
                projected_impact = f"[DRY-RUN] {step.estimated_impact}"
            else:
                perm_check = "DENIED"
                status = PlaybookExecutionStatus.SKIPPED
                projected_impact = (
                    f"[DRY-RUN] BLOCKED: permission '{req_perm}' not granted to caller."
                )
                blocking_issues.append(
                    f"Step '{step.step_id}' requires permission: {req_perm}"
                )

            if not step.reversible:
                warnings.append(
                    f"Step '{step.step_id}' is IRREVERSIBLE. Manual rollback required if executed."
                )

            step_results.append(
                DryRunStepResult(
                    step_id=step.step_id,
                    step_name=step.name,
                    status=status,
                    projected_impact=projected_impact,
                    permission_check=perm_check,
                )
            )

        overall_status = (
            PlaybookExecutionStatus.SIMULATED_SUCCESS
            if not blocking_issues
            else PlaybookExecutionStatus.SIMULATED_BLOCKED
        )

        summary = (
            f"Dry-run of '{pb.name}' ({pb.step_count} steps). "
            f"Blocking issues: {len(blocking_issues)}. "
            f"Warnings: {len(warnings)}. "
            f"Safe to execute: {not blocking_issues}."
        )

        return DryRunResult(
            playbook_id=pb.playbook_id,
            playbook_name=pb.name,
            step_results=step_results,
            overall_status=overall_status,
            blocking_issues=blocking_issues,
            warnings=warnings,
            summary=summary,
        )
