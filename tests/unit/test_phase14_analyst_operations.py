"""Tests for ULPF Phase 14 Milestone E — Analyst Operations & Case Workflow.

Verifies:
- Workstream Z: Investigation context graph aggregation
- Workstream AA: Analyst collaboration & annotations
- Workstream AB: 7-state case workflow governance
- Workstream AC & AD: Response playbook simulation mode (zero side effects) & authorized execution
"""

import pytest
from ulpf_intelligence.investigations.context_graph import (
    CaseState,
    CaseWorkflowManager,
    InvestigationContext,
)
from ulpf_mission.playbooks.simulator import (
    ActionType,
    ExecutionMode,
    PlaybookEngine,
    PlaybookStep,
)


def test_investigation_context_and_7_state_workflow():
    mgr = CaseWorkflowManager()

    # 1. Create Case: NEW
    ctx = mgr.create_case(
        case_id="CASE-2026-001",
        title="Lateral Movement Detected in Zone-B",
        severity="HIGH",
        analyst="analyst_alice",
        entities=["host-101", "10.0.0.15"],
        evidence_ids=["RAW-EV-100", "RAW-EV-101"],
    )
    assert ctx.state == CaseState.NEW
    assert "host-101" in ctx.entities

    # 2. Transition through permitted lifecycle
    assert mgr.transition_state("CASE-2026-001", CaseState.TRIAGED, "analyst_alice", "Triaged verified alert")
    assert mgr.transition_state("CASE-2026-001", CaseState.INVESTIGATING, "analyst_alice", "Pivoting on IP")
    assert mgr.transition_state("CASE-2026-001", CaseState.CONTAINMENT_RECOMMENDED, "analyst_alice", "Isolation required")
    assert mgr.transition_state("CASE-2026-001", CaseState.RESOLVED, "lead_bob", "Containment executed")
    assert mgr.transition_state("CASE-2026-001", CaseState.CLOSED, "lead_bob", "Incident resolved")

    # 3. Disallowed transition from CLOSED directly to INVESTIGATING should raise ValueError
    with pytest.raises(ValueError):
        mgr.transition_state("CASE-2026-001", CaseState.INVESTIGATING, "analyst_alice", "Illegal jump")

    # 4. Reopen case
    assert mgr.transition_state("CASE-2026-001", CaseState.REOPENED, "lead_bob", "New IOC observed")
    assert ctx.state == CaseState.REOPENED


def test_analyst_annotations():
    mgr = CaseWorkflowManager()
    mgr.create_case("CASE-002", "Credential Dumping", "CRITICAL")

    ann = mgr.add_annotation(
        case_id="CASE-002",
        author="analyst_bob",
        target_type="EVIDENCE",
        target_id="RAW-EV-999",
        content="LSASS memory dump detected via Sysmon Event 10",
    )
    assert ann.author == "analyst_bob"
    assert ann.target_id == "RAW-EV-999"
    assert len(mgr.cases["CASE-002"].annotations) == 1


def test_playbook_simulation_zero_side_effects():
    engine = PlaybookEngine()
    steps = [
        PlaybookStep("s1", ActionType.BLOCK_IP, "198.51.100.42", rollback_action="UNBLOCK_IP"),
        PlaybookStep("s2", ActionType.ISOLATE_HOST, "workstation-hr-04", rollback_action="RECONNECT_HOST"),
    ]

    # Dry-run simulation
    rep = engine.simulate_playbook("PB-CONTAIN-01", steps)
    assert rep.mode == ExecutionMode.SIMULATION.value
    assert rep.side_effects_occurred is False
    assert rep.rollback_supported is True
    assert "198.51.100.42" in rep.affected_entities
    assert "workstation-hr-04" in rep.affected_entities
    assert "secops.containment.network" in rep.required_permissions


def test_playbook_live_execution_authorization():
    engine = PlaybookEngine()
    steps = [PlaybookStep("s1", ActionType.REVOKE_SESSION, "user_evil", rollback_action="RESTORE_SESSION")]

    # Unauthorized attempt raises PermissionError
    with pytest.raises(PermissionError):
        engine.execute_live_authorized("PB-REVOKE-01", steps, authorizing_actor="", auth_token="")

    # Authorized execution succeeds
    res = engine.execute_live_authorized(
        "PB-REVOKE-01",
        steps,
        authorizing_actor="secops_admin",
        auth_token="bearer-auth-sig-9988",
    )
    assert len(res) == 1
    assert res[0].status == "EXECUTED"
