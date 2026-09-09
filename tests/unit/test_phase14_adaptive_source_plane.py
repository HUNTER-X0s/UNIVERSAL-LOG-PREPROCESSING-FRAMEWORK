"""Tests for ULPF Phase 14 Milestone C — Adaptive Source Plane.

Verifies:
- Workstream K: 10-state source lifecycle model and transition audits
- Workstream L: Multi-factor explainable source risk scoring
- Workstream M, N, O: Parser canarying and semantic differential validation
- Workstream P: Continuous schema drift learning and operator recommendations
"""

import pytest
from ulpf_onboarding.lifecycle import (
    SourceLifecycleManager,
    SourceLifecycleState,
    SourceRiskEvaluator,
)
from ulpf_onboarding.canary import ParserCanaryEngine
from ulpf_onboarding.drift_learning import ContinuousDriftLearner


def test_source_lifecycle_10_states_and_audit():
    mgr = SourceLifecycleManager()
    src = "cloudtrail_ingest"

    # 1. Register: DISCOVERED
    s0 = mgr.register_source(src, initial_state=SourceLifecycleState.DISCOVERED, actor="secops")
    assert s0 == SourceLifecycleState.DISCOVERED

    # 2. Valid transitions: DISCOVERED -> PROFILED -> ONBOARDING -> VALIDATING -> APPROVED -> ACTIVE
    assert mgr.transition(src, SourceLifecycleState.PROFILED, actor="analyst", reason="Profile generated")
    assert mgr.transition(src, SourceLifecycleState.ONBOARDING, actor="analyst", reason="Generating mappings")
    assert mgr.transition(src, SourceLifecycleState.VALIDATING, actor="analyst", reason="Canary replay")
    assert mgr.transition(src, SourceLifecycleState.APPROVED, actor="lead", reason="Approved by admin")
    assert mgr.transition(src, SourceLifecycleState.ACTIVE, actor="system", reason="Promoted to live stream")
    assert mgr.get_state(src) == SourceLifecycleState.ACTIVE

    # 3. Disallowed transition from ACTIVE directly to DISCOVERED should raise ValueError
    with pytest.raises(ValueError):
        mgr.transition(src, SourceLifecycleState.DISCOVERED, actor="user", reason="Illegal jump")

    # 4. Degradation and Quarantine
    assert mgr.transition(src, SourceLifecycleState.DEGRADED, actor="monitor", reason="Parse errors spike")
    assert mgr.transition(src, SourceLifecycleState.QUARANTINED, actor="monitor", reason="Threat suspected")
    assert mgr.get_state(src) == SourceLifecycleState.QUARANTINED

    # 5. Check history integrity
    history = mgr.get_history(src)
    assert len(history) >= 7
    assert history[-1].to_state == SourceLifecycleState.QUARANTINED


def test_explainable_source_risk_scoring():
    # Pristine source
    rep_clean = SourceRiskEvaluator.evaluate(
        source_id="clean_syslog",
        parse_failure_rate=0.001,
        drift_severity_score=0.05,
        unknown_field_ratio=0.01,
        latency_p95_ms=2.5,
    )
    assert rep_clean.risk_level == "LOW"
    assert rep_clean.composite_risk_score < 25.0
    assert rep_clean.recommended_action == "CONTINUE_ACTIVE_OPERATION"

    # High risk source under heavy drift and errors
    rep_risky = SourceRiskEvaluator.evaluate(
        source_id="failing_firewall",
        parse_failure_rate=0.35,
        drift_severity_score=0.75,
        unknown_field_ratio=0.50,
        latency_p95_ms=35.0,
        security_criticality=1.5,
    )
    assert rep_risky.risk_level in ("HIGH", "CRITICAL")
    assert rep_risky.composite_risk_score >= 50.0
    assert len(rep_risky.explanations) >= 3
    assert "parse_failure_risk" in rep_risky.factors


def test_parser_canary_semantic_differential():
    canary = ParserCanaryEngine(tolerance_mismatch_rate=0.10)

    # Active parser: extracts src, dst, action
    def active_p(raw: str) -> dict:
        return {"src": "10.0.0.1", "dst": "8.8.8.8", "action": "ALLOW"}

    # Candidate parser: identical extraction plus additional host field
    def candidate_p_good(raw: str) -> dict:
        return {"src": "10.0.0.1", "dst": "8.8.8.8", "action": "ALLOW", "host": "gateway1"}

    # Candidate parser bad: breaks action field
    def candidate_p_bad(raw: str) -> dict:
        return {"src": "10.0.0.1", "dst": "8.8.8.8", "action": "DENY"}

    samples = ["log1", "log2", "log3", "log4", "log5"]

    # Test candidate good: should recommend for approval
    rep_good = canary.evaluate_shadow("fw1", "v1.0", "v1.1", active_p, candidate_p_good, samples)
    assert rep_good.is_safe_for_promotion is True
    assert rep_good.governance_verdict == "CANDIDATE_RECOMMENDED_FOR_APPROVAL"

    # Test candidate bad: divergences exceed tolerance
    rep_bad = canary.evaluate_shadow("fw1", "v1.0", "v2.0-broken", active_p, candidate_p_bad, samples)
    assert rep_bad.is_safe_for_promotion is False
    assert rep_bad.governance_verdict == "PROMOTION_BLOCKED_EXCESSIVE_DIVERGENCE"


def test_continuous_drift_learning_and_recommendations():
    learner = ContinuousDriftLearner()
    src = "endpoint_telemetry"

    # Cycle 1: Baseline fields
    new1 = learner.observe_record(src, {"timestamp": 100, "user": "alice", "process": "bash"})
    assert set(new1) == {"timestamp", "user", "process"}

    # Cycle 2: Schema stable
    new2 = learner.observe_record(src, {"timestamp": 105, "user": "bob", "process": "zsh"})
    assert len(new2) == 0

    # Cycle 3: Drift introduced (3 new fields)
    new3 = learner.observe_record(src, {
        "timestamp": 110, "user": "charlie", "process": "curl",
        "parent_pid": 1234, "command_line": "curl -O evil.sh", "sha256": "abc"
    })
    assert len(new3) == 3

    # Generate recommendations
    rep = learner.generate_recommendations(src)
    assert rep.total_drift_events >= 2
    assert "RECOMMEND" in rep.recommended_action
    assert len(rep.new_fields_detected) >= 3
