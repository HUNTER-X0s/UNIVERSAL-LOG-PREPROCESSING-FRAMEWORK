"""Phase 8 Comprehensive Verification Test Suite — Intelligence Plane.

Tests:
1. Core models, immutability, and provenance tracking
2. Safe Rule DSL, condition evaluation, and versioned registry lifecycle
3. Detection engine, threshold counting, entity extraction, and explanation
4. Multi-event correlation engine and group risk aggregation
5. Multi-stage attack sequencing and confidence categorization
6. Feature store and statistical anomaly engine with Welford algorithm
7. Entity resolution and bounded relationship graph exploration
8. Transparent weighted risk scoring engine
9. Deterministic explainability engine (WHAT/WHEN/WHERE/WHO/WHY)
10. Auditable suppression and false-positive allowlisting
11. Bounded threat hunting engine and resource limits
12. Investigation workbench case lifecycle state machine
13. Chronological timeline generation
14. Air-gapped local analyst advisor
15. Durable relational repositories (SQLite migrations and persistence)
16. Security RBAC policies and permission matrix
17. FastAPI intelligence routes via TestClient
"""

from __future__ import annotations

import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from ulpf_api.app import create_app
from ulpf_intelligence.ai_assistant.advisor import LocalAnalystAdvisor
from ulpf_intelligence.anomaly.engine import StatisticalAnomalyEngine
from ulpf_intelligence.correlation.engine import CorrelationEngine
from ulpf_intelligence.detection.engine import DetectionEngine
from ulpf_intelligence.enrichment.local import LocalEnrichmentService
from ulpf_intelligence.entities.resolver import EntityResolver
from ulpf_intelligence.errors import (
    CaseStateError,
    GraphDepthExceededError,
    QueryResourceLimitExceededError,
    RuleValidationError,
)
from ulpf_intelligence.explainability.engine import ExplainabilityEngine
from ulpf_intelligence.false_positives.suppression import SuppressionEngine
from ulpf_intelligence.feature_store.extractor import FeatureExtractor
from ulpf_intelligence.graph.store import RelationshipGraph
from ulpf_intelligence.hunting.engine import ThreatHuntingEngine
from ulpf_intelligence.investigations.workbench import InvestigationWorkbench
from ulpf_intelligence.models.events import (
    AnomalyEvent,
    AttackSequence,
    CorrelationGroup,
    DetectionEvent,
    DetectionEvidence,
    EntityRecord,
    EntityRelationship,
    IndicatorRecord,
    InvestigationCase,
    RiskAssessment,
)
from ulpf_intelligence.models.provenance import (
    AlertSeverity,
    AlertStatus,
    CaseStatus,
    IndicatorStatus,
    IntelligenceProvenance,
    RuleState,
    SequenceConfidence,
)
from ulpf_intelligence.repositories.anomaly import AnomalyRepository
from ulpf_intelligence.repositories.correlation import CorrelationRepository
from ulpf_intelligence.repositories.detection import DetectionRepository
from ulpf_intelligence.repositories.investigation import CaseRepository
from ulpf_intelligence.repositories.rules import RuleRepository
from ulpf_intelligence.risk.engine import RiskScoringEngine
from ulpf_intelligence.rules.dsl import DetectionRule, RuleCondition, RuleOperator, RuleThreshold
from ulpf_intelligence.rules.registry import RuleRegistry
from ulpf_intelligence.sequences.engine import AttackSequenceEngine
from ulpf_intelligence.timeline.builder import TimelineBuilder
from ulpf_security.policy import IdentityContext, Permission, PolicyEngine
from ulpf_storage.database.relational import SQLiteDatabase


# ---------------------------------------------------------------------------
# Test 1: Models & Provenance
# ---------------------------------------------------------------------------
def test_models_and_provenance() -> None:
    prov = IntelligenceProvenance(
        source_events=["evt-001"],
        source_rules=["rule-ssh-brute"],
        derivation_method="DETERMINISTIC",
        generated_by="DETECTION_ENGINE",
        generated_at="2026-09-07T12:00:00Z",
    )
    assert prov.is_derived is True
    assert prov.is_mutable is False
    assert prov.to_dict()["derivation_method"] == "DETERMINISTIC"

    ev = DetectionEvidence(
        matched_event_ids=["evt-001"],
        raw_hashes=["sha256:abcd"],
        trigger_field="event_type",
        trigger_value="auth_failed",
    )
    det = DetectionEvent(
        detection_id="det-101",
        tenant_id="tenant-a",
        rule_id="rule-ssh-brute",
        rule_version="1.0.0",
        severity=AlertSeverity.HIGH,
        title="SSH Brute Force",
        description="Repeated failed auth",
        status=AlertStatus.NEW,
        entity_ids=["192.168.1.10"],
        evidence=ev,
        provenance=prov,
        mitre_tactics=["TA0006"],
        mitre_techniques=["T1110"],
        detected_at="2026-09-07T12:00:00Z",
        indexed_at="2026-09-07T12:00:01Z",
    )
    d = det.to_dict()
    assert d["detection_id"] == "det-101"
    assert d["severity"] == "HIGH"
    assert d["status"] == "NEW"


# ---------------------------------------------------------------------------
# Test 2: Rule DSL & Validation
# ---------------------------------------------------------------------------
def test_rule_dsl_operators_and_validation() -> None:
    # Valid rule
    rule = DetectionRule(
        rule_id="rule-test-1",
        name="Test Rule",
        description="Test description",
        severity=AlertSeverity.MEDIUM,
        conditions=[
            RuleCondition(field="status_code", operator=RuleOperator.EQUALS, value=404),
            RuleCondition(field="path", operator=RuleOperator.CONTAINS, value="/admin"),
            RuleCondition(field="ip", operator=RuleOperator.REGEX, value=r"^10\.\d+\.\d+\.\d+$"),
        ],
    )
    assert len(rule.conditions) == 3

    # Matching logic
    assert rule.matches({"status_code": 404, "path": "/admin/login", "ip": "10.0.0.1"}) is True
    assert rule.matches({"status_code": 200, "path": "/admin/login", "ip": "10.0.0.1"}) is False
    assert rule.matches({"status_code": 404, "path": "/user", "ip": "10.0.0.1"}) is False
    assert rule.matches({"status_code": 404, "path": "/admin", "ip": "192.168.1.1"}) is False

    # Validation errors
    with pytest.raises(RuleValidationError, match="Empty rule_id"):
        DetectionRule(
            rule_id="",
            name="No ID",
            description="",
            severity=AlertSeverity.LOW,
            conditions=[RuleCondition("a", RuleOperator.EQUALS, "b")],
        )

    with pytest.raises(RuleValidationError, match="must contain at least one condition"):
        DetectionRule(
            rule_id="r1",
            name="No cond",
            description="",
            severity=AlertSeverity.LOW,
            conditions=[],
        )

    with pytest.raises(RuleValidationError, match="Invalid regular expression"):
        DetectionRule(
            rule_id="r2",
            name="Bad regex",
            description="",
            severity=AlertSeverity.LOW,
            conditions=[RuleCondition("path", RuleOperator.REGEX, "[unclosed regex")],
        )


# ---------------------------------------------------------------------------
# Test 3: Rule Registry Lifecycle
# ---------------------------------------------------------------------------
def test_rule_registry_lifecycle() -> None:
    reg = RuleRegistry()
    rule = DetectionRule(
        rule_id="rule-auth-01",
        name="Auth Failure",
        description="Detects failed logins",
        severity=AlertSeverity.HIGH,
        conditions=[RuleCondition("action", RuleOperator.EQUALS, "failure")],
    )

    reg.register_rule(rule, author="alice")
    assert reg.get_rule_state("rule-auth-01") == RuleState.DRAFT
    assert len(reg.get_active_rules()) == 0

    reg.approve_rule("rule-auth-01", reviewer="bob")
    assert reg.get_rule_state("rule-auth-01") == RuleState.REVIEWED

    reg.activate_rule("rule-auth-01")
    assert reg.get_rule_state("rule-auth-01") == RuleState.ACTIVE
    assert len(reg.get_active_rules()) == 1

    reg.deactivate_rule("rule-auth-01")
    assert reg.get_rule_state("rule-auth-01") == RuleState.DEPRECATED
    assert len(reg.get_active_rules()) == 0


# ---------------------------------------------------------------------------
# Test 4: Detection Engine & Sliding Window Threshold
# ---------------------------------------------------------------------------
def test_detection_engine_threshold() -> None:
    reg = RuleRegistry()
    # Threshold rule: 3 occurrences within 60s grouped by src_ip
    rule = DetectionRule(
        rule_id="rule-brute-threshold",
        name="Brute Force Threshold",
        description="3 failures in 60s",
        severity=AlertSeverity.CRITICAL,
        conditions=[RuleCondition("action", RuleOperator.EQUALS, "failed_login")],
        threshold=RuleThreshold(count=3, window_seconds=60, group_by_fields=["src_ip"]),
    )
    reg.register_rule(rule)
    reg.approve_rule(rule.rule_id, reviewer="lead")
    reg.activate_rule(rule.rule_id)

    engine = DetectionEngine(rule_registry=reg)

    t0 = datetime(2026, 9, 7, 12, 0, 0, tzinfo=UTC)
    payload = {"action": "failed_login", "src_ip": "203.0.113.5", "user": "admin"}

    # Event 1: no detection yet
    d1 = engine.evaluate(payload, "evt-1", "t1", t0.isoformat())
    assert len(d1) == 0

    # Event 2: no detection yet
    d2 = engine.evaluate(payload, "evt-2", "t1", (t0 + timedelta(seconds=10)).isoformat())
    assert len(d2) == 0

    # Event 3: threshold breached!
    d3 = engine.evaluate(payload, "evt-3", "t1", (t0 + timedelta(seconds=20)).isoformat())
    assert len(d3) == 1
    det = d3[0]
    assert det.rule_id == "rule-brute-threshold"
    assert det.severity == AlertSeverity.CRITICAL
    assert det.evidence.observed_count == 3
    assert "203.0.113.5" in det.entity_ids
    assert det.explanation is not None
    assert "203.0.113.5" in det.explanation.who


# ---------------------------------------------------------------------------
# Test 5: Correlation Engine
# ---------------------------------------------------------------------------
def test_correlation_engine() -> None:
    engine = CorrelationEngine(window_seconds=300)

    prov = IntelligenceProvenance(
        source_events=["e1"],
        source_rules=["r1"],
        derivation_method="DETERMINISTIC",
        generated_by="TEST",
        generated_at="2026-09-07T12:00:00Z",
    )
    ev = DetectionEvidence(matched_event_ids=["e1"], raw_hashes=["h1"], trigger_field="a", trigger_value=1)

    det1 = DetectionEvent(
        detection_id="det-1",
        tenant_id="t1",
        rule_id="r1",
        rule_version="1",
        severity=AlertSeverity.HIGH,
        title="Port Scan",
        description="Port scan detected",
        status=AlertStatus.NEW,
        entity_ids=["10.0.0.5"],
        evidence=ev,
        provenance=prov,
        mitre_tactics=["TA0043"],
        mitre_techniques=["T1046"],
        detected_at="2026-09-07T12:00:00Z",
        indexed_at="2026-09-07T12:00:01Z",
    )
    det2 = DetectionEvent(
        detection_id="det-2",
        tenant_id="t1",
        rule_id="r2",
        rule_version="1",
        severity=AlertSeverity.CRITICAL,
        title="Exploit Attempt",
        description="Remote code execution attempt",
        status=AlertStatus.NEW,
        entity_ids=["10.0.0.5"],
        evidence=ev,
        provenance=prov,
        mitre_tactics=["TA0001"],
        mitre_techniques=["T1190"],
        detected_at="2026-09-07T12:01:00Z",
        indexed_at="2026-09-07T12:01:01Z",
    )

    g1 = engine.ingest_detection(det1)
    assert g1 is not None
    assert len(g1.detection_ids) == 1

    g2 = engine.ingest_detection(det2)
    assert g2 is not None
    assert g2.group_id == g1.group_id
    assert len(g2.detection_ids) == 2
    assert g2.primary_entity_id == "10.0.0.5"
    assert g2.aggregated_risk > 0.5


# ---------------------------------------------------------------------------
# Test 6: Attack Sequence Engine
# ---------------------------------------------------------------------------
def test_attack_sequence_engine() -> None:
    seq_engine = AttackSequenceEngine(window_seconds=600)
    prov = IntelligenceProvenance(
        source_events=["e"],
        source_rules=["r"],
        derivation_method="DETERMINISTIC",
        generated_by="TEST",
        generated_at="2026-09-07T12:00:00Z",
    )
    ev = DetectionEvidence(matched_event_ids=["e"], raw_hashes=["h"], trigger_field="a", trigger_value=1)

    # Ingest Recon detection
    d_recon = DetectionEvent(
        detection_id="d-recon",
        tenant_id="t1",
        rule_id="r-recon",
        rule_version="1",
        severity=AlertSeverity.LOW,
        title="Network Recon",
        description="Recon",
        status=AlertStatus.NEW,
        entity_ids=["10.1.1.50"],
        evidence=ev,
        provenance=prov,
        mitre_tactics=["TA0043"],
        mitre_techniques=["T1595"],
        detected_at="2026-09-07T12:00:00Z",
        indexed_at="2026-09-07T12:00:01Z",
    )
    seq = seq_engine.process_detection(d_recon)
    assert seq is not None
    assert seq.confidence == SequenceConfidence.PARTIAL

    # Ingest Auth Failure detection for same entity
    d_auth = DetectionEvent(
        detection_id="d-auth",
        tenant_id="t1",
        rule_id="r-auth",
        rule_version="1",
        severity=AlertSeverity.HIGH,
        title="Credential Access",
        description="Brute force",
        status=AlertStatus.NEW,
        entity_ids=["10.1.1.50"],
        evidence=ev,
        provenance=prov,
        mitre_tactics=["TA0006"],
        mitre_techniques=["T1110"],
        detected_at="2026-09-07T12:02:00Z",
        indexed_at="2026-09-07T12:02:01Z",
    )
    seq2 = seq_engine.process_detection(d_auth)
    assert seq2 is not None
    assert seq2.confidence == SequenceConfidence.POTENTIAL
    assert len(seq2.stages_observed) == 2


# ---------------------------------------------------------------------------
# Test 7: Statistical Anomaly Engine (Welford's Algorithm)
# ---------------------------------------------------------------------------
def test_statistical_anomaly_engine() -> None:
    engine = StatisticalAnomalyEngine(default_threshold_z=2.5)

    # Baseline observations around mean ~ 50.0, low std
    for _ in range(50):
        engine.update_baseline(entity_id="host-alpha", metric_name="cpu_load", value=50.0)

    # An observation within normal bounds
    anom_none = engine.evaluate(
        entity_id="host-alpha",
        metric_name="cpu_load",
        observed_value=51.0,
        tenant_id="t1",
        timestamp="2026-09-07T12:00:00Z",
    )
    assert anom_none is None

    # An extreme observation (e.g. 500.0)
    anom = engine.evaluate(
        entity_id="host-alpha",
        metric_name="cpu_load",
        observed_value=500.0,
        tenant_id="t1",
        timestamp="2026-09-07T12:01:00Z",
    )
    assert anom is not None
    assert anom.entity_id == "host-alpha"
    assert anom.observed_value == 500.0
    assert anom.z_score > 2.5
    assert anom.severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL]


# ---------------------------------------------------------------------------
# Test 8: Feature Extractor
# ---------------------------------------------------------------------------
def test_feature_extractor() -> None:
    events = [
        {"action": "failure", "src_port": 1024, "dst_ip": "10.0.0.1", "username": "user1"},
        {"action": "failure", "src_port": 1025, "dst_ip": "10.0.0.2", "username": "user2"},
        {"action": "success", "src_port": 1026, "dst_ip": "10.0.0.3", "username": "user3"},
    ]
    snap = FeatureExtractor.extract_snapshot(
        entity_id="192.168.1.100",
        events=events,
        window_seconds=60,
    )
    assert snap.features["event_count"] == 3.0
    assert snap.features["unique_destinations"] == 3.0
    assert snap.features["unique_ports"] == 3.0
    assert snap.features["failure_rate"] == pytest.approx(2.0 / 3.0)
    assert snap.features["payload_entropy"] > 0.0


# ---------------------------------------------------------------------------
# Test 9: Entity Resolver & Bounded Graph
# ---------------------------------------------------------------------------
def test_entity_resolver_and_graph() -> None:
    resolver = EntityResolver()
    e1 = resolver.get_or_create(identifier="192.168.1.20", entity_type="IP", tenant_id="t1")
    assert e1.canonical_id == "ip:192.168.1.20"

    resolver.add_alias(canonical_id=e1.canonical_id, alias="web-server-01.internal")
    assert resolver.resolve(identifier="web-server-01.internal", tenant_id="t1") == e1.canonical_id

    # Relationship graph
    graph = RelationshipGraph()
    graph.add_entity(e1)
    e2 = resolver.get_or_create(identifier="admin", entity_type="USER", tenant_id="t1")
    graph.add_entity(e2)
    graph.add_relationship(
        source_id=e1.canonical_id,
        target_id=e2.canonical_id,
        relationship_type="AUTHENTICATED_AS",
        weight=1.0,
    )

    entities, rels = graph.get_subgraph(entity_id=e1.canonical_id, max_depth=2)
    assert len(entities) == 2
    assert len(rels) == 1

    # Bounded depth exception
    with pytest.raises(GraphDepthExceededError):
        graph.get_subgraph(entity_id=e1.canonical_id, max_depth=10)


# ---------------------------------------------------------------------------
# Test 10: Transparent Risk Scoring Engine
# ---------------------------------------------------------------------------
def test_risk_scoring_engine() -> None:
    engine = RiskScoringEngine()
    assessment = engine.calculate_risk(
        entity_id="host-db",
        detections=[
            {"severity": "CRITICAL"},
            {"severity": "HIGH"},
        ],
        anomalies=[
            {"z_score": 4.0},
        ],
        asset_criticality="CRITICAL",
        is_external_facing=True,
    )
    assert 0.0 <= assessment.risk_score <= 1.0
    assert assessment.risk_score > 0.7
    assert len(assessment.contributing_factors) >= 4
    assert "criticality_weight" in assessment.contributing_factors


# ---------------------------------------------------------------------------
# Test 11: Explainability Engine
# ---------------------------------------------------------------------------
def test_explainability_engine() -> None:
    engine = ExplainabilityEngine()
    rule = DetectionRule(
        rule_id="r-sudo",
        name="Unauthorized Sudo",
        description="Detects unauthorized privilege escalation",
        severity=AlertSeverity.HIGH,
        conditions=[RuleCondition("command", RuleOperator.CONTAINS, "sudo")],
        mitre_tactics=["TA0004"],
        mitre_techniques=["T1548"],
    )
    explanation = engine.generate_explanation(
        rule=rule,
        event_payload={"command": "sudo su -", "user": "guest", "host": "srv-prod"},
        matched_event_ids=["evt-999"],
        raw_hashes=["hash-999"],
        observed_count=1,
    )
    assert explanation.rule_id == "r-sudo"
    assert "srv-prod" in explanation.where
    assert "guest" in explanation.who
    assert "sudo" in explanation.why
    assert "TA0004" in explanation.mitre_mapping["tactics"]


# ---------------------------------------------------------------------------
# Test 12: Suppression / False Positive Engine
# ---------------------------------------------------------------------------
def test_suppression_engine() -> None:
    engine = SuppressionEngine()
    engine.add_suppression(
        rule_id="rule-scan",
        tenant_id="t1",
        reason="Scheduled vulnerability scanner",
        author="secops",
        conditions={"src_ip": "10.0.50.50"},
    )

    # Event matching suppression
    suppressed, record = engine.is_suppressed(
        rule_id="rule-scan",
        tenant_id="t1",
        event_payload={"src_ip": "10.0.50.50", "action": "port_probe"},
    )
    assert suppressed is True
    assert record is not None
    assert record.hit_count == 1

    # Event not matching suppression
    suppressed2, _ = engine.is_suppressed(
        rule_id="rule-scan",
        tenant_id="t1",
        event_payload={"src_ip": "10.0.99.99", "action": "port_probe"},
    )
    assert suppressed2 is False


# ---------------------------------------------------------------------------
# Test 13: Threat Hunting Engine & Bounded Limits
# ---------------------------------------------------------------------------
def test_threat_hunting_engine() -> None:
    engine = ThreatHuntingEngine()

    now = datetime.now(UTC)
    t_start = (now - timedelta(days=2)).isoformat()
    t_end = now.isoformat()

    q = engine.create_query(
        user_id="hunter-1",
        field="status_code",
        operator=RuleOperator.EQUALS,
        value=500,
        start_time=t_start,
        end_time=t_end,
        limit=50,
    )

    candidates = [
        {"status_code": 500, "timestamp": (now - timedelta(days=1)).isoformat()},
        {"status_code": 200, "timestamp": (now - timedelta(days=1)).isoformat()},
        {"status_code": 500, "timestamp": (now - timedelta(hours=5)).isoformat()},
    ]

    res = engine.execute_query(q, candidate_records=candidates)
    assert res.total_matches == 2
    assert len(res.matched_records) == 2

    # Query exceeds 7-day window limit
    with pytest.raises(QueryResourceLimitExceededError, match="Time window exceeds maximum"):
        engine.create_query(
            user_id="hunter-1",
            field="ip",
            operator=RuleOperator.EQUALS,
            value="1.1.1.1",
            start_time=(now - timedelta(days=10)).isoformat(),
            end_time=now.isoformat(),
        )

    # Query exceeds record limit
    with pytest.raises(QueryResourceLimitExceededError, match="Query limit exceeds maximum"):
        engine.create_query(
            user_id="hunter-1",
            field="ip",
            operator=RuleOperator.EQUALS,
            value="1.1.1.1",
            start_time=t_start,
            end_time=t_end,
            limit=1000,
        )


# ---------------------------------------------------------------------------
# Test 14: Investigation Workbench Case Lifecycle
# ---------------------------------------------------------------------------
def test_investigation_workbench() -> None:
    wb = InvestigationWorkbench()

    case = wb.create_case(
        title="Suspected Lateral Movement",
        severity=AlertSeverity.HIGH,
        tenant_id="t1",
        created_by="analyst-1",
        assignee="analyst-2",
        initial_detections=["det-001"],
    )
    assert case.status == CaseStatus.OPEN
    assert len(case.detection_ids) == 1
    assert len(case.timeline) == 1

    # Add analyst note
    note = wb.add_analyst_note(
        case_id=case.case_id,
        author="analyst-2",
        content="Correlated with workstation WS-10.",
    )
    assert note.content == "Correlated with workstation WS-10."
    assert len(wb.get_case(case.case_id).notes) == 1

    # Add evidence
    wb.link_detection_evidence(case.case_id, detection_id="det-002", linked_by="analyst-2")
    assert len(wb.get_case(case.case_id).detection_ids) == 2

    # Valid transitions: OPEN -> IN_PROGRESS -> CONTAINED -> RESOLVED -> CLOSED
    c = wb.update_case_status(case.case_id, CaseStatus.IN_PROGRESS, user_id="analyst-2")
    assert c.status == CaseStatus.IN_PROGRESS
    c = wb.update_case_status(case.case_id, CaseStatus.CONTAINED, user_id="analyst-2")
    assert c.status == CaseStatus.CONTAINED
    c = wb.update_case_status(case.case_id, CaseStatus.RESOLVED, user_id="analyst-2")
    assert c.status == CaseStatus.RESOLVED
    c = wb.update_case_status(case.case_id, CaseStatus.CLOSED, user_id="analyst-2")
    assert c.status == CaseStatus.CLOSED

    # Invalid transition: CLOSED cannot transition to IN_PROGRESS directly
    with pytest.raises(CaseStateError):
        wb.update_case_status(case.case_id, CaseStatus.IN_PROGRESS, user_id="analyst-2")


# ---------------------------------------------------------------------------
# Test 15: Timeline Builder
# ---------------------------------------------------------------------------
def test_timeline_builder() -> None:
    builder = TimelineBuilder()
    builder.add_event(
        timestamp="2026-09-07T12:05:00Z",
        event_type="DETECTION",
        source_id="d2",
        summary="Exploit detected",
    )
    builder.add_event(
        timestamp="2026-09-07T12:00:00Z",
        event_type="DETECTION",
        source_id="d1",
        summary="Scan detected",
    )
    timeline = builder.build()
    assert len(timeline) == 2
    # Verify chronological sorting
    assert timeline[0].source_id == "d1"
    assert timeline[1].source_id == "d2"


# ---------------------------------------------------------------------------
# Test 16: Local Air-Gapped Analyst Advisor
# ---------------------------------------------------------------------------
def test_local_analyst_advisor() -> None:
    advisor = LocalAnalystAdvisor()
    wb = InvestigationWorkbench()
    case = wb.create_case(
        title="Air-gap Incident",
        severity=AlertSeverity.CRITICAL,
        tenant_id="t1",
        created_by="analyst",
        initial_detections=["d-1", "d-2"],
    )
    wb.add_analyst_note(case.case_id, author="analyst", content="Host isolated.")

    summary = advisor.summarize_case(wb.get_case(case.case_id))
    assert summary["case_id"] == case.case_id
    assert summary["provenance_tag"] == "AI_GENERATED"
    assert "Incident Analysis" in summary["summary"]
    assert len(summary["recommended_actions"]) > 0


# ---------------------------------------------------------------------------
# Test 17: Relational Repositories with SQLite
# ---------------------------------------------------------------------------
def test_relational_repositories_sqlite(tmp_path: Path) -> None:
    db_path = tmp_path / "test_intel.db"
    db = SQLiteDatabase(db_path)
    db.migrate()

    det_repo = DetectionRepository(db)
    corr_repo = CorrelationRepository(db)
    anom_repo = AnomalyRepository(db)
    case_repo = CaseRepository(db)
    rule_repo = RuleRepository(db)

    # 1. Detection Repo
    prov = IntelligenceProvenance(
        source_events=["e1"],
        source_rules=["r1"],
        derivation_method="DETERMINISTIC",
        generated_by="TEST",
        generated_at="2026-09-07T12:00:00Z",
    )
    ev = DetectionEvidence(matched_event_ids=["e1"], raw_hashes=["h1"], trigger_field="f", trigger_value="v")
    det = DetectionEvent(
        detection_id="det-sqlite-1",
        tenant_id="t1",
        rule_id="r1",
        rule_version="1",
        severity=AlertSeverity.HIGH,
        title="Title",
        description="Desc",
        status=AlertStatus.NEW,
        entity_ids=["10.0.0.1"],
        evidence=ev,
        provenance=prov,
        mitre_tactics=["TA0001"],
        mitre_techniques=["T1190"],
        detected_at="2026-09-07T12:00:00Z",
        indexed_at="2026-09-07T12:00:01Z",
    )
    det_repo.save(det)
    loaded_det = det_repo.get("det-sqlite-1", tenant_id="t1")
    assert loaded_det is not None
    assert loaded_det.detection_id == "det-sqlite-1"
    assert loaded_det.severity == AlertSeverity.HIGH
    assert det_repo.count("t1") == 1

    # 2. Correlation Repo
    group = CorrelationGroup(
        group_id="grp-sqlite-1",
        tenant_id="t1",
        title="Group 1",
        correlation_type="HOST",
        detection_ids=["det-sqlite-1"],
        primary_entity_id="10.0.0.1",
        aggregated_risk=0.85,
        status="ACTIVE",
        created_at="2026-09-07T12:00:00Z",
        updated_at="2026-09-07T12:00:00Z",
    )
    corr_repo.save(group)
    loaded_grp = corr_repo.get("grp-sqlite-1")
    assert loaded_grp is not None
    assert loaded_grp.aggregated_risk == 0.85

    # 3. Anomaly Repo
    anom = AnomalyEvent(
        anomaly_id="anom-sqlite-1",
        tenant_id="t1",
        entity_id="host-1",
        metric_name="bytes_out",
        observed_value=1000000.0,
        baseline_mean=5000.0,
        baseline_std=100.0,
        z_score=9950.0,
        severity=AlertSeverity.CRITICAL,
        detected_at="2026-09-07T12:00:00Z",
    )
    anom_repo.save(anom)
    loaded_anom = anom_repo.get("anom-sqlite-1")
    assert loaded_anom is not None
    assert loaded_anom.observed_value == 1000000.0

    # 4. Case Repo
    case = InvestigationCase(
        case_id="case-sqlite-1",
        tenant_id="t1",
        title="Investigation 1",
        severity=AlertSeverity.HIGH,
        status=CaseStatus.OPEN,
        assignee="analyst",
        detection_ids=["det-sqlite-1"],
        entity_ids=["10.0.0.1"],
        timeline=[],
        notes=[],
        created_at="2026-09-07T12:00:00Z",
        updated_at="2026-09-07T12:00:00Z",
    )
    case_repo.save(case)
    loaded_case = case_repo.get("case-sqlite-1")
    assert loaded_case is not None
    assert loaded_case.title == "Investigation 1"

    # 5. Rule Repo
    rule = DetectionRule(
        rule_id="rule-sqlite-1",
        name="Rule 1",
        description="Desc",
        severity=AlertSeverity.MEDIUM,
        conditions=[RuleCondition("f", RuleOperator.EQUALS, "v")],
    )
    rule_repo.save(rule, state=RuleState.DRAFT)
    loaded_rule, state = rule_repo.get("rule-sqlite-1")
    assert loaded_rule.rule_id == "rule-sqlite-1"
    assert state == RuleState.DRAFT

    db.close()


# ---------------------------------------------------------------------------
# Test 18: Security RBAC Intelligence Permissions
# ---------------------------------------------------------------------------
def test_security_rbac_intelligence() -> None:
    policy = PolicyEngine()

    # Viewer can read intelligence
    viewer_id = IdentityContext(subject="viewer-1", issuer="local", roles={"viewer"})
    assert policy.has_permission(viewer_id, Permission.INTELLIGENCE_READ) is True
    assert policy.has_permission(viewer_id, Permission.CASE_WRITE) is False

    # Analyst can hunt and write cases
    analyst_id = IdentityContext(subject="analyst-1", issuer="local", roles={"analyst"})
    assert policy.has_permission(analyst_id, Permission.INTELLIGENCE_HUNT) is True
    assert policy.has_permission(analyst_id, Permission.CASE_WRITE) is True
    assert policy.has_permission(analyst_id, Permission.RULE_ACTIVATE) is False

    # Detection engineer can review and activate rules
    engineer_id = IdentityContext(subject="eng-1", issuer="local", roles={"detection-engineer"})
    assert policy.has_permission(engineer_id, Permission.RULE_ACTIVATE) is True
    assert policy.has_permission(engineer_id, Permission.DETECTION_MANAGE) is True
    assert policy.has_permission(engineer_id, Permission.CASE_WRITE) is False

    # Platform admin has all
    admin_id = IdentityContext(subject="admin-1", issuer="local", roles={"platform-admin"})
    assert policy.has_permission(admin_id, Permission.RULE_ACTIVATE) is True
    assert policy.has_permission(admin_id, Permission.CASE_WRITE) is True
    assert policy.has_permission(admin_id, Permission.INTELLIGENCE_HUNT) is True


# ---------------------------------------------------------------------------
# Test 19: FastAPI Intelligence REST API Routes
# ---------------------------------------------------------------------------
def test_api_intelligence_routes() -> None:
    app = create_app()
    client = TestClient(app)

    # 1. Register a rule via API
    rule_payload = {
        "rule_id": "api-rule-1",
        "name": "API Detected Port Scan",
        "description": "API scan test",
        "severity": "HIGH",
        "conditions": [
            {"field": "event_type", "operator": "EQUALS", "value": "port_scan"},
        ],
        "mitre_tactics": ["TA0043"],
        "mitre_techniques": ["T1046"],
    }
    # Viewer cannot register rules
    res_forbid = client.post("/api/v1/intelligence/rules", json=rule_payload, headers={"X-ULPF-Role": "viewer"})
    assert res_forbid.status_code == 403

    # Detection engineer can register rules
    res_reg = client.post("/api/v1/intelligence/rules", json=rule_payload, headers={"X-ULPF-Role": "detection-engineer"})
    assert res_reg.status_code == 200
    assert res_reg.json()["rule_id"] == "api-rule-1"

    # Activate rule
    res_act = client.post("/api/v1/intelligence/rules/api-rule-1/activate", headers={"X-ULPF-Role": "detection-engineer"})
    assert res_act.status_code == 200
    assert res_act.json()["state"] == "ACTIVE"

    # 2. Evaluate an event against registered rules
    eval_payload = {
        "event_id": "evt-eval-1",
        "tenant_id": "default",
        "timestamp": "2026-09-07T12:00:00Z",
        "attributes": {"event_type": "port_scan", "src_ip": "192.168.5.10"},
        "raw_hash": "hash123",
    }
    res_eval = client.post("/api/v1/intelligence/detections/evaluate", json=eval_payload, headers={"X-ULPF-Role": "operator"})
    assert res_eval.status_code == 200
    eval_data = res_eval.json()
    assert eval_data["matched_count"] == 1
    assert eval_data["detections"][0]["rule_id"] == "api-rule-1"

    # 3. Create case via API
    case_payload = {
        "title": "API Investigation",
        "severity": "HIGH",
        "tenant_id": "default",
        "assignee": "analyst-1",
        "initial_detection_ids": [eval_data["detections"][0]["detection_id"]],
    }
    res_case = client.post("/api/v1/intelligence/cases", json=case_payload, headers={"X-ULPF-Role": "analyst"})
    assert res_case.status_code == 200
    case_id = res_case.json()["case_id"]

    # 4. Add case note
    res_note = client.post(
        f"/api/v1/intelligence/cases/{case_id}/notes",
        json={"content": "Investigating affected subnets."},
        headers={"X-ULPF-Role": "analyst"},
    )
    assert res_note.status_code == 200

    # 5. Generate deterministic local advisory summary
    res_adv = client.post(
        "/api/v1/intelligence/advisor/summary",
        json={"case_id": case_id},
        headers={"X-ULPF-Role": "analyst"},
    )
    assert res_adv.status_code == 200
    adv_data = res_adv.json()
    assert adv_data["case_id"] == case_id
    assert adv_data["provenance_tag"] == "AI_GENERATED"
