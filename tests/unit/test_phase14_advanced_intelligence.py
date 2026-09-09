"""Tests for ULPF Phase 14 Milestone D — Advanced Intelligence & Correlation.

Verifies:
- Workstream Q: Multi-stage event correlation across heterogeneous sources
- Workstream R: Campaign clustering without speculative attribution
- Workstream S: Attack path graph & bounded traversal (DoS defense)
- Workstream T: Explainable risk propagation with mathematical audits
- Workstream U: Composite attack chain confidence scoring
- Workstream V: Security posture time-series trend tracking
- Workstream W: Early warning vs detection escalation
"""

import pytest
from ulpf_intelligence.graph.attack_graph import (
    AttackChainConfidenceScorer,
    AttackEdge,
    AttackNode,
    AttackPathGraph,
    EdgeRelation,
    NodeType,
)
from ulpf_intelligence.correlation.mission_correlator import (
    AlertStage,
    CampaignClusterer,
    MultiStageCorrelator,
    SecurityPostureTrendTracker,
)


def test_attack_path_graph_bounded_traversal():
    graph = AttackPathGraph(max_nodes=100)

    # Build chain: Internet IP -> Firewall -> Gateway -> DMZ Host -> Database
    graph.add_node("ip-198.51.100.23", NodeType.IP, "Attacker IP", base_risk=80.0)
    graph.add_node("fw-edge-01", NodeType.ASSET, "Edge Firewall", base_risk=10.0)
    graph.add_node("gw-internal", NodeType.ASSET, "Internal Gateway", base_risk=15.0)
    graph.add_node("host-dmz-01", NodeType.ASSET, "DMZ Host", base_risk=40.0)
    graph.add_node("db-prod-core", NodeType.ASSET, "Core DB", base_risk=10.0)

    graph.add_edge("ip-198.51.100.23", "fw-edge-01", EdgeRelation.COMMUNICATES_WITH)
    graph.add_edge("fw-edge-01", "gw-internal", EdgeRelation.COMMUNICATES_WITH)
    graph.add_edge("gw-internal", "host-dmz-01", EdgeRelation.LATERAL_MOVEMENT)
    graph.add_edge("host-dmz-01", "db-prod-core", EdgeRelation.AUTHENTICATED_AS)

    # Traversal bounded at depth 2
    res = graph.traverse_bounded("ip-198.51.100.23", max_depth=2, max_results=10)
    visited_ids = [n.node_id for n in res["nodes"]]
    assert "ip-198.51.100.23" in visited_ids
    assert "fw-edge-01" in visited_ids
    assert "gw-internal" in visited_ids
    assert "db-prod-core" not in visited_ids  # Bounded: depth 4 not reached!


def test_explainable_risk_propagation():
    graph = AttackPathGraph()
    graph.add_node("compromised_host", NodeType.ASSET, "Infected Workstation", base_risk=90.0)
    graph.add_node("internal_server", NodeType.ASSET, "File Server", base_risk=5.0)

    # Connect via lateral movement edge
    graph.add_edge(
        "compromised_host",
        "internal_server",
        EdgeRelation.LATERAL_MOVEMENT,
        confidence=0.9,
        propagation_weight=0.6,
        evidence_ids=["EV-RAW-991"],
    )

    audits = graph.propagate_risk(max_iterations=1)
    assert len(audits) >= 1
    audit = audits[0]
    assert audit.from_node_id == "compromised_host"
    assert audit.to_node_id == "internal_server"
    assert audit.added_risk > 0.0
    assert audit.evidence_ids == ["EV-RAW-991"]

    target_node = graph.nodes["internal_server"]
    assert target_node.total_risk > 5.0  # Risk successfully propagated!


def test_attack_chain_confidence_scorer():
    conf = AttackChainConfidenceScorer.calculate_confidence(
        event_confidences=[0.90, 0.85, 0.95],
        temporal_coherence=0.9,
        evidence_count=5,
        cross_source_count=3,
    )
    assert 0.80 <= conf <= 1.0


def test_multi_stage_event_correlation_and_escalation():
    correlator = MultiStageCorrelator(time_window_seconds=60.0)
    t0 = 1725880000.0

    # Step 1: Ingest 3 failed logins on host-web-01 from firewall & sshd
    c1 = correlator.ingest_event("ev-1", "fw-palo", "host-web-01", t0 + 1, "deny", "RAW-1")
    c2 = correlator.ingest_event("ev-2", "sshd-auth", "host-web-01", t0 + 2, "failed", "RAW-2")
    c3 = correlator.ingest_event("ev-3", "fw-palo", "host-web-01", t0 + 3, "deny", "RAW-3")

    # At 3 failures, should trigger EARLY_WARNING
    assert len(c3) == 1
    assert c3[0].stage == AlertStage.EARLY_WARNING
    assert "CORR-RULE-001" in c3[0].rule_id

    # Step 2: Now ingest successful execution from auditd on the same host
    c4 = correlator.ingest_event("ev-4", "linux-auditd", "host-web-01", t0 + 5, "exec", "RAW-4", mitre_technique="T1059")
    assert len(c4) == 1
    assert c4[0].stage == AlertStage.DETECTION  # Escalated to DETECTION!
    assert "T1059" in c4[0].mitre_techniques
    assert len(c4[0].evidence_ids) == 4


def test_campaign_clustering_and_posture_tracking():
    clusterer = CampaignClusterer()
    tracker = SecurityPostureTrendTracker()

    correlator = MultiStageCorrelator(time_window_seconds=60.0)
    events = correlator.ingest_event("ev-1", "fw", "srv-app", 1000.0, "deny", "R1")
    # Fabricate a correlated detection
    from ulpf_intelligence.correlation.mission_correlator import CorrelatedEvent
    c_ev = CorrelatedEvent(
        correlation_id="C-101",
        rule_id="R-1",
        stage=AlertStage.DETECTION,
        title="Command Injection",
        description="Exploitation observed",
        primary_entity="srv-app",
        contributing_sources=("fw", "auditd"),
        evidence_ids=("R1", "R2"),
        time_window_start=1000.0,
        time_window_end=1010.0,
        confidence=0.92,
        mitre_techniques=("T1059",),
    )

    camp = clusterer.cluster_event(c_ev, indicators=["198.51.100.77", "evil-c2.internal"])
    assert "srv-app" in camp.involved_entities
    assert "198.51.100.77" in camp.shared_indicators

    # Track posture trend
    snap1 = tracker.record_snapshot(95.0, active_threats=0, contributing_sources=["fw"], reason="Normal operations")
    assert snap1["trend"] == "STABLE"

    snap2 = tracker.record_snapshot(72.0, active_threats=1, contributing_sources=["fw", "auditd"], reason="Active attack detected")
    assert snap2["trend"] == "DEGRADING"
    assert snap2["delta"] == -23.0
