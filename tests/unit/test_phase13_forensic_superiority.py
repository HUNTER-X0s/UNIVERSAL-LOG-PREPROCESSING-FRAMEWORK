"""Phase 13 Unit Tests for Milestone C: Forensic Superiority (Workstreams E, G, N, O, P)."""

import hashlib
import pytest
from ulpf_intelligence.investigations.attack_story import AttackStoryEngine
from ulpf_intelligence.investigations.case_package import CasePackageManager
from ulpf_intelligence.investigations.dual_view import DualViewGenerator
from ulpf_intelligence.investigations.investigate import OneClickInvestigationService


def test_dual_view_generator():
    raw_log = 'date=2024-09-01 time=10:00:00 devname="FGT-500E" type="traffic" action="deny" srcip=10.1.1.5 dstip=172.16.2.10'
    uce = {
        "event.timestamp": "2024-09-01T10:00:00Z",
        "event.action": "deny",
        "event.severity": "high",
        "source.ip": "10.1.1.5",
        "destination.ip": "172.16.2.10",
        "source.port": 54321,
        "destination.port": 443,
    }
    dv = DualViewGenerator.generate(
        event_id="evt-101",
        raw_payload=raw_log,
        uce_event=uce,
        source_vendor="Fortinet",
    )
    assert dv.event_id == "evt-101"
    assert dv.raw_sha256 == hashlib.sha256(raw_log.encode("utf-8")).hexdigest()
    assert dv.ocsf_projection["class_uid"] in (2001, 4001)
    assert dv.ocsf_projection["src_endpoint"]["ip"] == "10.1.1.5"
    assert dv.otel_projection["Attributes"]["ulpf.event.id"] == "evt-101"
    assert dv.lineage_chain_verified is True
    assert "source.ip" in dv.classification.normalized_uce_fields


def test_attack_story_engine():
    events = [
        {
            "event_id": "evt-01",
            "timestamp": "2026-09-09T10:00:00Z",
            "event.action": "login_failed",
            "source.ip": "198.51.100.5",
            "user.name": "admin",
            "raw_sha256": "sha_auth_1",
            "vendor": "Linux Auditd",
        },
        {
            "event_id": "evt-02",
            "timestamp": "2026-09-09T10:02:00Z",
            "event.action": "sudo_exec",
            "source.ip": "10.0.0.15",
            "user.name": "root",
            "raw_sha256": "sha_exec_2",
            "vendor": "Linux Auditd",
        },
        {
            "event_id": "evt-03",
            "timestamp": "2026-09-09T10:05:00Z",
            "event.action": "outbound_threat_deny",
            "source.ip": "10.0.0.15",
            "destination.ip": "203.0.113.88",
            "raw_sha256": "sha_net_3",
            "vendor": "Palo Alto",
        },
    ]
    story = AttackStoryEngine.construct_story(
        title="Lateral Intrusion Test",
        events=events,
    )
    assert len(story.milestones) == 3
    assert story.milestones[0].phase_name == "Initial Access"
    assert story.milestones[1].phase_name == "Privilege Escalation"
    assert story.milestones[2].phase_name == "Command & Control / Exfiltration"
    assert story.composite_confidence >= 0.90
    assert "10.0.0.15" in story.primary_entities


def test_case_package_manager_clean_and_tamper():
    raw_events = [
        {"event_id": "evt-01", "raw_payload": "type=SYSCALL syscall=59 exe=/bin/bash"},
        {"event_id": "evt-02", "raw_payload": "%ASA-4-106023: Deny tcp src 10.1.1.1 dst 10.2.2.2"},
    ]
    pkg = CasePackageManager.create_package(
        case_id="case-test-1",
        title="Test Forensic Package",
        raw_events=raw_events,
    )
    assert pkg["manifest"]["event_count"] == 2
    assert len(pkg["manifest"]["raw_digests"]) == 2

    # Verification passes on untampered package
    res = CasePackageManager.verify_package(pkg)
    assert res.is_valid is True
    assert res.tamper_detected is False
    assert res.events_verified == 2

    # Single-bit mutation tamper detection
    pkg["events"][0]["raw_payload"] = "type=SYSCALL syscall=59 exe=/bin/sh"  # Modified
    tamper_res = CasePackageManager.verify_package(pkg)
    assert tamper_res.is_valid is False
    assert tamper_res.tamper_detected is True
    assert len(tamper_res.errors) >= 1


def test_one_click_investigation():
    corpus = [
        {"event_id": "evt-1", "source.ip": "10.1.1.99", "event.action": "auth_login", "raw_sha256": "h1"},
        {"event_id": "evt-2", "source.ip": "10.1.1.99", "destination.ip": "192.168.1.5", "event.action": "outbound_connect", "raw_sha256": "h2"},
    ]
    dossier = OneClickInvestigationService.investigate("10.1.1.99", corpus)
    assert dossier.indicator_type == "IP"
    assert dossier.related_events_count == 2
    assert len(dossier.ai_summary.verified_facts) >= 2
    assert len(dossier.ai_summary.system_inferences) >= 1
    assert len(dossier.ai_summary.analyst_suggestions) >= 1
    assert "evt-1" in dossier.ai_summary.grounding_citations
