"""Phase 13 Unit Tests for Milestone B: Universal Intelligence (Workstreams A, B, C, D)."""

import pytest
from ulpf_onboarding import (
    DOMAIN_TEMPLATES,
    MappingDiffEngine,
    OnboardingService,
    SchemaDriftDetector,
    UniversalSourceIntelligenceEngine,
)
from ulpf_onboarding.models import DriftReport, DriftState, SourceProfile


def test_source_intelligence_palo_alto():
    sample = "1,2024/09/01 10:00:00,001234567890,TRAFFIC,drop,1,2024/09/01 10:00:00,10.0.0.1,192.168.1.1,0.0.0.0,0.0.0.0,rule1,vsys1"
    res = UniversalSourceIntelligenceEngine.analyze(sample)
    assert res.vendor == "Palo Alto Networks"
    assert res.device_family == "PAN-OS"
    assert res.source_family == "firewall"
    assert res.parser_candidate == "PaloAltoPanOSParser"
    assert res.confidence >= 0.70
    assert not res.is_unknown
    assert any("TRAFFIC" in ev for ev in res.evidence)


def test_source_intelligence_fortigate():
    sample = 'date=2024-09-01 time=10:00:00 devname="FGT-500E" devid="FG500E1234" type="traffic" subtype="forward" action="deny" policyid=42 srcip=10.1.1.5 dstip=172.16.2.10'
    res = UniversalSourceIntelligenceEngine.analyze(sample)
    assert res.vendor == "Fortinet"
    assert res.device_family == "FortiGate"
    assert res.parser_candidate == "FortiGateParser"
    assert res.confidence >= 0.70
    assert not res.is_unknown


def test_source_intelligence_cisco():
    sample = "%ASA-4-106023: Deny tcp src outside:198.51.100.2/1234 dst inside:10.0.0.5/80 by access-group"
    res = UniversalSourceIntelligenceEngine.analyze(sample)
    assert res.vendor == "Cisco"
    assert res.device_family == "ASA"
    assert res.parser_candidate == "CiscoSyslogParser"
    assert res.confidence >= 0.60


def test_source_intelligence_linux_auditd():
    sample = 'type=SYSCALL msg=audit(1725796800.123:1001): arch=c000003e syscall=59 success=yes exe="/bin/bash" key="exec"'
    res = UniversalSourceIntelligenceEngine.analyze(sample)
    assert res.vendor == "Linux"
    assert res.device_family == "Linux Auditd"
    assert res.parser_candidate == "LinuxAuditdParser"
    assert res.confidence >= 0.70


def test_source_intelligence_unknown_telemetry():
    sample = "DEVICE_CUSTOM_X random_token_foo=bar counter=9999"
    res = UniversalSourceIntelligenceEngine.analyze(sample)
    assert res.vendor == "Unknown"
    assert res.is_unknown
    assert res.parser_candidate == "KeyValueParser"
    assert res.confidence < 0.40
    assert "Unrecognized vendor signature" in res.explanation


def test_mapping_diff_engine():
    v1 = {
        "mapping_id": "map-v1",
        "field_mappings": {
            "src_ip": "source.ip",
            "dst_ip": "destination.ip",
            "old_action": "event.action",
        },
    }
    v2 = {
        "mapping_id": "map-v2",
        "field_mappings": {
            "src_ip": "source.ip",
            "dst_ip": "destination.ip",
            "new_field": "custom.field",
        },
    }
    diff = MappingDiffEngine.diff(v1, v2)
    assert diff.added_count == 1
    assert diff.removed_count == 1
    assert diff.impact_level == "HIGH"
    assert diff.rollback_recommended is True


def test_schema_drift_severity():
    report = DriftReport(
        report_id="rep-1",
        profile_id="prof-1",
        profile_version="1.0.0",
        drift_state=DriftState.BREAKING_DRIFT,
        timestamp="2026-09-09T12:00:00Z",
        type_changes=[{"field": "src_port", "old_type": "integer", "new_type": "string"}],
    )
    severity = SchemaDriftDetector.evaluate_severity(report)
    assert severity == "CRITICAL"
    summary = SchemaDriftDetector.generate_impact_summary(report)
    assert summary["rollback_recommended"] is True
    assert summary["parser_safe"] is False


def test_onboarding_service_phase13():
    svc = OnboardingService()
    sample = "%ASA-6-302013: Built inbound TCP connection 12345 for outside:192.0.2.1/443"
    intel = svc.analyze_source_intelligence(sample)
    assert intel.vendor == "Cisco"
    assert intel.confidence >= 0.60
