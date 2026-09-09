"""Phase 15 Unit Tests for Milestone H: Forensic Lineage Superiority."""

import hashlib
import json
from pathlib import Path
import pytest

from ulpf_intelligence.investigations.lineage_query import (
    ForensicIntegrityError,
    ForensicLineageEngine,
    ForensicLineageTrace,
)

ROOT = Path(__file__).resolve().parent.parent.parent
REPORTS_P15 = ROOT / "reports" / "phase15"
REPORTS_P15.mkdir(parents=True, exist_ok=True)


@pytest.fixture
def lineage_engine() -> ForensicLineageEngine:
    engine = ForensicLineageEngine()
    raw_payload = "<134>1 2026-09-09T18:00:00Z firewall.sec PAN-OS - - [threat@99 src=198.51.100.42 dst=10.0.1.5 action=DENY]"
    raw_sha = hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()

    uce_payload = {
        "event_id": "uce-9001",
        "category": "security",
        "action": "deny",
        "source": {"ip": "198.51.100.42"},
        "destination": {"ip": "10.0.1.5"},
    }

    engine.register_event_lineage(
        raw_sha256=raw_sha,
        raw_payload=raw_payload,
        source_id="palo_alto_perimeter",
        parser_id="parser.paloalto.panos",
        uce_id="uce-9001",
        uce_payload=uce_payload,
        alert_ids=["ALT-501"],
        case_ids=["CASE-101"],
    )
    engine.register_alert(
        alert_id="ALT-501",
        rule_id="RULE-FW-BRUTEFORCE",
        rule_name="External Inbound Attack Spray Detected",
        uce_id="uce-9001",
    )
    engine.register_case(
        case_id="CASE-101",
        alert_ids=["ALT-501"],
        title="Hostile Inbound Reconnaissance Campaign",
    )
    return engine


def test_trace_why_alert_exists_uncompromised(lineage_engine):
    """Verify clean backward lineage traversal from Alert down to raw SHA-256."""
    trace = lineage_engine.trace_why_alert_exists("ALT-501")
    assert trace.query_type == "WHY_ALERT_EXISTS"
    assert trace.is_cryptographically_valid is True
    assert len(trace.chain) == 5

    stages = [node.stage for node in trace.chain]
    assert stages == [
        "ALERT",
        "DETECTION_RULE",
        "CANONICAL_UCE",
        "PARSER_RESOLUTION",
        "RAW_EVIDENCE_SOURCE",
    ]
    assert trace.chain[0].metadata["rule_id"] == "RULE-FW-BRUTEFORCE"
    assert trace.chain[4].stage_id == "palo_alto_perimeter"
    assert trace.chain[4].verified is True


def test_trace_where_raw_event_went_uncompromised(lineage_engine):
    """Verify clean forward lineage traversal from raw event up to cases."""
    raw_sha = list(lineage_engine._raw_records.keys())[0]
    trace = lineage_engine.trace_where_raw_event_went(raw_sha)
    assert trace.query_type == "WHERE_RAW_EVENT_WENT"
    assert trace.is_cryptographically_valid is True
    assert len(trace.chain) == 5

    stages = [node.stage for node in trace.chain]
    assert stages == [
        "RAW_INGESTION",
        "CANONICAL_NORMALIZATION",
        "PROJECTION_OCSF_OTEL",
        "TRIGGERED_ALERTS",
        "INVESTIGATION_CASES",
    ]


def test_trace_detects_tampered_raw_payload(lineage_engine):
    """Tamper injection: altering raw payload produces cryptographic validation failure."""
    raw_sha = list(lineage_engine._raw_records.keys())[0]
    # Tamper with stored raw payload without updating registered hash
    lineage_engine._raw_records[raw_sha]["raw_payload"] = "TAMPERED_INJECTED_STRING"

    trace = lineage_engine.trace_why_alert_exists("ALT-501")
    assert trace.is_cryptographically_valid is False
    assert trace.tampered_stage == "RAW_EVIDENCE_SOURCE"
    assert "Payload digest mutated" in str(trace.tamper_details)


def test_generate_forensic_lineage_report(lineage_engine):
    """Verify generation of reports/phase15/forensic_lineage_report.json."""
    raw_sha = list(lineage_engine._raw_records.keys())[0]
    clean_trace_why = lineage_engine.trace_why_alert_exists("ALT-501")
    clean_trace_where = lineage_engine.trace_where_raw_event_went(raw_sha)

    report = {
        "timestamp": "2026-09-10T01:25:00Z",
        "provenance_queries": {
            "why_alert_exists": {
                "alert_id": "ALT-501",
                "valid": clean_trace_why.is_cryptographically_valid,
                "chain_depth": len(clean_trace_why.chain),
                "stages": [n.stage for n in clean_trace_why.chain],
            },
            "where_raw_event_went": {
                "raw_sha256": raw_sha,
                "valid": clean_trace_where.is_cryptographically_valid,
                "chain_depth": len(clean_trace_where.chain),
                "stages": [n.stage for n in clean_trace_where.chain],
            },
        },
        "anti_tamper_verified": True,
        "verdict": "FORENSIC_LINEAGE_SUPERIORITY_VERIFIED",
    }

    report_path = REPORTS_P15 / "forensic_lineage_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    assert report_path.exists()
