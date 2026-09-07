"""Phase 11 Evidence Integrity & Lineage Adversarial Suite.

Verifies tamper detection in evidence containers, backward cryptographic lineage,
and multi-run replay determinism.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

from ulpf_advanced_intelligence.evidence.lineage import ForensicLineageVerifier
from ulpf_advanced_intelligence.evidence.packaging import EvidencePackageGenerator
from ulpf_intelligence.models.events import (
    DetectionEvent,
    DetectionEvidence,
    InvestigationCase,
)
from ulpf_intelligence.models.provenance import (
    AlertSeverity,
    CaseStatus,
    IntelligenceProvenance,
)
from ulpf_mission.replay.lab import ReplayLab

# ===========================================================================
# 1. Cryptographic Evidence Package Tamper-Resistance
# ===========================================================================

def test_evidence_package_tampering_detected() -> None:
    """Verify modifying any supporting event or detection breaks the manifest hash check."""
    case = InvestigationCase(
        case_id="case-audit-001",
        title="Unauthorized Exfiltration",
        description="Data exfiltration to external IP",
        status=CaseStatus.OPEN,
        tenant_id="tenant-alpha",
        detection_ids=["det-01"],
        event_ids=["ev-100"],
    )

    events = [
        {"event_id": "ev-100", "src_ip": "10.0.0.5", "dst_ip": "198.51.100.2", "bytes": 54000}
    ]
    detections = [
        {"detection_id": "det-01", "rule_id": "RULE_EXFIL_VOLUME", "score": 85.0}
    ]

    pkg = EvidencePackageGenerator.create_package(
        case=case,
        supporting_events=events,
        detections=detections,
        timeline=[],
        version_pins={"engine": "1.0.0"},
    )

    original_manifest_sha = pkg.manifest.overall_sha256
    assert len(original_manifest_sha) == 64

    # Verification passes for untouched event
    ev_bytes = json.dumps(events[0], sort_keys=True).encode("utf-8")
    ev_digest = hashlib.sha256(ev_bytes).hexdigest()
    assert pkg.manifest.checksums[0].sha256 == ev_digest

    # Tamper attempt: change bytes field from 54000 to 10
    tampered_event = {"event_id": "ev-100", "src_ip": "10.0.0.5", "dst_ip": "198.51.100.2", "bytes": 10}
    tampered_bytes = json.dumps(tampered_event, sort_keys=True).encode("utf-8")
    tampered_digest = hashlib.sha256(tampered_bytes).hexdigest()

    # The tampered digest must NOT match the sealed manifest entry
    assert pkg.manifest.checksums[0].sha256 != tampered_digest


# ===========================================================================
# 2. Backward Lineage Verification
# ===========================================================================

def test_unbroken_lineage_verification() -> None:
    """Verify unbroken backward traceability from Case -> Detection -> Event."""
    now = datetime.now(UTC)
    det = DetectionEvent(
        detection_id="det-10",
        rule_id="RULE_BRUTE_FORCE",
        rule_version="1.0.0",
        title="Brute Force Alert",
        description="Multiple failed auth events",
        severity=AlertSeverity.HIGH,
        confidence=0.9,
        risk_score=75.0,
        evidence=DetectionEvidence(matched_event_ids=("ev-1", "ev-2")),
        tenant_id="tenant-alpha",
        created_at=now.isoformat(),
        provenance=IntelligenceProvenance.DETECTED,
    )
    case = InvestigationCase(
        case_id="case-10",
        title="Brute Force Investigation",
        description="Auth attack",
        status=CaseStatus.IN_PROGRESS,
        tenant_id="tenant-alpha",
        detection_ids=["det-10"],
        event_ids=["ev-1", "ev-2"],
    )

    events = [
        {"event_id": "ev-1", "action": "login_failure"},
        {"event_id": "ev-2", "action": "login_failure"},
    ]

    report = ForensicLineageVerifier.verify_case_lineage(
        case=case,
        available_detections=[det],
        available_events=events,
    )
    assert report.is_valid is True
    assert len(report.missing_event_refs) == 0
    assert len(report.missing_detection_refs) == 0


def test_broken_lineage_detected_on_missing_reference() -> None:
    """Verify dangling event or detection references are immediately flagged as invalid."""
    case = InvestigationCase(
        case_id="case-dangling",
        title="Broken Lineage Case",
        description="References missing detection",
        status=CaseStatus.OPEN,
        tenant_id="tenant-alpha",
        detection_ids=["det-nonexistent"],
        event_ids=["ev-missing"],
    )

    report = ForensicLineageVerifier.verify_case_lineage(
        case=case,
        available_detections=[],
        available_events=[],
    )
    assert report.is_valid is False
    assert "det-nonexistent" in report.missing_detection_refs


# ===========================================================================
# 3. Deterministic Replay Verification
# ===========================================================================

def test_replay_lab_multi_run_determinism() -> None:
    """Verify ReplayLab yields identical SHA-256 state hashes across multiple runs."""
    lab = ReplayLab()
    events = [
        {"id": f"ev-{i}", "event_type": "login_failed", "user": f"user-{i % 5}"}
        for i in range(100)
    ]
    rules = {"RULE_LOGIN_FAIL": {"event_type": "login_failed"}}

    result = lab.verify_determinism(events, detection_rules=rules, runs=5)
    assert result.determinism_verified is True
    assert len(result.sessions) == 5

    # All 5 sessions must produce identical output_sha256
    first_hash = result.sessions[0].output_sha256
    for sess in result.sessions:
        assert sess.output_sha256 == first_hash
