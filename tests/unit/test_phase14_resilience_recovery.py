"""Tests for ULPF Phase 14 Milestone F — Resilience, Backup/Restore & Diagnostics.

Verifies:
- Workstream AW, AX: Cryptographic backup creation, manifest integrity, and restore drill
- Workstream CH: Operator platform self-diagnostics
- Workstream AS, AT, AU: Mission telemetry and engineering SLO tracking
"""

import pytest
from ulpf_platform.backup_restore import DisasterRecoveryManager
from ulpf_platform.diagnostics import PlatformSelfDiagnostics
from ulpf_observability.telemetry_slo import MissionSLOTracker


def test_cryptographic_backup_and_restore_drill():
    dr = DisasterRecoveryManager()
    components = {
        "config": {"profile": "production", "airgap": True, "auth_enabled": True},
        "mappings": {"palo_alto": {"action": "event.action", "src_ip": "source.ip"}},
        "rules": [{"id": "RULE-1", "severity": "HIGH", "threshold": 5}],
        "cases": [{"id": "CASE-101", "state": "INVESTIGATING"}],
    }

    # 1. Create signed backup
    archive = dr.create_backup("BKP-2026-09-09", components)
    assert len(archive.manifest_hash) == 64
    assert len(archive.entries) == 4

    # 2. Verify backup integrity
    verif = dr.verify_backup_integrity("BKP-2026-09-09")
    assert verif["manifest_valid"] is True
    assert verif["is_restorable"] is True
    assert len(verif["corruptions"]) == 0

    # 3. Execute recovery drill
    drill = dr.execute_restore_drill("BKP-2026-09-09")
    assert drill["drill_status"] == "RESTORED_VERIFIED"
    assert drill["rpo_data_loss_bytes"] == 0
    assert set(drill["restored_components"]) == set(components.keys())


def test_backup_tamper_detection():
    dr = DisasterRecoveryManager()
    components = {"secret_rules": {"rule_1": "active"}}
    archive = dr.create_backup("BKP-TAMPER", components)

    # Tamper with payload
    archive.entries["secret_rules"].payload = '{"rule_1": "corrupted_by_attacker"}'

    verif = dr.verify_backup_integrity("BKP-TAMPER")
    assert verif["is_restorable"] is False
    assert len(verif["corruptions"]) >= 1


def test_platform_self_diagnostics():
    rep = PlatformSelfDiagnostics.run_diagnostics()
    assert rep.overall_health in ("GREEN", "DEGRADED")
    assert rep.passed_count >= 3
    assert rep.total_count >= 4
    check_names = [c.check_name for c in rep.checks]
    assert "Storage Access" in check_names
    assert "Core Packages" in check_names


def test_mission_slo_tracking_and_error_budget():
    tracker = MissionSLOTracker()

    # Record 100 fast ingestion events (0.5ms - 2.0ms)
    for _ in range(100):
        tracker.record_ingestion(1.2)

    # Record 20 fast queries (15.0ms)
    for _ in range(20):
        tracker.record_query(15.0)

    slos = tracker.compute_slos()
    assert slos["ingestion_latency"].status == "MET"
    assert slos["ingestion_latency"].current_compliance == 100.0
    assert slos["query_latency"].status == "MET"
    assert slos["lossless_evidence"].status == "MET"
    assert slos["lossless_evidence"].current_compliance == 100.0
