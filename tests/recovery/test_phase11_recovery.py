"""Phase 11 Disaster Recovery & Backup Certification Suite.

Validates encrypted, checksummed backups, detection of corrupted or tampered archives,
wrong encryption passwords, and measured Recovery Time Objective (RTO).
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from ulpf_runtime.backup import BackupError, BackupManager


@pytest.fixture
def backup_dir(tmp_path: Path) -> Path:
    return tmp_path / "phase11_backups"


@pytest.fixture
def backup_mgr(backup_dir: Path) -> BackupManager:
    return BackupManager(
        backup_root=backup_dir,
        encryption_password="phase11-dr-test-master-key",  # noqa: S106
    )


# ===========================================================================
# 1. Backup Integrity & Wrong-Key Detection
# ===========================================================================

def test_backup_rejects_wrong_decryption_password(
    backup_mgr: BackupManager, backup_dir: Path
) -> None:
    """Verify attempting restore with an incorrect encryption key fails closed."""
    components = {"db": b"CRITICAL_DATABASE_PAYLOAD_EVIDENCE"}
    backup_mgr.create_backup(components, schema_version=10, backup_id="bk-pass-test")

    # Attempt restore using a different password
    wrong_key_mgr = BackupManager(
        backup_root=backup_dir,
        encryption_password="completely-wrong-password-attacker",  # noqa: S106
    )
    with pytest.raises(BackupError):
        wrong_key_mgr.restore_backup("bk-pass-test")


def test_corrupted_manifest_fails_closed(
    backup_mgr: BackupManager, backup_dir: Path
) -> None:
    """Verify tampering with the backup manifest json causes restore to fail."""
    components = {"canonical_events": b"event-1,event-2,event-3"}
    backup_mgr.create_backup(components, schema_version=10, backup_id="bk-manifest-tamper")

    manifest_file = backup_dir / "bk-manifest-tamper" / "manifest.json"
    assert manifest_file.exists()

    # Corrupt manifest contents
    manifest_file.write_text("{\"corrupted\": true, \"invalid\": 123}")

    with pytest.raises((BackupError, KeyError)):
        backup_mgr.restore_backup("bk-manifest-tamper")


# ===========================================================================
# 2. Measured RTO (Recovery Time Objective) Benchmark
# ===========================================================================

def test_measured_rto_within_operational_sla(
    backup_mgr: BackupManager,
) -> None:
    """Measure disaster recovery restore time and verify RTO is well within SLA (<2.0s)."""
    # Simulate a realistic dataset dump across all 4 key system stores
    components = {
        "sqlite_database": b"DURABLE_SQLITE_DATABASE_WAL_CONTENT" * 5000,
        "canonical_uce": b"UCE_CANONICAL_INDEX_STORE" * 5000,
        "threat_intel_index": b"THREAT_INTEL_ACTIVE_INDICATORS" * 2000,
        "audit_logs": b"IMMUTABLE_SECURITY_AUDIT_LOG_CHAIN" * 2000,
    }

    backup_mgr.create_backup(components, schema_version=10, backup_id="bk-rto-sla")

    t0 = time.perf_counter()
    restored_manifest, restored_components = backup_mgr.restore_backup("bk-rto-sla")
    elapsed_s = time.perf_counter() - t0

    # Verify data fidelity
    assert restored_manifest.schema_version == 10
    assert restored_components["sqlite_database"] == components["sqlite_database"]
    assert restored_components["canonical_uce"] == components["canonical_uce"]

    # RTO SLA: Must restore within 2.0s
    assert elapsed_s < 2.0, f"RTO recovery took {elapsed_s:.3f}s (exceeded 2.0s SLA)"
