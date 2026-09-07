"""Phase 7 Test: Backup and Restore.

Verifies:
- Rule D1: Encrypted, checksummed, versioned backups are created
- Rule D1: Restore verification checks checksums on all components
- Rule D1: Tampered backup component is detected on restore
- Rule D3: Manifest contains schema version and component checksums
"""

from pathlib import Path

import pytest
from ulpf_runtime.backup import BackupError, BackupManager


@pytest.fixture()
def backup_root(tmp_path: Path) -> Path:
    return tmp_path / "backups"


@pytest.fixture()
def manager(backup_root: Path) -> BackupManager:
    return BackupManager(backup_root=backup_root, encryption_password="test-backup-password")


def test_create_backup_produces_manifest(manager: BackupManager) -> None:
    components = {
        "database": b"CREATE TABLE events ...",
        "mappings": b'{"mappings": []}',
        "audit": b"audit record 1\naudit record 2",
    }
    manifest = manager.create_backup(components, schema_version=7, backup_id="backup-001")

    assert manifest.backup_id == "backup-001"
    assert manifest.schema_version == 7
    assert set(manifest.components.keys()) == {"database", "mappings", "audit"}
    assert all(len(sha256) == 64 for sha256 in manifest.components.values())


def test_restore_returns_original_data(manager: BackupManager) -> None:
    components = {
        "database": b"sqlite database dump content",
        "profiles": b'{"source": "fw-A"}',
    }
    manifest = manager.create_backup(components, schema_version=7, backup_id="backup-restore-01")
    assert manifest.backup_id == "backup-restore-01"
    restored_manifest, restored_components = manager.restore_backup("backup-restore-01")

    assert restored_manifest.schema_version == 7
    assert restored_components["database"] == components["database"]
    assert restored_components["profiles"] == components["profiles"]


def test_tampered_backup_detected_on_restore(
    manager: BackupManager, backup_root: Path
) -> None:
    components = {"database": b"legitimate database dump"}
    manager.create_backup(components, schema_version=7, backup_id="backup-tamper-01")

    # Tamper the encrypted file directly
    enc_path = backup_root / "backup-tamper-01" / "database.enc"
    enc_path.write_bytes(b"tampered encrypted content padding here 0000000000")

    with pytest.raises(BackupError, match="[Cc]hecksum"):
        manager.restore_backup("backup-tamper-01")


def test_restore_nonexistent_backup_raises(manager: BackupManager) -> None:
    with pytest.raises(BackupError, match="not found"):
        manager.restore_backup("backup-does-not-exist")


def test_list_backups_returns_ids(manager: BackupManager) -> None:
    manager.create_backup({"db": b"data"}, schema_version=7, backup_id="bk-001")
    manager.create_backup({"db": b"data"}, schema_version=7, backup_id="bk-002")
    backups = manager.list_backups()
    assert "bk-001" in backups
    assert "bk-002" in backups


def test_delete_backup(manager: BackupManager) -> None:
    manager.create_backup({"db": b"data"}, schema_version=7, backup_id="bk-del")
    manager.delete_backup("bk-del")
    assert "bk-del" not in manager.list_backups()


def test_multiple_components_all_checksummed(manager: BackupManager) -> None:
    components = {
        "database": b"db dump",
        "mappings": b"mapping config",
        "profiles": b"source profiles",
        "audit": b"audit trail",
    }
    manifest = manager.create_backup(components, schema_version=7, backup_id="bk-multi")
    assert len(manifest.components) == 4

    # Restore and verify all
    _, restored = manager.restore_backup("bk-multi")
    for name, data in components.items():
        assert restored[name] == data


def test_different_backups_have_different_checksums(manager: BackupManager) -> None:
    m1 = manager.create_backup({"db": b"version-1"}, schema_version=7, backup_id="bk-v1")
    m2 = manager.create_backup({"db": b"version-2"}, schema_version=7, backup_id="bk-v2")
    assert m1.components["db"] != m2.components["db"]
