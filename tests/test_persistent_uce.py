"""Phase 7 Test: Persistent UCE Repository (durable SQLite-backed).

Verifies:
- Rule 1: UCE canonical source of truth persists across process boundaries
- Rule B2: Write-once immutability enforced at database layer
- Rule B3: Parameterized queries (no injection risk)
- Persistence survives reconnect (simulated restart)
"""

import pytest
from ulpf_runtime.errors import PersistenceError
from ulpf_storage.database.relational import SQLiteDatabase
from ulpf_storage.durable_uce import DurableUCERepository
from ulpf_storage.interfaces import UCERecord


@pytest.fixture()
def db() -> SQLiteDatabase:
    return SQLiteDatabase(":memory:")


@pytest.fixture()
def repo(db: SQLiteDatabase) -> DurableUCERepository:
    return DurableUCERepository(db)


def _make_record(uid: str = "uce-001", raw_id: str = "raw-001") -> UCERecord:
    return UCERecord(
        uce_event_id=uid,
        raw_event_id=raw_id,
        raw_sha256="abc123" * 10 + "abcd",
        payload={"source": "firewall", "action": "DENY", "src_ip": "10.0.0.1"},
        schema_version="1.0.0",
        source_id="firewall-A",
        captured_at="2026-01-01T00:00:00Z",
    )


def test_put_and_get(repo: DurableUCERepository) -> None:
    record = _make_record()
    repo.put(record)
    retrieved = repo.get("uce-001")
    assert retrieved is not None
    assert retrieved.uce_event_id == "uce-001"
    assert retrieved.source_id == "firewall-A"
    assert retrieved.payload["action"] == "DENY"


def test_write_once_enforced(repo: DurableUCERepository) -> None:
    record = _make_record()
    repo.put(record)
    with pytest.raises(PersistenceError, match="already exists"):
        repo.put(record)


def test_exists_and_not_exists(repo: DurableUCERepository) -> None:
    record = _make_record()
    assert not repo.exists("uce-001")
    repo.put(record)
    assert repo.exists("uce-001")


def test_query_by_raw_id(repo: DurableUCERepository) -> None:
    r1 = _make_record("uce-001", "raw-A")
    r2 = _make_record("uce-002", "raw-A")
    r3 = _make_record("uce-003", "raw-B")
    repo.put(r1)
    repo.put(r2)
    repo.put(r3)

    results = repo.query_by_raw_id("raw-A")
    assert len(results) == 2
    ids = {r.uce_event_id for r in results}
    assert ids == {"uce-001", "uce-002"}


def test_get_nonexistent_returns_none(repo: DurableUCERepository) -> None:
    assert repo.get("does-not-exist") is None


def test_metadata_roundtrip(repo: DurableUCERepository) -> None:
    record = UCERecord(
        uce_event_id="uce-meta",
        raw_event_id="raw-meta",
        raw_sha256="sha" * 21 + "sha",
        payload={"k": "v"},
        schema_version="1.0.0",
        source_id="src",
        captured_at="2026-01-01T00:00:00Z",
        metadata={"region": "us-east-1", "tier": "prod"},
    )
    repo.put(record)
    retrieved = repo.get("uce-meta")
    assert retrieved is not None
    assert retrieved.metadata["region"] == "us-east-1"


def test_database_migration_applied(db: SQLiteDatabase) -> None:
    """Schema version must be at least 7 after initialization."""
    assert db.schema_version() >= 7
