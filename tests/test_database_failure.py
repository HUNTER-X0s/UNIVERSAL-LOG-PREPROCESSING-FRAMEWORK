"""Phase 7 Test: Database Failure Mode.

Verifies:
- Rule D6: Database failure prevents false ACK (fail-closed)
- Rule D6: PersistenceError propagates; UCE is NOT ACKed on failure
- Rule D6: No silent swallowing of persistence failures
"""

from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from ulpf_runtime.errors import PersistenceError
from ulpf_storage.database.relational import DatabaseError, SQLiteDatabase
from ulpf_storage.durable_uce import DurableUCERepository
from ulpf_storage.interfaces import UCERecord


def _make_record(uid: str = "uce-fail") -> UCERecord:
    return UCERecord(
        uce_event_id=uid,
        raw_event_id="raw-fail",
        raw_sha256="abc" * 22 + "ab",
        payload={"k": "v"},
        schema_version="1.0.0",
        source_id="fw-A",
        captured_at=datetime.now(UTC).isoformat(),
    )


def test_database_error_raises_persistence_error() -> None:
    """When the DB is unavailable, PersistenceError must be raised (not swallowed)."""
    db = SQLiteDatabase(":memory:")
    repo = DurableUCERepository(db)

    # Simulate DB error by patching execute
    with patch.object(db, "execute", side_effect=DatabaseError("disk full")):
        with pytest.raises(PersistenceError):
            repo.put(_make_record())


def test_false_ack_impossible_on_db_failure() -> None:
    """Demonstrates that the caller receives an exception (no silent ACK) on DB failure.

    In production this means the message is NOT committed to the stream offset,
    so it will be replayed.
    """
    db = SQLiteDatabase(":memory:")
    repo = DurableUCERepository(db)

    acked = False
    try:
        with patch.object(db, "execute", side_effect=DatabaseError("DB unavailable")):
            repo.put(_make_record())
        # This line should NOT be reached
        acked = True
    except PersistenceError:
        pass

    assert not acked, "False ACK occurred: persistence error was silently swallowed"


def test_write_once_violation_raises_persistence_error() -> None:
    db = SQLiteDatabase(":memory:")
    repo = DurableUCERepository(db)
    record = _make_record("uce-dup")
    repo.put(record)

    with pytest.raises(PersistenceError, match="already exists"):
        repo.put(record)


def test_query_on_healthy_db_returns_results() -> None:
    db = SQLiteDatabase(":memory:")
    repo = DurableUCERepository(db)
    record = _make_record("uce-healthy")
    repo.put(record)
    result = repo.get("uce-healthy")
    assert result is not None
    assert result.uce_event_id == "uce-healthy"
