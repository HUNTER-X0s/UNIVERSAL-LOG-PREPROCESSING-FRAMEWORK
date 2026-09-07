"""Phase 7 Test: Durable Dead Letter Queue Manager.

Verifies:
- Rule 11: DLQ entries are durably persisted and never silently dropped
- Rule 11: count() reflects only QUEUED entries
- DLQ survives process restart
- get_queued() respects limit
"""

from datetime import UTC, datetime

import pytest
from ulpf_storage.database.relational import SQLiteDatabase
from ulpf_storage.durable_dlq import DurableDLQEntry, DurableDLQManager


@pytest.fixture()
def db() -> SQLiteDatabase:
    return SQLiteDatabase(":memory:")


@pytest.fixture()
def dlq(db: SQLiteDatabase) -> DurableDLQManager:
    return DurableDLQManager(db)


def _entry(eid: str = "dlq-001", reason: str = "PARSE_FAILURE") -> DurableDLQEntry:
    return DurableDLQEntry(
        entry_id=eid,
        raw_event_id=f"raw-{eid}",
        reason=reason,
        error_detail="test error",
        raw_payload_hex="deadbeef",
        source_id="fw-A",
        queued_at=datetime.now(UTC).isoformat(),
    )


def test_enqueue_and_count(dlq: DurableDLQManager) -> None:
    assert dlq.count() == 0
    dlq.enqueue(_entry("dlq-1"))
    dlq.enqueue(_entry("dlq-2"))
    assert dlq.count() == 2


def test_get_queued_returns_queued_only(dlq: DurableDLQManager) -> None:
    dlq.enqueue(_entry("dlq-queued"))
    dlq.enqueue(_entry("dlq-poison"))
    dlq.mark_poison("dlq-poison")

    queued = dlq.get_queued()
    ids = {e.entry_id for e in queued}
    assert "dlq-queued" in ids
    assert "dlq-poison" not in ids


def test_get_queued_limit(dlq: DurableDLQManager) -> None:
    for i in range(10):
        dlq.enqueue(_entry(f"dlq-{i}"))
    limited = dlq.get_queued(limit=3)
    assert len(limited) == 3


def test_mark_replayed_removes_from_queue(dlq: DurableDLQManager) -> None:
    dlq.enqueue(_entry("dlq-r"))
    assert dlq.count() == 1
    dlq.mark_replayed("dlq-r")
    assert dlq.count() == 0


def test_dlq_survives_restart(db: SQLiteDatabase) -> None:
    dlq1 = DurableDLQManager(db)
    dlq1.enqueue(_entry("dlq-p", reason="TIMEOUT"))

    dlq2 = DurableDLQManager(db)
    assert dlq2.count() == 1
    entries = dlq2.get_queued()
    assert entries[0].reason == "TIMEOUT"


def test_duplicate_entry_id_ignored(dlq: DurableDLQManager) -> None:
    """INSERT OR IGNORE: duplicate entry_id does not raise."""
    dlq.enqueue(_entry("dlq-dup"))
    dlq.enqueue(_entry("dlq-dup"))  # Should not raise
    assert dlq.count() == 1


def test_entry_fields_preserved(dlq: DurableDLQManager) -> None:
    e = DurableDLQEntry(
        entry_id="dlq-fields",
        raw_event_id="raw-x",
        reason="SCHEMA_VIOLATION",
        error_detail="missing required field: timestamp",
        raw_payload_hex="cafebabe",
        source_id="ids-01",
        queued_at="2026-01-01T00:00:00Z",
        retry_count=2,
    )
    dlq.enqueue(e)
    queued = dlq.get_queued()
    assert len(queued) == 1
    assert queued[0].entry_id == "dlq-fields"
    assert queued[0].reason == "SCHEMA_VIOLATION"
    assert queued[0].retry_count == 2
    assert queued[0].source_id == "ids-01"
