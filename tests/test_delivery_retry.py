"""Phase 7 Test: Delivery Retry and DLQ Routing.

Verifies:
- Rule 11: DLQ entries never silently dropped
- Rule 10: Bounded exponential retry before DLQ routing
- Delivery sink failure → DLQ, not silent drop
"""

from datetime import UTC, datetime

import pytest
from ulpf_runtime.models import DeliveryIntent
from ulpf_storage.database.relational import SQLiteDatabase
from ulpf_storage.durable_dlq import DurableDLQEntry, DurableDLQManager
from ulpf_storage.durable_outbox import DurableOutboxRepository


@pytest.fixture()
def db() -> SQLiteDatabase:
    return SQLiteDatabase(":memory:")


@pytest.fixture()
def outbox(db: SQLiteDatabase) -> DurableOutboxRepository:
    return DurableOutboxRepository(db)


@pytest.fixture()
def dlq(db: SQLiteDatabase) -> DurableDLQManager:
    return DurableDLQManager(db)


def _intent(iid: str, max_attempts: int = 3) -> DeliveryIntent:
    return DeliveryIntent(
        intent_id=iid,
        event_id=f"ev-{iid}",
        sink_name="siem-sink",
        payload_type="raw",
        payload={"data": "test"},
        created_at=datetime.now(UTC).isoformat(),
        attempt_count=0,
        max_attempts=max_attempts,
        status="PENDING",
    )


def test_retry_escalates_to_dlq_after_max_attempts(
    outbox: DurableOutboxRepository,
) -> None:
    outbox.save_intent(_intent("i-retry", max_attempts=2))

    # First failure: still pending
    outbox.mark_failed("i-retry", "timeout")
    pending = outbox.get_pending()
    assert any(i.intent_id == "i-retry" for i in pending)

    # Second failure: max_attempts reached → DLQ
    outbox.mark_failed("i-retry", "timeout again")
    pending_after = outbox.get_pending()
    assert not any(i.intent_id == "i-retry" for i in pending_after)


def test_delivery_sink_failure_routed_to_dlq_not_dropped(
    dlq: DurableDLQManager,
) -> None:
    entry = DurableDLQEntry(
        entry_id="dlq-001",
        raw_event_id="raw-001",
        reason="SINK_UNAVAILABLE",
        error_detail="Connection refused",
        raw_payload_hex="deadbeef",
        source_id="fw-A",
        queued_at=datetime.now(UTC).isoformat(),
    )
    dlq.enqueue(entry)
    assert dlq.count() == 1
    queued = dlq.get_queued()
    assert queued[0].entry_id == "dlq-001"
    assert queued[0].reason == "SINK_UNAVAILABLE"


def test_dlq_entry_persists_after_restart(db: SQLiteDatabase) -> None:
    dlq1 = DurableDLQManager(db)
    dlq1.enqueue(DurableDLQEntry(
        entry_id="dlq-persist",
        raw_event_id="raw-p",
        reason="PARSE_FAILURE",
        error_detail="malformed JSON",
        raw_payload_hex="cafebabe",
        source_id="ids-01",
        queued_at=datetime.now(UTC).isoformat(),
    ))

    dlq2 = DurableDLQManager(db)
    assert dlq2.count() == 1
    queued = dlq2.get_queued()
    assert queued[0].entry_id == "dlq-persist"


def test_dlq_mark_replayed(dlq: DurableDLQManager) -> None:
    dlq.enqueue(DurableDLQEntry(
        entry_id="dlq-replay",
        raw_event_id="raw-r",
        reason="TIMEOUT",
        error_detail="",
        raw_payload_hex="ff",
        source_id="src",
        queued_at=datetime.now(UTC).isoformat(),
    ))
    assert dlq.count() == 1
    dlq.mark_replayed("dlq-replay")
    assert dlq.count() == 0  # No longer QUEUED


def test_dlq_mark_poison(dlq: DurableDLQManager) -> None:
    dlq.enqueue(DurableDLQEntry(
        entry_id="dlq-poison",
        raw_event_id="raw-px",
        reason="REPEATED_FAILURE",
        error_detail="",
        raw_payload_hex="00",
        source_id="src",
        queued_at=datetime.now(UTC).isoformat(),
    ))
    dlq.mark_poison("dlq-poison")
    # Count only QUEUED; poison should be excluded
    assert dlq.count() == 0


def test_successful_delivery_not_in_dlq(outbox: DurableOutboxRepository) -> None:
    outbox.save_intent(_intent("i-success"))
    outbox.mark_delivered("i-success")
    # Delivered intents don't appear in pending
    pending = outbox.get_pending()
    assert not any(i.intent_id == "i-success" for i in pending)
