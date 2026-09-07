"""Phase 7 Test: Crash Recovery Verification.

Verifies:
- Rule D6: After crash, UCE records still present in durable store
- Rule D6: Idempotency keys survive crash (no reprocessing duplicates)
- Rule D6: Outbox intents survive crash and remain pending
- Rule D6: DLQ entries survive crash
"""

from datetime import UTC, datetime

import pytest
from ulpf_runtime.models import DeliveryIntent
from ulpf_storage.database.relational import SQLiteDatabase
from ulpf_storage.durable_dlq import DurableDLQEntry, DurableDLQManager
from ulpf_storage.durable_idempotency import DuplicateEventError, DurableIdempotencyGuard
from ulpf_storage.durable_outbox import DurableOutboxRepository
from ulpf_storage.durable_uce import DurableUCERepository
from ulpf_storage.interfaces import UCERecord


@pytest.fixture()
def db() -> SQLiteDatabase:
    """Shared in-memory DB simulating persistent storage."""
    return SQLiteDatabase(":memory:")


def _uce_record(uid: str = "uce-crash-01") -> UCERecord:
    return UCERecord(
        uce_event_id=uid,
        raw_event_id=f"raw-{uid}",
        raw_sha256="a" * 64,
        payload={"action": "DENY", "src_ip": "10.1.0.1"},
        schema_version="1.0.0",
        source_id="fw-crash",
        captured_at=datetime.now(UTC).isoformat(),
    )


def _delivery_intent(iid: str = "intent-crash-01") -> DeliveryIntent:
    return DeliveryIntent(
        intent_id=iid,
        event_id="ev-crash-01",
        sink_name="siem",
        payload_type="ocsf_v1",
        payload={"data": "crash-test"},
        created_at=datetime.now(UTC).isoformat(),
        attempt_count=0,
        max_attempts=3,
        status="PENDING",
    )


def test_uce_records_survive_crash(db: SQLiteDatabase) -> None:
    """UCE records written before crash are available after 'restart' (new repo instance)."""
    repo1 = DurableUCERepository(db)
    repo1.put(_uce_record("uce-pre-crash"))

    # Simulate crash & restart: new repo on same DB
    repo2 = DurableUCERepository(db)
    result = repo2.get("uce-pre-crash")
    assert result is not None
    assert result.source_id == "fw-crash"


def test_idempotency_keys_survive_crash(db: SQLiteDatabase) -> None:
    guard1 = DurableIdempotencyGuard(db)
    guard1.check_and_register("fp-before-crash", "ev-before-crash")

    # After restart
    guard2 = DurableIdempotencyGuard(db)
    # Must recognize the fingerprint as duplicate
    with pytest.raises(DuplicateEventError):
        guard2.check_and_register("fp-before-crash", "ev-new")


def test_outbox_intents_survive_crash(db: SQLiteDatabase) -> None:
    repo1 = DurableOutboxRepository(db)
    repo1.save_intent(_delivery_intent("intent-crash-01"))

    repo2 = DurableOutboxRepository(db)
    pending = repo2.get_pending()
    assert any(i.intent_id == "intent-crash-01" for i in pending)


def test_dlq_entries_survive_crash(db: SQLiteDatabase) -> None:
    dlq1 = DurableDLQManager(db)
    dlq1.enqueue(DurableDLQEntry(
        entry_id="dlq-crash-01",
        raw_event_id="raw-crash",
        reason="PARSE_FAILURE",
        error_detail="bad JSON",
        raw_payload_hex="deadbeef",
        source_id="ids-crash",
        queued_at=datetime.now(UTC).isoformat(),
    ))

    dlq2 = DurableDLQManager(db)
    assert dlq2.count() == 1
    queued = dlq2.get_queued()
    assert queued[0].entry_id == "dlq-crash-01"


def test_multiple_components_survive_crash(db: SQLiteDatabase) -> None:
    """All durable components maintain state across restart."""
    # Write state
    DurableUCERepository(db).put(_uce_record("uce-multi"))
    DurableIdempotencyGuard(db).check_and_register("fp-multi", "ev-multi")
    DurableOutboxRepository(db).save_intent(_delivery_intent("intent-multi"))
    DurableDLQManager(db).enqueue(DurableDLQEntry(
        entry_id="dlq-multi", raw_event_id="raw-m", reason="TIMEOUT",
        error_detail="", raw_payload_hex="ff", source_id="src",
        queued_at=datetime.now(UTC).isoformat(),
    ))

    # Verify all on "restart"
    assert DurableUCERepository(db).get("uce-multi") is not None
    assert DurableIdempotencyGuard(db).is_known("fp-multi")
    pending = DurableOutboxRepository(db).get_pending()
    assert any(i.intent_id == "intent-multi" for i in pending)
    assert DurableDLQManager(db).count() == 1
