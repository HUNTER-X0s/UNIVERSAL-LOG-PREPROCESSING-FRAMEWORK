"""Phase 7 Test: Durable Outbox Repository.

Verifies:
- Rule B5: Outbox survives process restart (SQLite-backed)
- Rule 10: Delivery intents never silently lost
- Atomic status transitions: PENDING → DELIVERED / DLQ
"""

import pytest
from ulpf_runtime.models import DeliveryIntent
from ulpf_storage.database.relational import SQLiteDatabase
from ulpf_storage.durable_outbox import DurableOutboxRepository


@pytest.fixture()
def db() -> SQLiteDatabase:
    return SQLiteDatabase(":memory:")


@pytest.fixture()
def repo(db: SQLiteDatabase) -> DurableOutboxRepository:
    return DurableOutboxRepository(db)


def _make_intent(
    intent_id: str = "intent-001",
    event_id: str = "ev-001",
    sink: str = "ocsf-siem",
    max_attempts: int = 3,
) -> DeliveryIntent:
    from datetime import UTC, datetime
    return DeliveryIntent(
        intent_id=intent_id,
        event_id=event_id,
        sink_name=sink,
        payload_type="ocsf_v1",
        payload={"event": "login_failed"},
        created_at=datetime.now(UTC).isoformat(),
        attempt_count=0,
        max_attempts=max_attempts,
        status="PENDING",
    )


def test_save_and_get_pending(repo: DurableOutboxRepository) -> None:
    repo.save_intent(_make_intent("i-001"))
    repo.save_intent(_make_intent("i-002"))
    pending = repo.get_pending()
    assert len(pending) == 2
    ids = {i.intent_id for i in pending}
    assert ids == {"i-001", "i-002"}


def test_mark_delivered_removes_from_pending(repo: DurableOutboxRepository) -> None:
    repo.save_intent(_make_intent("i-del"))
    repo.mark_delivered("i-del")
    pending = repo.get_pending()
    assert not any(i.intent_id == "i-del" for i in pending)


def test_mark_failed_increments_attempts(repo: DurableOutboxRepository) -> None:
    repo.save_intent(_make_intent("i-fail", max_attempts=3))
    repo.mark_failed("i-fail", "Connection refused")
    # Still PENDING after 1 failure (max_attempts=3)
    pending = repo.get_pending()
    assert any(i.intent_id == "i-fail" for i in pending)


def test_mark_failed_to_dlq_on_max_attempts(repo: DurableOutboxRepository) -> None:
    repo.save_intent(_make_intent("i-dlq", max_attempts=1))
    repo.mark_failed("i-dlq", "Fatal error")
    # After 1 failure with max_attempts=1, should be DLQ
    pending = repo.get_pending()
    assert not any(i.intent_id == "i-dlq" for i in pending)


def test_save_intent_idempotent_on_same_id(repo: DurableOutboxRepository) -> None:
    """Duplicate save_intent with same ID is silently ignored (INSERT OR IGNORE)."""
    repo.save_intent(_make_intent("i-idem"))
    repo.save_intent(_make_intent("i-idem"))  # Should not raise
    pending = repo.get_pending()
    assert sum(1 for i in pending if i.intent_id == "i-idem") == 1


def test_survives_restart(db: SQLiteDatabase) -> None:
    repo1 = DurableOutboxRepository(db)
    repo1.save_intent(_make_intent("i-persist"))

    # Simulated restart: new repo on same DB
    repo2 = DurableOutboxRepository(db)
    pending = repo2.get_pending()
    assert any(i.intent_id == "i-persist" for i in pending)


def test_get_pending_limit(repo: DurableOutboxRepository) -> None:
    for j in range(10):
        repo.save_intent(_make_intent(f"i-{j:03d}"))
    limited = repo.get_pending(limit=3)
    assert len(limited) == 3
