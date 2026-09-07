"""Phase 7 Test: Durable Idempotency Guard.

Verifies:
- Rule 12: Fingerprint deduplication is crash-safe (backed by UNIQUE constraint)
- Duplicate fingerprints raise DuplicateEventError
- count() reflects registered keys
- Survives simulated restart (new repo instance on same DB)
"""

import pytest
from ulpf_storage.database.relational import SQLiteDatabase
from ulpf_storage.durable_idempotency import DuplicateEventError, DurableIdempotencyGuard


@pytest.fixture()
def db() -> SQLiteDatabase:
    return SQLiteDatabase(":memory:")


@pytest.fixture()
def guard(db: SQLiteDatabase) -> DurableIdempotencyGuard:
    return DurableIdempotencyGuard(db)


def test_new_fingerprint_accepted(guard: DurableIdempotencyGuard) -> None:
    result = guard.check_and_register("fp-unique-001", "event-001")
    assert result is True


def test_duplicate_fingerprint_rejected(guard: DurableIdempotencyGuard) -> None:
    guard.check_and_register("fp-dup", "event-A")
    with pytest.raises(DuplicateEventError, match="Duplicate fingerprint"):
        guard.check_and_register("fp-dup", "event-B")


def test_is_known_before_and_after(guard: DurableIdempotencyGuard) -> None:
    assert not guard.is_known("fp-new")
    guard.check_and_register("fp-new", "event-X")
    assert guard.is_known("fp-new")


def test_count_increments(guard: DurableIdempotencyGuard) -> None:
    assert guard.count() == 0
    guard.check_and_register("fp-1", "ev-1")
    guard.check_and_register("fp-2", "ev-2")
    assert guard.count() == 2


def test_different_fingerprints_all_accepted(guard: DurableIdempotencyGuard) -> None:
    for i in range(20):
        result = guard.check_and_register(f"fp-{i}", f"ev-{i}")
        assert result is True
    assert guard.count() == 20


def test_survives_simulated_restart(db: SQLiteDatabase) -> None:
    """After re-instantiating guard on same DB, fingerprints are still known."""
    guard1 = DurableIdempotencyGuard(db)
    guard1.check_and_register("fp-persistent", "ev-persistent")

    # Simulate restart: new guard instance on same DB
    guard2 = DurableIdempotencyGuard(db)
    assert guard2.is_known("fp-persistent")
    with pytest.raises(DuplicateEventError):
        guard2.check_and_register("fp-persistent", "ev-new")
