"""Phase 7 Test: Persistent Semantic Event Repository (durable SQLite-backed).

Verifies:
- Rule 4: SemanticEvent persistence with multi-attribute querying
- Rule B3: Parameterized queries
- Filtering by risk_level, fingerprint, vendor (post-filter from JSON)
"""

import pytest
from ulpf_storage.database.relational import SQLiteDatabase
from ulpf_storage.durable_semantic import DurableSemanticEventRepository
from ulpf_storage.interfaces import StoredSemanticEvent


@pytest.fixture()
def db() -> SQLiteDatabase:
    return SQLiteDatabase(":memory:")


@pytest.fixture()
def repo(db: SQLiteDatabase) -> DurableSemanticEventRepository:
    return DurableSemanticEventRepository(db)


def _make_event(
    sem_id: str = "sem-001",
    uce_id: str = "uce-001",
    risk_level: str = "HIGH",
    fingerprint: str = "fp-abc",
    vendor: str = "cisco",
    source_id: str = "fw-A",
) -> StoredSemanticEvent:
    return StoredSemanticEvent(
        semantic_event_id=sem_id,
        uce_event_id=uce_id,
        raw_sha256="abc" * 21 + "ab",
        mapping_version="1.0.0",
        semantic_version="1.0.0",
        payload={"source_id": source_id, "event_type": "connection_denied"},
        fingerprint=fingerprint,
        risk_level=risk_level,
        risk_score=8.5,
        entities=[{"type": "IP_ADDRESS", "value": "10.0.0.1"}],
        indicators=[{"type": "IP_INDICATOR", "value": "10.0.0.1"}],
        classification={"vendor": vendor, "product": "ASA"},
    )


def test_put_and_get(repo: DurableSemanticEventRepository) -> None:
    event = _make_event()
    repo.put(event)
    retrieved = repo.get("sem-001")
    assert retrieved is not None
    assert retrieved.risk_level == "HIGH"
    assert retrieved.risk_score == pytest.approx(8.5)
    assert retrieved.entities[0]["type"] == "IP_ADDRESS"


def test_query_by_risk_level(repo: DurableSemanticEventRepository) -> None:
    repo.put(_make_event("sem-001", risk_level="HIGH"))
    repo.put(_make_event("sem-002", risk_level="LOW"))
    repo.put(_make_event("sem-003", risk_level="HIGH"))

    highs = repo.query(risk_level="HIGH")
    assert len(highs) == 2
    lows = repo.query(risk_level="LOW")
    assert len(lows) == 1


def test_query_by_fingerprint(repo: DurableSemanticEventRepository) -> None:
    repo.put(_make_event("sem-001", fingerprint="fp-unique"))
    repo.put(_make_event("sem-002", fingerprint="fp-other"))

    results = repo.query(fingerprint="fp-unique")
    assert len(results) == 1
    assert results[0].semantic_event_id == "sem-001"


def test_query_by_vendor(repo: DurableSemanticEventRepository) -> None:
    repo.put(_make_event("sem-001", vendor="cisco"))
    repo.put(_make_event("sem-002", vendor="paloalto"))

    cisco = repo.query(vendor="cisco")
    assert len(cisco) == 1
    palo = repo.query(vendor="paloalto")
    assert len(palo) == 1


def test_query_limit_offset(repo: DurableSemanticEventRepository) -> None:
    for i in range(10):
        repo.put(_make_event(f"sem-{i:03d}", risk_level="MEDIUM"))

    page1 = repo.query(limit=5, offset=0)
    page2 = repo.query(limit=5, offset=5)
    assert len(page1) == 5
    assert len(page2) == 5
    ids = {e.semantic_event_id for e in page1} | {e.semantic_event_id for e in page2}
    assert len(ids) == 10


def test_get_nonexistent_returns_none(repo: DurableSemanticEventRepository) -> None:
    assert repo.get("nonexistent") is None


def test_entities_and_indicators_roundtrip(repo: DurableSemanticEventRepository) -> None:
    event = _make_event("sem-001")
    repo.put(event)
    retrieved = repo.get("sem-001")
    assert retrieved is not None
    assert retrieved.entities == event.entities
    assert retrieved.indicators == event.indicators
    assert retrieved.classification == event.classification
