"""Phase 7 Test: Phase 0–6 Regression Guard.

Verifies that all Phase 0–6 core invariants still hold after Phase 7 changes.
Exercises representative tests from each phase to catch regressions.
"""

from datetime import UTC, datetime

import pytest

# Phase 5: Mapping models
from ulpf_mapping.models import MappingDefinition, MatchCriteria, SemanticTarget

# Phase 1: Foundation errors and contracts
from ulpf_runtime.errors import PersistenceError, StorageIntegrityError

# Phase 6: Runtime
from ulpf_runtime.idempotency import IdempotencyGuard
from ulpf_semantic.taxonomy.actions import ActionTaxonomy

# Phase 4: Semantic taxonomy (representative sample)
from ulpf_semantic.taxonomy.categories import EventCategory

# Phase 6: Storage - in-memory implementations
from ulpf_storage.interfaces import StoredSemanticEvent, UCERecord
from ulpf_storage.memory import (
    MemorySemanticEventRepository,
    MemoryUCERepository,
)

# ---- Phase 1: Foundation ----

def test_persistence_error_contract_preserved() -> None:
    err = PersistenceError("test persistence error")
    assert isinstance(err, Exception)
    assert "test persistence error" in str(err)


def test_storage_integrity_error_preserved() -> None:
    err = StorageIntegrityError("integrity check failed")
    assert isinstance(err, Exception)


# ---- Phase 3/6: UCE Storage Write-Once Invariant ----

def test_uce_write_once_invariant_preserved() -> None:
    repo = MemoryUCERepository()
    record = UCERecord(
        uce_event_id="reg-uce-001",
        raw_event_id="reg-raw-001",
        raw_sha256="a" * 64,
        payload={"action": "DENY", "src_ip": "10.0.0.1"},
        schema_version="1.0.0",
        source_id="fw-regression",
        captured_at=datetime.now(UTC).isoformat(),
    )
    repo.put(record)
    with pytest.raises(PersistenceError, match="already exists"):
        repo.put(record)


def test_uce_query_by_raw_id_preserved() -> None:
    repo = MemoryUCERepository()
    for i in range(3):
        repo.put(UCERecord(
            uce_event_id=f"uce-{i}",
            raw_event_id="raw-shared",
            raw_sha256="b" * 64,
            payload={},
            schema_version="1.0.0",
            source_id="fw",
            captured_at=datetime.now(UTC).isoformat(),
        ))
    results = repo.query_by_raw_id("raw-shared")
    assert len(results) == 3


# ---- Phase 6: Idempotency Invariant ----

def test_in_memory_idempotency_guard_regression() -> None:
    guard = IdempotencyGuard(max_entries=100)
    key = IdempotencyGuard.generate_key("fw-A", "sha256-abc")
    is_dup, _ = guard.check_and_record(key, "ev-1", "sha256-abc")
    assert is_dup is False
    guard.update_result(key, "sem-1", state="PROCESSED")
    is_dup2, rec = guard.check_and_record(key, "ev-2", "sha256-abc")
    assert is_dup2 is True
    assert rec is not None


def test_idempotency_capacity_eviction_preserved() -> None:
    guard = IdempotencyGuard(max_entries=3)
    for i in range(5):
        k = IdempotencyGuard.generate_key(f"src-{i}", f"sha-{i}")
        guard.check_and_record(k, f"evt-{i}", f"sha-{i}")
    assert guard.size() == 3


# ---- Phase 6: Semantic Event Repository Regression ----

def test_semantic_event_repository_query_regression() -> None:
    repo = MemorySemanticEventRepository()
    event = StoredSemanticEvent(
        semantic_event_id="reg-sem-001",
        uce_event_id="reg-uce-001",
        raw_sha256="c" * 64,
        mapping_version="1.0.0",
        semantic_version="1.0.0",
        payload={"source_id": "fw-A"},
        fingerprint="fp-reg-001",
        risk_level="HIGH",
        risk_score=9.0,
        entities=[],
        indicators=[],
        classification={"vendor": "cisco"},
    )
    repo.put(event)
    results = repo.query(risk_level="HIGH")
    assert len(results) == 1
    assert results[0].semantic_event_id == "reg-sem-001"


# ---- Phase 4: Semantic Taxonomy Regression ----

def test_event_category_taxonomy_preserved() -> None:
    # EventCategory must have at least one member
    members = list(EventCategory)
    assert len(members) > 0


def test_event_action_taxonomy_preserved() -> None:
    members = list(ActionTaxonomy)
    assert len(members) > 0


# ---- Phase 5: Mapping Model Regression ----

def test_mapping_definition_contract_preserved() -> None:
    defn = MappingDefinition(
        mapping_id="reg-map-001",
        version="1.0.0",
        vendor="test-vendor",
        product="test-product",
        match=MatchCriteria(vendor="test-vendor", product="test-product"),
        semantic=SemanticTarget(category="NETWORK", class_name="TRAFFIC", type_name="FLOW"),
    )
    assert defn.mapping_id == "reg-map-001"
    assert defn.vendor == "test-vendor"
