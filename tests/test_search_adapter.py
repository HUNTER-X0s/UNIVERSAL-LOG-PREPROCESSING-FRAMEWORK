"""Tests for ULPF Phase 6 search and analytics adapter."""

import unittest

from ulpf_runtime.errors import QueryValidationError
from ulpf_search.interfaces import SearchQuery
from ulpf_search.memory import MemorySearchIndex
from ulpf_storage.interfaces import StoredSemanticEvent


class TestSearchAdapter(unittest.TestCase):
    def setUp(self) -> None:
        self.search_index = MemorySearchIndex(max_indexed_events=100)
        self.sample_event = StoredSemanticEvent(
            semantic_event_id="sem-100",
            uce_event_id="uce-100",
            raw_sha256="sha-100",
            mapping_version="v1.0.0",
            semantic_version="1.0.0",
            payload={
                "action": {"name": "DENY"},
                "result": {"status": "SUCCESS"},
            },
            fingerprint="fp-100",
            risk_level="CRITICAL",
            risk_score=95.0,
            entities=[{"type": "IP", "value": "10.0.0.1"}],
            indicators=[{"type": "DOMAIN", "value": "malicious.com"}],
            classification={"vendor": "Fortinet", "product": "FortiGate", "event_type": "FIREWALL", "severity": "HIGH"},
        )
        self.search_index.index_event(self.sample_event)

    def test_structured_search_matching(self) -> None:
        # Search by vendor
        q1 = SearchQuery(vendor="Fortinet")
        res1 = self.search_index.search(q1)
        self.assertEqual(res1.total_matches, 1)
        self.assertEqual(res1.events[0]["semantic_event_id"], "sem-100")

        # Search by non-existent vendor
        q2 = SearchQuery(vendor="NonExistent")
        res2 = self.search_index.search(q2)
        self.assertEqual(res2.total_matches, 0)

        # Search by entity value
        q3 = SearchQuery(entity_value="10.0.0.1")
        res3 = self.search_index.search(q3)
        self.assertEqual(res3.total_matches, 1)

    def test_query_safety_limits(self) -> None:
        # Query exceeding limit
        with self.assertRaises(QueryValidationError):
            self.search_index.search(SearchQuery(limit=5000))

        # Query with negative offset
        with self.assertRaises(QueryValidationError):
            self.search_index.search(SearchQuery(offset=-1))

    def test_rebuild_index(self) -> None:
        self.assertEqual(self.search_index.count(), 1)
        # Rebuild from empty list
        self.search_index.rebuild_index([])
        self.assertEqual(self.search_index.count(), 0)

        # Rebuild from sample
        rebuilt = self.search_index.rebuild_index([self.sample_event])
        self.assertEqual(rebuilt, 1)
        self.assertEqual(self.search_index.count(), 1)


if __name__ == "__main__":
    unittest.main()
