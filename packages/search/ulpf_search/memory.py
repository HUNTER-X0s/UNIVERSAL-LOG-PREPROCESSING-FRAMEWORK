"""In-memory structured search and analytics index implementation for ULPF Phase 6.

Enforces:
- Rule 15/16: Offline, air-gapped test and development support
- Rule 101: Bounded query limits and pagination
- Rule 111/112: Rebuild index safely from canonical SemanticEvent records
"""

import threading
import time
from typing import Any

from ulpf_runtime.errors import QueryValidationError
from ulpf_storage.interfaces import StoredSemanticEvent

from ulpf_search.interfaces import SearchIndexAdapter, SearchQuery, SearchResult


class MemorySearchIndex(SearchIndexAdapter):
    """In-memory inverted index indexing structured semantic fields."""

    def __init__(self, max_indexed_events: int = 50_000) -> None:
        self.max_indexed_events = max_indexed_events
        self._events: dict[str, dict[str, Any]] = {}
        self._order: list[str] = []
        self._lock = threading.RLock()

    def _extract_indexed_doc(self, event: StoredSemanticEvent) -> dict[str, Any]:
        """Extract structured indexed fields to prevent field explosion."""
        p = event.payload
        classification = event.classification or {}
        return {
            "semantic_event_id": event.semantic_event_id,
            "uce_event_id": event.uce_event_id,
            "raw_sha256": event.raw_sha256,
            "fingerprint": event.fingerprint,
            "risk_level": event.risk_level,
            "risk_score": event.risk_score,
            "vendor": classification.get("vendor"),
            "product": classification.get("product"),
            "event_type": classification.get("event_type"),
            "severity": classification.get("severity"),
            "action": p.get("action", {}).get("name")
            if isinstance(p.get("action"), dict)
            else None,
            "result": p.get("result", {}).get("status")
            if isinstance(p.get("result"), dict)
            else None,
            "entities": [e.get("value") for e in event.entities if isinstance(e, dict)],
            "indicators": [i.get("value") for i in event.indicators if isinstance(i, dict)],
            "stored_at": event.stored_at,
        }

    def index_event(self, event: StoredSemanticEvent) -> None:
        with self._lock:
            doc = self._extract_indexed_doc(event)
            eid = event.semantic_event_id

            if (
                eid not in self._events
                and len(self._events) >= self.max_indexed_events
                and self._order
            ):
                oldest_id = self._order.pop(0)
                self._events.pop(oldest_id, None)

            self._events[eid] = doc
            if eid not in self._order:
                self._order.append(eid)

    def search(self, query: SearchQuery) -> SearchResult:
        start_time = time.perf_counter()

        # Bounded query safety
        if query.limit > 1000:
            raise QueryValidationError("Query limit exceeds maximum allowed of 1000")
        if query.offset < 0:
            raise QueryValidationError("Query offset cannot be negative")

        with self._lock:
            matched: list[dict[str, Any]] = []

            for eid in reversed(self._order):  # Newest first
                doc = self._events[eid]

                if query.vendor and doc.get("vendor") != query.vendor:
                    continue
                if query.product and doc.get("product") != query.product:
                    continue
                if query.event_type and doc.get("event_type") != query.event_type:
                    continue
                if query.severity and doc.get("severity") != query.severity:
                    continue
                if query.action and doc.get("action") != query.action:
                    continue
                if query.result and doc.get("result") != query.result:
                    continue
                if query.risk_level and doc.get("risk_level") != query.risk_level:
                    continue
                if query.fingerprint and doc.get("fingerprint") != query.fingerprint:
                    continue
                if query.entity_value and query.entity_value not in doc.get("entities", []):
                    continue
                if query.indicator_value and query.indicator_value not in doc.get("indicators", []):
                    continue

                matched.append(doc)

            total = len(matched)
            page = matched[query.offset : query.offset + query.limit]
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

            return SearchResult(
                total_matches=total,
                returned_count=len(page),
                offset=query.offset,
                events=page,
                execution_time_ms=elapsed_ms,
            )

    def rebuild_index(self, events: list[StoredSemanticEvent]) -> int:
        with self._lock:
            self._events.clear()
            self._order.clear()
            count = 0
            for ev in events:
                self.index_event(ev)
                count += 1
            return count

    def count(self) -> int:
        with self._lock:
            return len(self._events)
