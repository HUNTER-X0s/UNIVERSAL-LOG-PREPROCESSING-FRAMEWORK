"""Search and analytics indexing interfaces for ULPF Phase 6.

Enforces:
- Rule 13/14: Pluggable adapter boundary for search engines (OpenSearch/Elastic-compatible)
- Rule 66/101: Query safety, bounded result sets, indexed structured fields
- Rule 111/112: Derived index; rebuild capability from canonical store
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ulpf_storage.interfaces import StoredSemanticEvent


@dataclass(frozen=True)
class SearchQuery:
    """Structured, safe search query with strict boundaries."""

    time_start: str | None = None
    time_end: str | None = None
    vendor: str | None = None
    product: str | None = None
    event_type: str | None = None
    severity: str | None = None
    action: str | None = None
    result: str | None = None
    risk_level: str | None = None
    fingerprint: str | None = None
    indicator_value: str | None = None
    entity_value: str | None = None
    limit: int = 50
    offset: int = 0


@dataclass(frozen=True)
class SearchResult:
    """Bounded search query results."""

    total_matches: int
    returned_count: int
    offset: int
    events: list[dict[str, Any]]
    execution_time_ms: float = 0.0


class SearchIndexAdapter(ABC):
    """Port for search and analytics index operations."""

    @abstractmethod
    def index_event(self, event: StoredSemanticEvent) -> None:
        """Index high-value structured fields of a semantic event."""
        ...

    @abstractmethod
    def search(self, query: SearchQuery) -> SearchResult:
        """Execute a safe, bounded structured search."""
        ...

    @abstractmethod
    def rebuild_index(self, events: list[StoredSemanticEvent]) -> int:
        """Rebuild index from canonical semantic events for disaster recovery."""
        ...

    @abstractmethod
    def count(self) -> int:
        """Return total indexed event count."""
        ...
