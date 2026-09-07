"""Structured Threat Hunting Query Engine for ULPF Phase 8."""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime
from typing import Any

from ulpf_intelligence.errors import QueryResourceLimitExceededError
from ulpf_intelligence.models.events import ThreatHuntQuery, ThreatHuntResult


class ThreatHuntingEngine:
    """Executes safe, parameterized, resource-bounded threat hunting queries."""

    MAX_LIMIT = 500
    MAX_TIME_WINDOW_HOURS = 168  # 7 days max window

    def __init__(self) -> None:
        pass

    def create_query(
        self,
        user_id: str,
        field: str,
        operator: Any,
        value: Any,
        start_time: str,
        end_time: str,
        limit: int = 100,
        tenant_id: str | None = None,
    ) -> ThreatHuntQuery:
        """Create and validate a parameterized threat hunt query."""
        q = ThreatHuntQuery(
            query_id=f"hunt-{uuid.uuid4().hex[:12]}",
            time_start=start_time,
            time_end=end_time,
            filters={field: value},
            limit=limit,
            tenant_id=tenant_id,
        )
        self.validate_query(q)
        return q

    def execute_query(
        self,
        query: ThreatHuntQuery,
        candidate_records: list[dict[str, Any]],
    ) -> ThreatHuntResult:
        """Execute query across candidate records."""
        return self.execute_hunt(query, candidate_records)

    def validate_query(self, query: ThreatHuntQuery) -> None:
        """Enforce strict bounding limits on hunting queries to prevent resource exhaustion."""
        if query.limit > self.MAX_LIMIT:
            raise QueryResourceLimitExceededError(
                f"Query limit exceeds maximum allowable {self.MAX_LIMIT} (requested {query.limit})"
            )

        try:
            t0 = datetime.fromisoformat(query.time_start)
            t1 = datetime.fromisoformat(query.time_end)
            diff_hours = (t1 - t0).total_seconds() / 3600.0
            if diff_hours > self.MAX_TIME_WINDOW_HOURS:
                raise QueryResourceLimitExceededError(
                    f"Time window exceeds maximum allowed {self.MAX_TIME_WINDOW_HOURS} hours"
                )
        except (ValueError, TypeError) as exc:
            if isinstance(exc, QueryResourceLimitExceededError):
                raise
            # If date format invalid, continue with basic validation

    def execute_hunt(
        self,
        query: ThreatHuntQuery,
        events: list[dict[str, Any]],
    ) -> ThreatHuntResult:
        """Deterministically search across provided events matching query criteria."""
        self.validate_query(query)
        t_start = time.perf_counter()

        matched_event_ids: list[str] = []
        matched_records: list[dict[str, Any]] = []
        matched_entities: set[str] = set()

        for ev in events:
            # Check tenant isolation
            if query.tenant_id and ev.get("tenant_id") and ev.get("tenant_id") != query.tenant_id:
                continue

            # Check time range
            ev_time = ev.get("captured_at") or ev.get("timestamp") or ""
            if query.time_start and ev_time < query.time_start:
                continue
            if query.time_end and ev_time > query.time_end:
                continue

            # Check entity filters
            if query.entity_ids:
                ev_entities = [str(ev.get(k)) for k in ("src_ip", "dst_ip", "user", "host") if ev.get(k)]
                if not any(target in ev_entities for target in query.entity_ids):
                    continue

            # Check custom field filters
            matched_filters = True
            for f_key, f_val in query.filters.items():
                if str(ev.get(f_key, "")).lower() != str(f_val).lower():
                    matched_filters = False
                    break
            if not matched_filters:
                continue

            # Matched!
            ev_id = str(ev.get("raw_event_id") or ev.get("uce_event_id") or ev.get("id", "unknown"))
            matched_event_ids.append(ev_id)
            matched_records.append(ev)
            for k in ("src_ip", "dst_ip", "user", "host"):
                if ev.get(k):
                    matched_entities.add(f"{k}:{ev[k]}")

        duration = time.perf_counter() - t_start
        total = len(matched_event_ids)

        # Apply pagination
        paginated_ids = matched_event_ids[query.offset : query.offset + query.limit]
        paginated_records = matched_records[query.offset : query.offset + query.limit]

        return ThreatHuntResult(
            query_id=query.query_id,
            total_matches=total,
            matched_event_ids=tuple(paginated_ids),
            matched_entities=tuple(sorted(matched_entities)),
            execution_duration_sec=round(duration, 4),
            executed_at=datetime.now(UTC).isoformat(),
            matched_records=tuple(paginated_records),
        )
