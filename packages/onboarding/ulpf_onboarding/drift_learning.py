"""ULPF Phase 14 — Continuous Schema Drift Learning & History Tracking.

Fulfills Phase 14 Workstream P:
- Maintains source schema history over time
- Tracks field appearance trends, type evolutions, and drift frequency
- Recommends mapping/parser updates to the human operator
- CRITICAL INVARIANT: Never self-modifies production schema or mappings silently.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any


@dataclass
class FieldTrend:
    """Historical behavior of a specific field within a source."""

    field_path: str
    first_seen: str
    last_seen: str
    observed_count: int = 0
    data_types_seen: set[str] = field(default_factory=set)
    is_newly_discovered: bool = False


@dataclass
class DriftLearningReport:
    """Actionable recommendations derived from accumulated drift patterns."""

    source_id: str
    total_drift_events: int
    new_fields_detected: list[str]
    type_mutations_detected: list[dict[str, Any]]
    drift_frequency_hourly: float
    recommended_action: str
    reasoning: str
    timestamp: str


class ContinuousDriftLearner:
    """Tracks continuous schema evolution across ingestion cycles."""

    def __init__(self) -> None:
        # source_id -> field_path -> FieldTrend
        self._schema_history: dict[str, dict[str, FieldTrend]] = defaultdict(dict)
        # source_id -> list of drift timestamps
        self._drift_timestamps: dict[str, list[float]] = defaultdict(list)

    def observe_record(self, source_id: str, fields: dict[str, Any]) -> list[str]:
        """Record field presence and types. Returns list of newly discovered fields."""
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        new_fields = []
        source_fields = self._schema_history[source_id]

        for k, v in fields.items():
            t_name = type(v).__name__
            if k not in source_fields:
                source_fields[k] = FieldTrend(
                    field_path=k,
                    first_seen=now_iso,
                    last_seen=now_iso,
                    observed_count=1,
                    data_types_seen={t_name},
                    is_newly_discovered=True,
                )
                new_fields.append(k)
            else:
                trend = source_fields[k]
                trend.last_seen = now_iso
                trend.observed_count += 1
                trend.data_types_seen.add(t_name)

        if new_fields:
            self._drift_timestamps[source_id].append(time.time())

        return new_fields

    def generate_recommendations(self, source_id: str) -> DriftLearningReport:
        """Analyze accumulated drift trends and generate operator recommendations."""
        source_fields = self._schema_history.get(source_id, {})
        timestamps = self._drift_timestamps.get(source_id, [])
        now = time.time()
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # Hourly drift frequency over the last 24h
        recent = [t for t in timestamps if now - t <= 86400.0]
        freq_hourly = round(len(recent) / 24.0, 2)

        new_fields = [f.field_path for f in source_fields.values() if f.is_newly_discovered]
        type_mutations = []
        for f in source_fields.values():
            if len(f.data_types_seen) > 1:
                type_mutations.append({
                    "field": f.field_path,
                    "types": list(f.data_types_seen),
                })

        # Governance logic for recommendation
        if len(type_mutations) > 0:
            rec = "RECOMMEND_PARSER_UPGRADE"
            reason = f"Type mutations detected in {len(type_mutations)} fields; potential breaking upstream change"
        elif len(new_fields) >= 3 or freq_hourly > 2.0:
            rec = "RECOMMEND_MAPPING_UPDATE"
            reason = f"{len(new_fields)} new fields observed frequently; suggest updating UCE semantic mapping"
        elif len(new_fields) > 0:
            rec = "MONITOR_SOURCE"
            reason = f"{len(new_fields)} new fields observed, under frequency threshold"
        else:
            rec = "SCHEMA_STABLE"
            reason = "No drift anomalies observed"

        return DriftLearningReport(
            source_id=source_id,
            total_drift_events=len(timestamps),
            new_fields_detected=new_fields,
            type_mutations_detected=type_mutations,
            drift_frequency_hourly=freq_hourly,
            recommended_action=rec,
            reasoning=reason,
            timestamp=now_iso,
        )
