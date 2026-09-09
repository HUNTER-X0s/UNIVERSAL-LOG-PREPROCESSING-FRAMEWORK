"""ULPF Phase 14 — Mission Event Correlation, Campaign Clustering & Early Warning.

Fulfills Phase 14 Workstreams Q, R, V, and W:
- Multi-stage correlation preserving evidence IDs, rule IDs, and time windows
- Campaign clustering by shared infrastructure / behavioral patterns
- Early warning intelligence separating: EARLY_WARNING, DETECTION, CONFIRMED_FINDING
- Security posture trends tracking with explainable deltas
"""

from __future__ import annotations

import collections
import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AlertStage(str, Enum):
    """The 3 explicit escalation stages for security signals."""

    EARLY_WARNING = "EARLY_WARNING"
    DETECTION = "DETECTION"
    CONFIRMED_FINDING = "CONFIRMED_FINDING"


@dataclass(frozen=True)
class CorrelatedEvent:
    """Correlated event bundle linking evidence across multiple sources."""

    correlation_id: str
    rule_id: str
    stage: AlertStage
    title: str
    description: str
    primary_entity: str
    contributing_sources: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    time_window_start: float
    time_window_end: float
    confidence: float
    mitre_techniques: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class CampaignCluster:
    """Group of correlated events forming a broader cyber campaign."""

    campaign_id: str
    campaign_name: str
    shared_indicators: set[str] = field(default_factory=set)
    involved_entities: set[str] = field(default_factory=set)
    event_ids: list[str] = field(default_factory=list)
    mitre_tactics: set[str] = field(default_factory=set)
    first_seen: float = 0.0
    last_seen: float = 0.0
    confidence: float = 0.5


class MultiStageCorrelator:
    """Correlates events across temporal windows and heterogeneous log sources."""

    def __init__(self, time_window_seconds: float = 300.0) -> None:
        self.time_window_seconds = time_window_seconds
        # entity -> list of raw parsed events
        self._sliding_window: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)

    def ingest_event(
        self,
        event_id: str,
        source_id: str,
        entity_id: str,
        timestamp: float,
        action: str,
        raw_evidence_id: str,
        ioc_indicators: list[str] | None = None,
        mitre_technique: str | None = None,
    ) -> list[CorrelatedEvent]:
        """Ingest event and evaluate multi-stage correlation rules."""
        now = timestamp
        bucket = self._sliding_window[entity_id]
        # Prune old events outside time window
        self._sliding_window[entity_id] = [e for e in bucket if (now - e["timestamp"]) <= self.time_window_seconds]
        bucket = self._sliding_window[entity_id]

        new_entry = {
            "event_id": event_id,
            "source_id": source_id,
            "entity_id": entity_id,
            "timestamp": timestamp,
            "action": action,
            "evidence_id": raw_evidence_id,
            "iocs": set(ioc_indicators or []),
            "technique": mitre_technique,
        }
        bucket.append(new_entry)

        correlations: list[CorrelatedEvent] = []

        # Rule 1: Multi-Source Brute Force to Execution (Early Warning -> Detection)
        sources = {e["source_id"] for e in bucket}
        deny_count = sum(1 for e in bucket if e["action"] in ("deny", "failed", "blocked"))
        exec_count = sum(1 for e in bucket if e["action"] in ("exec", "spawn", "login_success"))

        if len(sources) >= 2 and deny_count >= 3 and exec_count >= 1:
            ev_ids = tuple(e["evidence_id"] for e in bucket)
            corr_id = hashlib.sha256(f"CORR:BF_EXEC:{entity_id}:{now}".encode("utf-8")).hexdigest()[:16]
            techs = tuple(set(e["technique"] for e in bucket if e["technique"]))
            correlations.append(
                CorrelatedEvent(
                    correlation_id=corr_id,
                    rule_id="CORR-RULE-101",
                    stage=AlertStage.DETECTION,
                    title=f"Multi-source authentication spray followed by successful execution on {entity_id}",
                    description=f"Observed {deny_count} authentication failures across {len(sources)} sources followed by privileged execution",
                    primary_entity=entity_id,
                    contributing_sources=tuple(sources),
                    evidence_ids=ev_ids,
                    time_window_start=bucket[0]["timestamp"],
                    time_window_end=now,
                    confidence=0.88,
                    mitre_techniques=techs or ("T1110", "T1059"),
                )
            )
        elif deny_count >= 3:
            ev_ids = tuple(e["evidence_id"] for e in bucket)
            corr_id = hashlib.sha256(f"CORR:WARN_SPRAY:{entity_id}:{now}".encode("utf-8")).hexdigest()[:16]
            correlations.append(
                CorrelatedEvent(
                    correlation_id=corr_id,
                    rule_id="CORR-RULE-001",
                    stage=AlertStage.EARLY_WARNING,
                    title=f"Potential authentication burst detected on {entity_id}",
                    description=f"{deny_count} failed auth events detected within window",
                    primary_entity=entity_id,
                    contributing_sources=tuple(sources),
                    evidence_ids=ev_ids,
                    time_window_start=bucket[0]["timestamp"],
                    time_window_end=now,
                    confidence=0.65,
                    mitre_techniques=("T1110",),
                )
            )

        return correlations


class CampaignClusterer:
    """Aggregates correlated events into cohesive campaigns by shared indicators."""

    def __init__(self) -> None:
        self.campaigns: dict[str, CampaignCluster] = {}

    def cluster_event(
        self,
        event: CorrelatedEvent,
        indicators: list[str] | None = None,
    ) -> CampaignCluster:
        ind_set = set(indicators or [])
        # Find existing campaign sharing an indicator or entity
        matched_c = None
        for c in self.campaigns.values():
            if (ind_set and not ind_set.isdisjoint(c.shared_indicators)) or (event.primary_entity in c.involved_entities):
                matched_c = c
                break

        now = time.time()
        if not matched_c:
            cid = hashlib.sha256(f"CAMP:{event.correlation_id}:{now}".encode("utf-8")).hexdigest()[:12]
            matched_c = CampaignCluster(
                campaign_id=cid,
                campaign_name=f"Campaign-{cid}",
                shared_indicators=set(ind_set),
                involved_entities={event.primary_entity},
                event_ids=[event.correlation_id],
                mitre_tactics=set(event.mitre_techniques),
                first_seen=event.time_window_start,
                last_seen=event.time_window_end,
                confidence=event.confidence,
            )
            self.campaigns[cid] = matched_c
        else:
            matched_c.shared_indicators.update(ind_set)
            matched_c.involved_entities.add(event.primary_entity)
            matched_c.event_ids.append(event.correlation_id)
            matched_c.mitre_tactics.update(event.mitre_techniques)
            matched_c.last_seen = max(matched_c.last_seen, event.time_window_end)
            matched_c.confidence = min(0.99, max(matched_c.confidence, event.confidence))

        return matched_c


class SecurityPostureTrendTracker:
    """Maintains time-series security posture snapshots with explainable deltas."""

    def __init__(self) -> None:
        self.snapshots: list[dict[str, Any]] = []

    def record_snapshot(
        self,
        posture_score: float,  # 0 to 100 (100 = optimal security)
        active_threats: int,
        contributing_sources: list[str],
        reason: str,
    ) -> dict[str, Any]:
        prev = self.snapshots[-1] if self.snapshots else None
        delta = round(posture_score - (prev["score"] if prev else posture_score), 1)

        snap = {
            "timestamp": time.time(),
            "iso_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "score": round(posture_score, 1),
            "delta": delta,
            "active_threats": active_threats,
            "contributing_sources": list(contributing_sources),
            "trend": "STABLE" if delta == 0 else ("IMPROVING" if delta > 0 else "DEGRADING"),
            "reason": reason,
        }
        self.snapshots.append(snap)
        return snap
