"""Investigation Timeline Builder for ULPF Phase 8."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from ulpf_intelligence.models.events import DetectionEvent, TimelineEntry
from ulpf_intelligence.models.provenance import AlertSeverity, IntelligenceProvenance


class TimelineBuilder:
    """Builds unified, chronological incident timelines from events and detections."""

    def __init__(self) -> None:
        self._entries: list[TimelineEntry] = []

    def add_event(
        self,
        timestamp: str,
        event_type: str,
        source_id: str,
        summary: str,
        details: dict[str, Any] | None = None,
    ) -> TimelineEntry:
        """Add an event to the builder timeline."""
        entry = TimelineEntry(
            entry_id=f"tl-{uuid.uuid4().hex[:8]}",
            timestamp=timestamp,
            event_type=event_type,
            description=summary,
            summary=summary,
            source_id=source_id,
            source_event_id=source_id,
            details=details or {},
        )
        self._entries.append(entry)
        return entry

    def build(self) -> list[TimelineEntry]:
        """Return sorted entries in chronological order."""
        return sorted(self._entries, key=lambda x: x.timestamp)

    @staticmethod
    def build_timeline(
        events: list[dict[str, Any]],
        detections: list[DetectionEvent] | None = None,
    ) -> list[TimelineEntry]:
        """Aggregate, sort, and normalize event and detection streams into a chronological timeline."""
        entries: list[TimelineEntry] = []

        # 1. Ingest raw/canonical events
        for ev in events:
            eid = str(ev.get("raw_event_id") or ev.get("uce_event_id") or ev.get("id", "unknown"))
            ts = str(ev.get("captured_at") or ev.get("timestamp") or datetime.now(UTC).isoformat())
            act = str(ev.get("action", "EVENT"))
            src = str(ev.get("src_ip", ""))
            dst = str(ev.get("dst_ip", ""))
            desc = f"{act} from {src} to {dst}" if src and dst else f"Telemetry event ({act})"

            entities: list[str] = []
            for k in ("src_ip", "dst_ip", "user", "host"):
                if ev.get(k):
                    entities.append(f"{k}:{ev[k]}")

            entries.append(
                TimelineEntry(
                    entry_id=f"tl-{uuid.uuid4().hex[:8]}",
                    timestamp=ts,
                    event_type=act,
                    description=desc,
                    severity=AlertSeverity.INFORMATIONAL,
                    associated_entity_ids=tuple(entities),
                    source_event_id=eid,
                    timestamp_confidence=1.0 if ev.get("captured_at") else 0.8,
                    provenance=IntelligenceProvenance.OBSERVED,
                )
            )

        # 2. Ingest detections
        if detections:
            for det in detections:
                entries.append(
                    TimelineEntry(
                        entry_id=f"tl-det-{uuid.uuid4().hex[:8]}",
                        timestamp=det.created_at,
                        event_type=f"ALERT:{det.title}",
                        description=f"Detection: {det.description} (Risk: {det.risk_score})",
                        severity=det.severity,
                        associated_entity_ids=det.entities,
                        detection_id=det.detection_id,
                        timestamp_confidence=1.0,
                        provenance=IntelligenceProvenance.DETECTED,
                    )
                )

        # 3. Sort deterministically by timestamp ascending
        return sorted(entries, key=lambda x: (x.timestamp, x.entry_id))
