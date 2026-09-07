"""Multi-Event Correlation Engine for ULPF Phase 8."""

from __future__ import annotations

import threading
import time
import uuid
from datetime import UTC, datetime

from ulpf_intelligence.models.events import CorrelationGroup, DetectionEvent
from ulpf_intelligence.models.provenance import AlertSeverity


class CorrelationEngine:
    """Correlates multiple detections across temporal windows and common entities."""

    def __init__(
        self,
        window_seconds: int = 300,
        default_window_seconds: int | None = None,
    ) -> None:
        self.default_window_seconds = default_window_seconds or window_seconds
        # group_key -> CorrelationGroup (persistent group, updated in-place)
        self._groups: dict[str, CorrelationGroup] = {}
        # group_key -> list of (timestamp_epoch, DetectionEvent)
        self._events: dict[str, list[tuple[float, DetectionEvent]]] = {}
        self._lock = threading.Lock()

    def _primary_entity(self, detection: DetectionEvent) -> str | None:
        ids = detection.entity_ids or detection.entities
        return ids[0] if ids else None

    def ingest_detection(
        self,
        detection: DetectionEvent,
        source_id: str = "perimeter",
    ) -> CorrelationGroup:
        """Ingest a detection and return the updated or new correlation group.

        Groups are keyed by the primary entity of the detection. The group is
        returned immediately (even for the first detection), and is updated as
        more detections arrive.
        """
        now_epoch = time.time()
        now_iso = datetime.now(UTC).isoformat()
        entity = self._primary_entity(detection) or source_id

        with self._lock:
            group_key = f"entity:{entity}"
            cutoff = now_epoch - self.default_window_seconds

            # Maintain sliding-window event list
            items = self._events.setdefault(group_key, [])
            items = [it for it in items if it[0] > cutoff]
            items.append((now_epoch, detection))
            self._events[group_key] = items

            # Collect all distinct detections in the window
            unique: dict[str, DetectionEvent] = {it[1].detection_id: it[1] for it in items}
            det_list = list(unique.values())

            # Aggregate severity
            severities = [d.severity for d in det_list]
            highest_sev = AlertSeverity.LOW
            if AlertSeverity.CRITICAL in severities:
                highest_sev = AlertSeverity.CRITICAL
            elif AlertSeverity.HIGH in severities:
                highest_sev = AlertSeverity.HIGH
            elif AlertSeverity.MEDIUM in severities:
                highest_sev = AlertSeverity.MEDIUM

            # Normalised 0-1 aggregated risk
            n = len(det_list)
            severity_weights = {
                AlertSeverity.CRITICAL: 1.0,
                AlertSeverity.HIGH: 0.8,
                AlertSeverity.MEDIUM: 0.5,
                AlertSeverity.LOW: 0.2,
                AlertSeverity.INFORMATIONAL: 0.1,
            }
            max_w = max(severity_weights.get(d.severity, 0.5) for d in det_list)
            avg_w = sum(severity_weights.get(d.severity, 0.5) for d in det_list) / n
            agg_risk = round(min(1.0, max_w + avg_w * 0.2 * (n - 1)), 4)

            existing = self._groups.get(group_key)
            group_id = existing.group_id if existing else f"corr-{uuid.uuid4().hex[:12]}"

            group = CorrelationGroup(
                group_id=group_id,
                correlation_id=group_id,
                correlation_key=group_key,
                title=f"Correlated activity on {entity}",
                dimension="entity",
                dimension_value=entity,
                window_start=datetime.fromtimestamp(items[0][0], UTC).isoformat(),
                window_end=now_iso,
                event_ids=tuple(
                    sorted({
                        ev_id
                        for d in det_list
                        for ev_id in (
                            d.evidence.matched_event_ids
                            if hasattr(d.evidence, "matched_event_ids")
                            else ()
                        )
                    })
                ),
                detection_ids=tuple(d.detection_id for d in det_list),
                severity=highest_sev,
                confidence=round(min(1.0, 0.6 + n * 0.1), 4),
                aggregated_risk=agg_risk,
                primary_entity_id=entity,
                status="ACTIVE",
                tenant_id=detection.tenant_id,
                metadata={"detection_count": n},
            )
            self._groups[group_key] = group
        return group

    def get_active_groups(self, tenant_id: str | None = None) -> list[CorrelationGroup]:
        """Return currently active correlation groups (optionally filtered by tenant)."""
        with self._lock:
            groups = list(self._groups.values())
        if tenant_id is not None:
            groups = [g for g in groups if g.tenant_id is None or g.tenant_id == tenant_id]
        return groups
