"""Intelligent Fingerprint Alert Deduplication Engine for ULPF Phase 9."""

from __future__ import annotations

import hashlib
import threading
import uuid
from datetime import UTC, datetime

from ulpf_advanced_intelligence.models.alerts import (
    AlertLifecycleStatus,
    AlertRecord,
    AlertTriageSeverity,
    DedupGroup,
)
from ulpf_intelligence.models.events import DetectionEvent


class AlertDeduplicator:
    """Groups repetitive detections into stable deduplication groups under a primary alert."""

    def __init__(self) -> None:
        # fingerprint -> DedupGroup
        self._groups: dict[str, DedupGroup] = {}
        # primary_alert_id -> AlertRecord
        self._primary_alerts: dict[str, AlertRecord] = {}
        self._lock = threading.Lock()

    def process_detection(
        self,
        detection: DetectionEvent,
        risk_score: float = 50.0,
        severity: AlertTriageSeverity = AlertTriageSeverity.MEDIUM,
    ) -> tuple[AlertRecord, DedupGroup, bool]:
        """Ingest a detection, return (primary_alert, dedup_group, is_new_alert)."""
        entity = detection.entity_ids[0] if detection.entity_ids else "unknown"
        fingerprint = self.compute_fingerprint(entity, detection.rule_id, detection.tenant_id)
        now_iso = datetime.now(UTC).isoformat()

        with self._lock:
            if fingerprint in self._groups:
                group = self._groups[fingerprint]
                updated_group = DedupGroup(
                    group_id=group.group_id,
                    fingerprint=fingerprint,
                    primary_alert_id=group.primary_alert_id,
                    member_detection_ids=group.member_detection_ids + (detection.detection_id,),
                    count=group.count + 1,
                    first_seen=group.first_seen,
                    last_seen=now_iso,
                    tenant_id=detection.tenant_id,
                )
                self._groups[fingerprint] = updated_group
                primary_alert = self._primary_alerts[group.primary_alert_id]
                return primary_alert, updated_group, False
            else:
                alert_id = f"alert-{uuid.uuid4().hex[:10]}"
                group_id = f"dedup-{uuid.uuid4().hex[:10]}"

                new_alert = AlertRecord(
                    alert_id=alert_id,
                    title=f"[Alert] {detection.title}",
                    description=f"{detection.description} on {entity}",
                    severity=severity,
                    status=AlertLifecycleStatus.NEW,
                    tenant_id=detection.tenant_id,
                    primary_entity_id=entity,
                    entity_ids=(entity,),
                    detection_ids=(detection.detection_id,),
                    risk_score=risk_score,
                    fingerprint=fingerprint,
                    created_at=now_iso,
                    updated_at=now_iso,
                    contributing_factors=(f"INITIAL_DETECTION:{detection.rule_id}",),
                )
                new_group = DedupGroup(
                    group_id=group_id,
                    fingerprint=fingerprint,
                    primary_alert_id=alert_id,
                    member_detection_ids=(detection.detection_id,),
                    count=1,
                    first_seen=now_iso,
                    last_seen=now_iso,
                    tenant_id=detection.tenant_id,
                )
                self._primary_alerts[alert_id] = new_alert
                self._groups[fingerprint] = new_group
                return new_alert, new_group, True

    @staticmethod
    def compute_fingerprint(entity: str, rule_id: str, tenant_id: str | None) -> str:
        basis = f"{entity}:{rule_id}:{tenant_id}"
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]

    def get_group(self, fingerprint: str) -> DedupGroup | None:
        with self._lock:
            return self._groups.get(fingerprint)
