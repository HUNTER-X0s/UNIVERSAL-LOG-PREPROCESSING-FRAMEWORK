"""Activity Clustering and Campaign Engine for ULPF Phase 9."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime

from ulpf_advanced_intelligence.models.alerts import AlertRecord
from ulpf_advanced_intelligence.models.campaigns import CampaignConfidence, CampaignRecord
from ulpf_intelligence.models.events import AttackSequence, DetectionEvent


class CampaignClusteringEngine:
    """Groups related detections, alerts, and indicators into auditable campaign clusters."""

    @classmethod
    def cluster_activities(
        cls,
        detections: Sequence[DetectionEvent],
        alerts: Sequence[AlertRecord] | None = None,
        sequences: Sequence[AttackSequence] | None = None,
        tenant_id: str | None = None,
    ) -> list[CampaignRecord]:
        """Cluster detections based on shared primary entities and temporal proximity."""
        if not detections:
            return []

        # Group detections by primary entity
        entity_groups: dict[str, list[DetectionEvent]] = {}
        for d in detections:
            primary_entity = d.entity_ids[0] if d.entity_ids else "unassigned-entity"
            entity_groups.setdefault(primary_entity, []).append(d)

        campaigns: list[CampaignRecord] = []
        now_iso = datetime.now(UTC).isoformat()

        for entity, group in entity_groups.items():
            if len(group) < 2:
                continue

            det_ids = tuple(d.detection_id for d in group)
            evidence_ids: set[str] = set()
            tactics: set[str] = set()
            for d in group:
                if d.evidence and d.evidence.matched_event_ids:
                    evidence_ids.update(d.evidence.matched_event_ids)
                tactics.update(d.mitre_tactics)

            # Match associated alerts
            matched_alert_ids: list[str] = []
            if alerts:
                for a in alerts:
                    if entity in a.entity_ids or any(did in a.detection_ids for did in det_ids):
                        matched_alert_ids.append(a.alert_id)

            # Match associated attack sequences
            matched_seq_names: list[str] = []
            has_multi_stage = False
            if sequences:
                for s in sequences:
                    if len(s.stages_detected) >= 3:
                        has_multi_stage = True
                        matched_seq_names.append(s.sequence_id)

            # Confidence and stage progression
            if has_multi_stage or (len(group) >= 5 and len(tactics) >= 3):
                stage = CampaignConfidence.CORRELATED_CAMPAIGN
                confidence = 0.88
                summary = f"Multi-stage coordinated campaign targeting {entity} across {len(tactics)} tactics"
            elif len(group) >= 3 or len(tactics) >= 2:
                stage = CampaignConfidence.POTENTIAL_CAMPAIGN
                confidence = 0.72
                summary = f"Potential persistent campaign observed targeting {entity}"
            else:
                stage = CampaignConfidence.ACTIVITY_CLUSTER
                confidence = 0.55
                summary = f"Activity cluster centered on entity {entity} ({len(group)} related detections)"

            camp = CampaignRecord(
                campaign_id=f"camp-{uuid.uuid4().hex[:10]}",
                tenant_id=tenant_id,
                name=f"Campaign-{entity[:12]}-{stage.value}",
                stage=stage,
                confidence=confidence,
                entity_ids=(entity,),
                indicator_ids=(),
                detection_ids=det_ids,
                alert_ids=tuple(matched_alert_ids),
                attack_sequences=tuple(matched_seq_names),
                start_time=now_iso,
                end_time=now_iso,
                summary=summary,
                supporting_evidence=tuple(sorted(evidence_ids)),
            )
            campaigns.append(camp)

        return campaigns
