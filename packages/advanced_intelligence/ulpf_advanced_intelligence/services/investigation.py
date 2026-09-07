"""Cross-Source & Cross-Vendor Investigation Orchestration Service for ULPF Phase 9."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from ulpf_advanced_intelligence.adaptive_detection.engine import AdaptiveDetectionEngine
from ulpf_advanced_intelligence.content.lifecycle import AdvancedDetectionRule
from ulpf_advanced_intelligence.models.alerts import AlertRecord
from ulpf_advanced_intelligence.ti_matching.engine import ThreatIntelMatchingEngine
from ulpf_intelligence.entities.resolver import EntityResolver
from ulpf_intelligence.investigations.workbench import InvestigationWorkbench
from ulpf_intelligence.models.events import DetectionEvent, InvestigationCase


class CrossSourceInvestigationService:
    """Orchestrates multi-vendor, heterogeneous event investigations under canonical UCE representations."""

    def __init__(
        self,
        entity_resolver: EntityResolver | None = None,
        ti_matcher: ThreatIntelMatchingEngine | None = None,
        workbench: InvestigationWorkbench | None = None,
    ) -> None:
        self.resolver = entity_resolver or EntityResolver()
        self.ti_matcher = ti_matcher or ThreatIntelMatchingEngine()
        self.workbench = workbench or InvestigationWorkbench()

    def investigate_heterogeneous_events(
        self,
        events: Sequence[dict[str, Any]],
        rules: list[AdvancedDetectionRule],
        title: str = "Cross-Vendor Security Investigation",
        tenant_id: str | None = None,
    ) -> tuple[InvestigationCase, list[DetectionEvent], list[AlertRecord]]:
        """Process events from diverse vendors (e.g. Cisco, Fortinet, Palo Alto, Zeek, Linux auth).

        Unifies them by canonical entity, evaluates TI and detections, and builds a comprehensive case.
        """
        all_detections: list[DetectionEvent] = []
        all_alerts: list[AlertRecord] = []
        involved_entities: set[str] = set()
        vendor_sources: set[str] = set()

        for ev in events:
            # 1. Resolve source and destination entities
            src_ip = ev.get("src_ip") or ev.get("source_ip")
            if src_ip:
                e = self.resolver.get_or_create(identifier=str(src_ip), entity_type="IP", tenant_id=tenant_id)
                involved_entities.add(e.canonical_id)

            dst_ip = ev.get("dst_ip") or ev.get("destination_ip")
            if dst_ip:
                e2 = self.resolver.get_or_create(identifier=str(dst_ip), entity_type="IP", tenant_id=tenant_id)
                involved_entities.add(e2.canonical_id)

            user = ev.get("username") or ev.get("user")
            if user:
                eu = self.resolver.get_or_create(identifier=str(user), entity_type="USER", tenant_id=tenant_id)
                involved_entities.add(eu.canonical_id)

            vendor = str(ev.get("vendor") or ev.get("source_vendor") or "GENERIC")
            vendor_sources.add(vendor)

            # 2. Check Threat Intelligence
            ti_assessment = self.ti_matcher.match_event(ev, tenant_id=tenant_id)

            # 3. Evaluate adaptive detection rules
            pairs = AdaptiveDetectionEngine.evaluate(
                event=ev,
                rules=rules,
                ti_assessment=ti_assessment,
            )
            for det, alert in pairs:
                all_detections.append(det)
                all_alerts.append(alert)

        # 4. Create or update investigation case
        case = self.workbench.create_case(
            title=f"{title} ({len(vendor_sources)} vendors: {', '.join(sorted(vendor_sources))})",
            description=f"Automated cross-source correlation over {len(events)} events",
            tenant_id=tenant_id,
            initial_detection_ids=[d.detection_id for d in all_detections],
            initial_event_ids=[str(ev.get("event_id", "")) for ev in events if ev.get("event_id")],
        )
        case.entity_ids = list(involved_entities)

        return case, all_detections, all_alerts
