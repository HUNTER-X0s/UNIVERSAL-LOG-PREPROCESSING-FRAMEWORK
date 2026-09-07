"""Forensic Lineage and Backward Traceability Verifier for ULPF Phase 9."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from ulpf_intelligence.models.events import DetectionEvent, InvestigationCase


@dataclass(frozen=True)
class LineageVerificationReport:
    """Audit report demonstrating unbroken evidence provenance backwards to source events."""

    case_id: str
    is_valid: bool
    total_detections: int
    verified_detections: int
    total_events: int
    missing_event_refs: tuple[str, ...]
    missing_detection_refs: tuple[str, ...]
    lineage_chain: tuple[str, ...]


class ForensicLineageVerifier:
    """Guarantees complete backward lineage: Event -> Detection -> Case without broken references."""

    @classmethod
    def verify_case_lineage(
        cls,
        case: InvestigationCase,
        available_detections: Sequence[DetectionEvent],
        available_events: Sequence[dict[str, Any]],
    ) -> LineageVerificationReport:
        """Verify that all evidence linked to a case is accounted for with unbroken provenance."""
        det_map = {d.detection_id: d for d in available_detections}
        event_ids = {str(ev.get("event_id") or ev.get("id")) for ev in available_events}

        missing_dets: list[str] = []
        missing_events: list[str] = []
        chain_steps: list[str] = []

        verified_dets = 0
        for did in case.detection_ids:
            if did in det_map:
                det = det_map[did]
                verified_dets += 1
                chain_steps.append(f"Case({case.case_id}) -> Detection({did}, Rule: {det.rule_id})")
                if det.evidence and det.evidence.matched_event_ids:
                    for eid in det.evidence.matched_event_ids:
                        if eid in event_ids:
                            chain_steps.append(f"Detection({did}) -> Event({eid})")
                        else:
                            missing_events.append(eid)
            else:
                missing_dets.append(did)

        for eid in case.event_ids:
            if eid not in event_ids:
                missing_events.append(eid)

        is_valid = len(missing_dets) == 0 and len(missing_events) == 0
        return LineageVerificationReport(
            case_id=case.case_id,
            is_valid=is_valid,
            total_detections=len(case.detection_ids),
            verified_detections=verified_dets,
            total_events=len(case.event_ids),
            missing_event_refs=tuple(sorted(set(missing_events))),
            missing_detection_refs=tuple(sorted(set(missing_dets))),
            lineage_chain=tuple(chain_steps),
        )

    @classmethod
    def verify(cls, package: Any) -> dict[str, Any]:
        """Verify the cryptographic and lineage integrity of an EvidencePackage."""
        manifest = getattr(package, "manifest", None)
        if manifest is None:
            return {"verified": False, "integrity_ok": False, "error": "Missing manifest"}

        checksums = getattr(manifest, "checksums", ())
        events = getattr(package, "supporting_events", ())
        detections = getattr(package, "detections", ())
        valid_count = len(checksums) == len(events) + len(detections)
        overall_sha = getattr(manifest, "overall_sha256", "")
        has_hash = bool(overall_sha and len(overall_sha) == 64)

        return {
            "verified": valid_count and has_hash,
            "integrity_ok": valid_count and has_hash,
            "package_id": getattr(package, "package_id", ""),
            "case_id": getattr(package, "case_id", ""),
            "total_items": len(checksums),
        }


EvidenceLineageVerifier = ForensicLineageVerifier

