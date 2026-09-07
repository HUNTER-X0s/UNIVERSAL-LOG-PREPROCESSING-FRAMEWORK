"""Forensic Evidence Package Generator for ULPF Phase 9."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from ulpf_advanced_intelligence.models.evidence_package import (
    ChecksumEntry,
    EvidencePackage,
    EvidencePackageManifest,
)
from ulpf_intelligence.models.events import InvestigationCase


class EvidencePackageGenerator:
    """Produces cryptographically manifest-audited, reproducible evidence packages."""

    SCHEMA_VERSION = "1.0.0"
    GENERATOR_VERSION = "1.0.0"

    @classmethod
    def create_package(
        cls,
        case: InvestigationCase,
        supporting_events: Sequence[dict[str, Any]],
        detections: Sequence[dict[str, Any]],
        timeline: Sequence[dict[str, Any]],
        version_pins: dict[str, str],
        entity_graph: dict[str, Any] | None = None,
        indicators: Sequence[dict[str, Any]] | None = None,
        risk_explanation: dict[str, Any] | None = None,
    ) -> EvidencePackage:
        """Construct an evidence package with individual item checksums and an overall manifest digest."""
        pkg_id = f"pkg-{uuid.uuid4().hex[:12]}"
        now_iso = datetime.now(UTC).isoformat()
        checksums: list[ChecksumEntry] = []

        # 1. Hash supporting events
        for ev in supporting_events:
            ev_bytes = json.dumps(ev, sort_keys=True).encode("utf-8")
            digest = hashlib.sha256(ev_bytes).hexdigest()
            ev_id = str(ev.get("event_id") or ev.get("id") or "event")
            checksums.append(
                ChecksumEntry(item_type="CANONICAL_EVENT", item_id=ev_id, sha256=digest, byte_count=len(ev_bytes))
            )

        # 2. Hash detections
        for det in detections:
            det_bytes = json.dumps(det, sort_keys=True).encode("utf-8")
            digest = hashlib.sha256(det_bytes).hexdigest()
            det_id = str(det.get("detection_id") or "detection")
            checksums.append(
                ChecksumEntry(item_type="DETECTION", item_id=det_id, sha256=digest, byte_count=len(det_bytes))
            )

        # 3. Overall manifest digest
        manifest_basis = f"{pkg_id}:{case.case_id}:{len(checksums)}:{now_iso}"
        for c in checksums:
            manifest_basis += f":{c.sha256}"
        overall_sha256 = hashlib.sha256(manifest_basis.encode("utf-8")).hexdigest()

        manifest = EvidencePackageManifest(
            manifest_id=f"man-{uuid.uuid4().hex[:12]}",
            package_id=pkg_id,
            case_id=case.case_id,
            tenant_id=case.tenant_id,
            generated_at=now_iso,
            generator_version=cls.GENERATOR_VERSION,
            schema_version=cls.SCHEMA_VERSION,
            total_events=len(supporting_events),
            total_detections=len(detections),
            total_anomalies=0,
            checksums=tuple(checksums),
            overall_sha256=overall_sha256,
        )

        return EvidencePackage(
            package_id=pkg_id,
            case_id=case.case_id,
            tenant_id=case.tenant_id,
            manifest=manifest,
            version_pins=dict(version_pins),
            supporting_events=tuple(supporting_events),
            detections=tuple(detections),
            timeline=tuple(timeline),
            entity_graph=dict(entity_graph or {}),
            indicators=tuple(indicators or ()),
            risk_explanation=dict(risk_explanation or {}),
            exported_at=now_iso,
        )
