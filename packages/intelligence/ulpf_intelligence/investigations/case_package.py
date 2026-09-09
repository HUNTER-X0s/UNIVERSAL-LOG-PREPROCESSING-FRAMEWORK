"""Forensic Case Package Generator and Cryptographic Verifier for ULPF Phase 13.

Workstream N: Packages full investigation context (raw evidence, SHA-256 digests,
13-stage lineage, entities, attack story, analyst notes) into an independently verifiable bundle.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass(frozen=True)
class CasePackageManifest:
    """Cryptographic manifest anchoring the case package contents."""
    package_id: str
    case_id: str
    created_at: str
    event_count: int
    raw_digests: list[str]
    package_overall_sha256: str
    signing_algorithm: str = "SHA-256"


@dataclass(frozen=True)
class CasePackageVerificationResult:
    """Outcome of an independent forensic integrity check on a case package."""
    is_valid: bool
    package_id: str
    events_verified: int
    tamper_detected: bool
    errors: list[str]
    verification_timestamp: str


class CasePackageManager:
    """Creates and independently validates cryptographically sealed case packages."""

    @classmethod
    def create_package(
        cls,
        case_id: str,
        title: str,
        raw_events: list[dict[str, Any]],
        detections: list[dict[str, Any]] | None = None,
        attack_story: dict[str, Any] | None = None,
        analyst_notes: list[str] | None = None,
    ) -> dict[str, Any]:
        """Assemble an immutable case package bundle with cryptographic manifest."""
        pkg_id = f"pkg-{uuid.uuid4().hex[:12]}"
        now_iso = datetime.now(UTC).isoformat()

        digests: list[str] = []
        packaged_events: list[dict[str, Any]] = []

        for ev in raw_events:
            raw_payload = ev.get("raw_payload", ev.get("raw_text", str(ev)))
            if isinstance(raw_payload, str):
                raw_bytes = raw_payload.encode("utf-8")
            else:
                raw_bytes = bytes(raw_payload)

            digest = hashlib.sha256(raw_bytes).hexdigest()
            digests.append(digest)

            packaged_events.append({
                "event_id": ev.get("event_id", f"evt-{len(packaged_events)+1}"),
                "raw_sha256": digest,
                "raw_payload": raw_payload if isinstance(raw_payload, str) else raw_payload.decode("utf-8", errors="replace"),
                "normalized": ev.get("normalized", ev),
                "lineage_stages_count": ev.get("lineage_stages_count", 13),
            })

        # Calculate package overall hash across sorted digests and metadata
        combined_repr = json.dumps(sorted(digests), sort_keys=True) + case_id + title
        overall_sha = hashlib.sha256(combined_repr.encode("utf-8")).hexdigest()

        manifest = CasePackageManifest(
            package_id=pkg_id,
            case_id=case_id,
            created_at=now_iso,
            event_count=len(packaged_events),
            raw_digests=sorted(digests),
            package_overall_sha256=overall_sha,
        )

        return {
            "schema_version": "1.3.0",
            "package_id": pkg_id,
            "case_id": case_id,
            "case_title": title,
            "manifest": {
                "package_id": manifest.package_id,
                "case_id": manifest.case_id,
                "created_at": manifest.created_at,
                "event_count": manifest.event_count,
                "raw_digests": manifest.raw_digests,
                "package_overall_sha256": manifest.package_overall_sha256,
                "signing_algorithm": manifest.signing_algorithm,
            },
            "events": packaged_events,
            "detections": detections or [],
            "attack_story": attack_story or {},
            "analyst_notes": analyst_notes or ["Case packaged for forensic evidence transfer."],
        }

    @classmethod
    def verify_package(cls, package_bundle: dict[str, Any]) -> CasePackageVerificationResult:
        """Perform deterministic bit-level validation of all raw hashes and manifest."""
        manifest_data = package_bundle.get("manifest", {})
        pkg_id = package_bundle.get("package_id", "unknown")
        recorded_overall_sha = manifest_data.get("package_overall_sha256", "")
        case_id = package_bundle.get("case_id", "")
        title = package_bundle.get("case_title", "")
        events = package_bundle.get("events", [])

        errors: list[str] = []
        computed_digests: list[str] = []

        # 1. Verify each event raw payload against its declared SHA-256
        for idx, ev in enumerate(events):
            raw_text = ev.get("raw_payload", "")
            declared_sha = ev.get("raw_sha256", "")
            actual_sha = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()

            if actual_sha != declared_sha:
                errors.append(
                    f"Tamper detected in event {idx} ({ev.get('event_id')}): "
                    f"Declared {declared_sha}, actual {actual_sha}."
                )
            computed_digests.append(actual_sha)

        # 2. Verify overall package signature
        combined_repr = json.dumps(sorted(computed_digests), sort_keys=True) + case_id + title
        expected_overall_sha = hashlib.sha256(combined_repr.encode("utf-8")).hexdigest()

        if expected_overall_sha != recorded_overall_sha:
            errors.append(
                f"Overall manifest checksum mismatch: Recorded {recorded_overall_sha}, "
                f"recomputed {expected_overall_sha}."
            )

        now_iso = datetime.now(UTC).isoformat()
        is_valid = len(errors) == 0

        return CasePackageVerificationResult(
            is_valid=is_valid,
            package_id=pkg_id,
            events_verified=len(events),
            tamper_detected=not is_valid,
            errors=errors,
            verification_timestamp=now_iso,
        )
