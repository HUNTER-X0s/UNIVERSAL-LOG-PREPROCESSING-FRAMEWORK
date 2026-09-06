"""Schema Drift Detector for ULPF Phase 5 Onboarding Governance.

Compares active SourceProfile specifications against new sample telemetry batches,
detecting schema additions, deletions, renames, and type mutations without modifying
production mappings automatically.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

from ulpf_onboarding.models import DriftReport, DriftState, SourceProfile
from ulpf_onboarding.profiler import SampleProfiler


class SchemaDriftDetector:
    """Detects structural and type deviations from established source profiles."""

    @classmethod
    def detect_drift(
        cls,
        baseline_profile: SourceProfile,
        new_samples: list[dict[str, Any]] | SourceProfile,
    ) -> DriftReport:
        """Compare baseline profile against a new batch of samples or candidate profile."""
        if isinstance(new_samples, SourceProfile):
            new_profile = new_samples
        else:
            new_profile = SampleProfiler.profile_samples(
                samples=new_samples,
                vendor=baseline_profile.vendor,
                product=baseline_profile.product,
                format_id=baseline_profile.format,
            )

        old_fields = {f.path: f.inferred_type for f in baseline_profile.fields}
        new_fields = {f.path: f.inferred_type for f in new_profile.fields}

        added = sorted(list(set(new_fields.keys()) - set(old_fields.keys())))
        removed = sorted(list(set(old_fields.keys()) - set(new_fields.keys())))

        type_changes = []
        for common_path in set(old_fields.keys()) & set(new_fields.keys()):
            if old_fields[common_path] != new_fields[common_path]:
                type_changes.append(
                    {
                        "field": common_path,
                        "old_type": old_fields[common_path],
                        "new_type": new_fields[common_path],
                    }
                )

        # Classify drift state
        if not added and not removed and not type_changes:
            drift_state = DriftState.STABLE
            rec_action = "Schema is stable. No mapping update required."
        elif type_changes:
            drift_state = DriftState.BREAKING_DRIFT
            rec_action = "Type mutation detected on existing fields. Requires urgent manual review."
        elif removed:
            drift_state = DriftState.MAJOR_DRIFT
            rec_action = (
                "Fields removed from telemetry stream. Validate downstream mapping dependencies."
            )
        else:
            drift_state = DriftState.MINOR_DRIFT
            rec_action = (
                "New fields added. Consider candidate mapping generation to enrich semantics."
            )

        r_id = f"drift_{uuid.uuid4().hex[:12]}"
        now_iso = datetime.now(UTC).isoformat()

        return DriftReport(
            report_id=r_id,
            profile_id=baseline_profile.profile_id,
            profile_version=baseline_profile.version,
            drift_state=drift_state,
            timestamp=now_iso,
            fields_added=added,
            fields_removed=removed,
            type_changes=type_changes,
            recommended_action=rec_action,
        )
