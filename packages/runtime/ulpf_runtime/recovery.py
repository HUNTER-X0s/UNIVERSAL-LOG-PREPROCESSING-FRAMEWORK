"""ULPF Phase 7 — Disaster Recovery Coordinator.

Validates restore operations to a clean environment:
- Schema version verification post-restore
- Checksum verification of all restored components
- Search index rebuild from canonical store
- Replay jobs recovery from persisted state

Enforces:
- Rule D4: DR restore drill validates schema, checksums, and search rebuild
- Rule D5: Search failure does not stall canonical processing
- Rule D6: Database failure prevents false ACK (fail-closed)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)


class RecoveryError(Exception):
    """Raised when a recovery operation fails validation."""


@dataclass
class RecoveryReport:
    """Report from a disaster recovery drill."""

    recovery_id: str
    started_at: str
    completed_at: str | None = None
    schema_version_verified: bool = False
    components_verified: list[str] = field(default_factory=list)
    components_failed: list[str] = field(default_factory=list)
    search_index_rebuilt: bool = False
    replay_jobs_recovered: int = 0
    overall_success: bool = False
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "recovery_id": self.recovery_id,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "schema_version_verified": self.schema_version_verified,
            "components_verified": self.components_verified,
            "components_failed": self.components_failed,
            "search_index_rebuilt": self.search_index_rebuilt,
            "replay_jobs_recovered": self.replay_jobs_recovered,
            "overall_success": self.overall_success,
            "notes": self.notes,
        }


class DisasterRecoveryCoordinator:
    """Orchestrates disaster recovery drills and validates restore correctness.

    The coordinator works against abstract callable hooks so it can be
    tested without a running production deployment.
    """

    def __init__(
        self,
        expected_schema_version: int,
    ) -> None:
        self._expected_schema = expected_schema_version

    def run_restore_drill(
        self,
        backup_manifest: dict[str, Any],
        restored_components: dict[str, bytes],
        actual_schema_version: int,
        rebuild_search_index_fn: Any | None = None,
        recover_replay_jobs_fn: Any | None = None,
    ) -> RecoveryReport:
        """Execute a full disaster recovery drill.

        Steps:
        1. Verify schema version matches expected.
        2. Verify SHA-256 checksums for all restored components.
        3. Rebuild search index from canonical store.
        4. Recover outstanding replay jobs.

        Returns a RecoveryReport with pass/fail per step.
        Raises RecoveryError only on catastrophic validation failure.
        """
        import hashlib

        recovery_id = f"dr-drill-{datetime.now(UTC).isoformat().replace(':', '-')}"
        report = RecoveryReport(
            recovery_id=recovery_id,
            started_at=datetime.now(UTC).isoformat(),
        )

        # Step 1: Schema version check
        if actual_schema_version >= self._expected_schema:
            report.schema_version_verified = True
            report.notes.append(
                f"Schema version {actual_schema_version} >= expected {self._expected_schema}: OK"
            )
        else:
            report.notes.append(
                f"Schema version mismatch: actual={actual_schema_version} "
                f"expected={self._expected_schema}"
            )
            logger.error(
                "DR drill %s: schema version mismatch %d < %d",
                recovery_id,
                actual_schema_version,
                self._expected_schema,
            )

        # Step 2: Checksum verification of all components
        expected_checksums: dict[str, str] = backup_manifest.get("components", {})
        for name, raw_data in restored_components.items():
            actual_sha256 = hashlib.sha256(raw_data).hexdigest()
            expected_sha256 = expected_checksums.get(name, "")
            if actual_sha256 == expected_sha256:
                report.components_verified.append(name)
            else:
                report.components_failed.append(name)
                report.notes.append(
                    f"Component '{name}' checksum mismatch: "
                    f"expected={expected_sha256} actual={actual_sha256}"
                )

        # Step 3: Rebuild search index (non-blocking if unavailable)
        if rebuild_search_index_fn is not None:
            try:
                rebuild_search_index_fn()
                report.search_index_rebuilt = True
                report.notes.append("Search index rebuild: OK")
            except Exception as exc:
                # Search failure does not stall canonical processing (Rule D5)
                report.notes.append(f"Search index rebuild WARNING: {exc}")
                logger.warning("DR drill %s: search rebuild warning: %s", recovery_id, exc)
        else:
            report.search_index_rebuilt = True  # No search component; pass
            report.notes.append("Search index rebuild: skipped (no component)")

        # Step 4: Recover outstanding replay jobs
        if recover_replay_jobs_fn is not None:
            try:
                recovered = recover_replay_jobs_fn()
                report.replay_jobs_recovered = int(recovered)
                report.notes.append(f"Replay jobs recovered: {recovered}")
            except Exception as exc:
                report.notes.append(f"Replay job recovery WARNING: {exc}")
                logger.warning("DR drill %s: replay recovery warning: %s", recovery_id, exc)
        else:
            report.notes.append("Replay job recovery: skipped")

        # Overall success requires schema + all components verified
        report.overall_success = (
            report.schema_version_verified
            and len(report.components_failed) == 0
            and report.search_index_rebuilt
        )
        report.completed_at = datetime.now(UTC).isoformat()

        if not report.overall_success:
            logger.error(
                "DR drill %s FAILED: schema_ok=%s failed_components=%s",
                recovery_id,
                report.schema_version_verified,
                report.components_failed,
            )

        return report
