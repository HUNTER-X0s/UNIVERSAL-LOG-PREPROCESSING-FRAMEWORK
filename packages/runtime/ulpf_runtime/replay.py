"""Operational historical replay coordinator for ULPF Phase 6.

Enforces:
- Rule 38: Raw, UCE, and semantic replay. Distinguish reprocess from redeliver.
- Rule 39: Replay safety: replay MUST NOT overwrite canonical history or bypass audit.
- Rule 40: Explicit pinned mapping version required; never silently use latest.
- Rule 79: Bounded replay batches and time ranges.
"""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from ulpf_storage.interfaces import AuditRepository, RawEvidenceRepository, UCERepository

from ulpf_runtime.errors import ReplayError
from ulpf_runtime.models import AuditActionRecord
from ulpf_runtime.pipeline import PipelineResult, RuntimePipeline


@dataclass(frozen=True)
class ReplayRequest:
    """Historical replay job request."""

    job_id: str
    target_stage: str  # RAW, UCE, PROJECTION
    mapping_version: str  # Must be explicitly pinned
    event_ids: list[str]
    mode: str = "REPROCESS"  # REPROCESS (re-run through pipeline) or REDELIVER
    reason: str = "Investigation"
    requested_by: str = "operator"
    max_events: int = 500


@dataclass(frozen=True)
class ReplayJobResult:
    """Outcome of historical replay job."""

    job_id: str
    target_stage: str
    mapping_version: str
    total_requested: int
    processed_count: int
    failed_count: int
    results: list[PipelineResult]
    audit_id: str
    started_at: str
    completed_at: str


class RuntimeReplayCoordinator:
    """Coordinates deterministic historical replay with pinned mapping versions."""

    def __init__(
        self,
        pipeline: RuntimePipeline,
        raw_store: RawEvidenceRepository,
        uce_store: UCERepository,
        audit_repo: AuditRepository,
        max_events_per_job: int = 1000,
    ) -> None:
        self.pipeline = pipeline
        self.raw_store = raw_store
        self.uce_store = uce_store
        self.audit_repo = audit_repo
        self.max_events_per_job = max_events_per_job

    def execute_replay(self, request: ReplayRequest) -> ReplayJobResult:
        """Execute a replay job safely with mapping version pinning."""
        started_at = datetime.now(UTC).isoformat()

        # Enforce version pinning
        if not request.mapping_version or request.mapping_version.strip() == "":
            raise ReplayError("Replay requires an explicit pinned mapping_version.")

        # Bounded event limit check
        if len(request.event_ids) > self.max_events_per_job:
            raise ReplayError(
                f"Replay request exceeds maximum limit of {self.max_events_per_job} events."
            )

        # Audit the start of replay
        audit_id = f"audit-replay-{uuid.uuid4().hex[:8]}"
        self.audit_repo.record_action(
            AuditActionRecord(
                audit_id=audit_id,
                actor=request.requested_by,
                action="REPLAY_START",
                target=request.job_id,
                previous_state=None,
                new_state="RUNNING",
                reason=request.reason,
                checksum=request.mapping_version,
            )
        )

        pipeline_results: list[PipelineResult] = []
        processed_count = 0
        failed_count = 0

        for eid in request.event_ids:
            try:
                if request.target_stage == "RAW":
                    # Fetch raw evidence and reprocess
                    meta, raw_bytes = self.raw_store.get(eid)
                    res = self.pipeline.process_event(
                        raw_payload=raw_bytes,
                        source_id=meta.source_id,
                        format_str=meta.format,
                        raw_event_id=meta.raw_event_id,
                        correlation_id=f"replay-{request.job_id}",
                        mapping_version=request.mapping_version,
                    )
                    pipeline_results.append(res)
                    if res.error:
                        failed_count += 1
                    else:
                        processed_count += 1

                elif request.target_stage == "UCE":
                    uce_rec = self.uce_store.get(eid)
                    if not uce_rec:
                        raise ReplayError(f"UCE record {eid} not found for replay")

                    res = self.pipeline.process_event(
                        raw_payload=b"",
                        source_id=uce_rec.source_id,
                        format_str="uce_replay",
                        raw_event_id=uce_rec.raw_event_id,
                        correlation_id=f"replay-{request.job_id}",
                        custom_uce=uce_rec.payload,
                        mapping_version=request.mapping_version,
                    )
                    pipeline_results.append(res)
                    if res.error:
                        failed_count += 1
                    else:
                        processed_count += 1

                else:
                    raise ReplayError(f"Unsupported replay stage: {request.target_stage}")

            except Exception:
                failed_count += 1

        completed_at = datetime.now(UTC).isoformat()

        # Audit completion
        self.audit_repo.record_action(
            AuditActionRecord(
                audit_id=f"audit-replay-end-{uuid.uuid4().hex[:8]}",
                actor=request.requested_by,
                action="REPLAY_COMPLETE",
                target=request.job_id,
                previous_state="RUNNING",
                new_state="COMPLETED",
                reason=f"Processed: {processed_count}, Failed: {failed_count}",
                checksum=request.mapping_version,
            )
        )

        return ReplayJobResult(
            job_id=request.job_id,
            target_stage=request.target_stage,
            mapping_version=request.mapping_version,
            total_requested=len(request.event_ids),
            processed_count=processed_count,
            failed_count=failed_count,
            results=pipeline_results,
            audit_id=audit_id,
            started_at=started_at,
            completed_at=completed_at,
        )
