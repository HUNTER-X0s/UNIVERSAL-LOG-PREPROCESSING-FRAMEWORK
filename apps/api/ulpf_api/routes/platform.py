"""Phase 6 operational and administrative REST API routes for ULPF.

Enforces:
- Rule 27/28: Health endpoints (/health, /health/live, /health/ready)
- Rule 29/30: Versioned API contracts for events, UCE, semantic events, search, DLQ, replay
- Rule 31/32: Role-based authorization (viewer, operator, mapping-admin, platform-admin)
- Rule 33: Audit logging for administrative mutations
- Rule 101: Bounded query limits and pagination
"""

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Query, status
from pydantic import BaseModel
from ulpf_delivery.outbox import OutboxDispatcher
from ulpf_delivery.sinks import OCSFJsonSink, OTelBatchSink, SiemMockSink
from ulpf_observability.metrics import OperationalMetricsRegistry
from ulpf_runtime.backpressure import BackpressureController
from ulpf_runtime.dlq import DLQManager
from ulpf_runtime.health import HealthRegistry, HealthState
from ulpf_runtime.idempotency import IdempotencyGuard
from ulpf_runtime.pipeline import RuntimePipeline
from ulpf_runtime.replay import ReplayRequest, RuntimeReplayCoordinator
from ulpf_search.interfaces import SearchQuery
from ulpf_search.memory import MemorySearchIndex
from ulpf_storage.memory import (
    MemoryAuditRepository,
    MemoryOutboxRepository,
    MemoryRawEvidenceRepository,
    MemorySemanticEventRepository,
    MemoryUCERepository,
)

router = APIRouter(tags=["platform"])

# Shared singleton instances for API runtime
raw_store = MemoryRawEvidenceRepository()
uce_store = MemoryUCERepository()
semantic_store = MemorySemanticEventRepository()
outbox_repo = MemoryOutboxRepository()
audit_repo = MemoryAuditRepository()
search_adapter = MemorySearchIndex()
dlq_manager = DLQManager()
backpressure = BackpressureController(max_capacity=5000)
idempotency = IdempotencyGuard()
metrics_registry = OperationalMetricsRegistry()
health_registry = HealthRegistry(service_name="ulpf-platform-api", version="1.0.0")

# Register dependencies for health checks
health_registry.register_dependency(
    "raw_store", lambda: (HealthState.HEALTHY, None), is_critical=True
)
health_registry.register_dependency(
    "uce_store", lambda: (HealthState.HEALTHY, None), is_critical=True
)
health_registry.register_dependency(
    "search_index", lambda: (HealthState.HEALTHY, None), is_critical=False
)

sinks = {
    "ocsf": OCSFJsonSink(),
    "otel": OTelBatchSink(),
    "siem": SiemMockSink(),
}
outbox_dispatcher = OutboxDispatcher(outbox_repo=outbox_repo, sinks=sinks)

pipeline = RuntimePipeline(
    raw_store=raw_store,
    uce_store=uce_store,
    semantic_store=semantic_store,
    search_adapter=search_adapter,
    outbox_repo=outbox_repo,
    dlq_manager=dlq_manager,
    backpressure=backpressure,
    idempotency=idempotency,
    metrics=metrics_registry,
)

replay_coordinator = RuntimeReplayCoordinator(
    pipeline=pipeline,
    raw_store=raw_store,
    uce_store=uce_store,
    audit_repo=audit_repo,
)


def verify_role(required_roles: set[str], role_header: str | None) -> str:
    """Verify role authorization."""
    role = role_header or "viewer"
    if role not in required_roles and "platform-admin" not in role:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Operation requires one of roles: {required_roles}, caller has: {role}",
        )
    return role


# --- Request/Response Models ---

class EventIngestRequest(BaseModel):
    raw_payload: str
    source_id: str
    format: str = "syslog"
    correlation_id: str | None = None
    mapping_version: str | None = None


class ReplayApiRequest(BaseModel):
    target_stage: str = "RAW"  # RAW, UCE
    mapping_version: str
    event_ids: list[str]
    reason: str = "Forensic Investigation"


# --- Health Endpoints ---

@router.get("/health")
def get_health() -> dict[str, Any]:
    return health_registry.check_liveness()


@router.get("/health/live")
def get_health_live() -> dict[str, Any]:
    return health_registry.check_liveness()


@router.get("/health/ready")
def get_health_ready() -> dict[str, Any]:
    res = health_registry.check_readiness()
    if not res["is_ready"]:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=res)
    return res


# --- Telemetry Ingestion & Data APIs ---

@router.post("/events/ingest", status_code=status.HTTP_202_ACCEPTED)
def ingest_event(
    req: EventIngestRequest,
    x_role: str | None = Header(None, alias="X-Role"),
) -> dict[str, Any]:
    verify_role({"operator", "platform-admin"}, x_role)

    res = pipeline.process_event(
        raw_payload=req.raw_payload,
        source_id=req.source_id,
        format_str=req.format,
        correlation_id=req.correlation_id,
        mapping_version=req.mapping_version,
    )
    return {
        "event_id": res.event_id,
        "raw_sha256": res.raw_sha256,
        "state": res.lifecycle_state.value,
        "semantic_event_id": res.semantic_event_id,
        "duration_ms": res.duration_ms,
        "is_duplicate": res.is_duplicate,
        "dlq_id": res.dlq_id,
    }


@router.get("/events/raw/{raw_event_id}")
def get_raw_evidence(
    raw_event_id: str,
    x_role: str | None = Header(None, alias="X-Role"),
) -> dict[str, Any]:
    verify_role({"viewer", "operator", "platform-admin"}, x_role)
    meta = raw_store.get_metadata(raw_event_id)
    if not meta:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Raw evidence not found")
    _, payload = raw_store.get(raw_event_id)
    return {
        "raw_event_id": meta.raw_event_id,
        "sha256": meta.sha256,
        "source_id": meta.source_id,
        "byte_length": meta.byte_length,
        "payload_text": payload.decode("utf-8", errors="replace"),
    }


@router.get("/uce/{uce_event_id}")
def get_uce_event(
    uce_event_id: str,
    x_role: str | None = Header(None, alias="X-Role"),
) -> dict[str, Any]:
    verify_role({"viewer", "operator", "platform-admin"}, x_role)
    rec = uce_store.get(uce_event_id)
    if not rec:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="UCE not found")
    return {
        "uce_event_id": rec.uce_event_id,
        "raw_event_id": rec.raw_event_id,
        "raw_sha256": rec.raw_sha256,
        "payload": rec.payload,
        "stored_at": rec.stored_at,
    }


@router.get("/semantic/{semantic_event_id}")
def get_semantic_event(
    semantic_event_id: str,
    x_role: str | None = Header(None, alias="X-Role"),
) -> dict[str, Any]:
    verify_role({"viewer", "operator", "platform-admin"}, x_role)
    rec = semantic_store.get(semantic_event_id)
    if not rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Semantic event not found"
        )
    return {
        "semantic_event_id": rec.semantic_event_id,
        "uce_event_id": rec.uce_event_id,
        "fingerprint": rec.fingerprint,
        "risk_level": rec.risk_level,
        "risk_score": rec.risk_score,
        "classification": rec.classification,
        "payload": rec.payload,
    }


# --- Search API ---

@router.get("/search")
def search_events(
    vendor: str | None = None,
    product: str | None = None,
    risk_level: str | None = None,
    fingerprint: str | None = None,
    entity: str | None = None,
    indicator: str | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    x_role: str | None = Header(None, alias="X-Role"),
) -> dict[str, Any]:
    verify_role({"viewer", "operator", "platform-admin"}, x_role)
    q = SearchQuery(
        vendor=vendor,
        product=product,
        risk_level=risk_level,
        fingerprint=fingerprint,
        entity_value=entity,
        indicator_value=indicator,
        limit=limit,
        offset=offset,
    )
    res = search_adapter.search(q)
    return {
        "total_matches": res.total_matches,
        "returned_count": res.returned_count,
        "offset": res.offset,
        "execution_time_ms": res.execution_time_ms,
        "events": res.events,
    }


# --- DLQ Management ---

@router.get("/dlq")
def list_dlq_records(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    x_role: str | None = Header(None, alias="X-Role"),
) -> dict[str, Any]:
    verify_role({"operator", "platform-admin"}, x_role)
    records = dlq_manager.list_records(limit=limit, offset=offset)
    return {
        "total": dlq_manager.count(),
        "records": [
            {
                "dlq_id": r.dlq_id,
                "original_event_id": r.original_event_id,
                "stage": r.stage,
                "error_type": r.error_type,
                "error_message": r.error_message,
                "source_id": r.source_id,
                "replayed": r.replayed,
            }
            for r in records
        ],
    }


# --- Historical Replay API ---

@router.post("/replay", status_code=status.HTTP_200_OK)
def trigger_replay(
    req: ReplayApiRequest,
    x_role: str | None = Header(None, alias="X-Role"),
) -> dict[str, Any]:
    role = verify_role({"operator", "platform-admin"}, x_role)
    ts_ms = int(datetime.now(UTC).timestamp() * 1000)
    replay_req = ReplayRequest(
        job_id=f"job-{ts_ms}",
        target_stage=req.target_stage,
        mapping_version=req.mapping_version,
        event_ids=req.event_ids,
        reason=req.reason,
        requested_by=role,
    )
    res = replay_coordinator.execute_replay(replay_req)
    return {
        "job_id": res.job_id,
        "mapping_version": res.mapping_version,
        "total_requested": res.total_requested,
        "processed_count": res.processed_count,
        "failed_count": res.failed_count,
        "audit_id": res.audit_id,
    }


# --- Metrics Snapshot API ---

@router.get("/metrics")
def get_metrics(
    x_role: str | None = Header(None, alias="X-Role"),
) -> dict[str, Any]:
    verify_role({"viewer", "operator", "platform-admin"}, x_role)
    return metrics_registry.snapshot()
