"""Non-business API routes required by the Phase 1 foundation."""

from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Request
from ulpf_contracts.foundation import HealthResponse, MetadataResponse
from ulpf_platform.correlation import request_context

router = APIRouter(tags=["foundation"])


def _health(request: Request, status: Literal["healthy", "ready", "alive"]) -> HealthResponse:
    settings = request.app.state.settings
    context = request_context()
    return HealthResponse(
        status=status,
        service=settings.service_name,
        environment=settings.environment,
        timestamp=datetime.now(UTC),
        request_id=context.request_id,
        correlation_id=context.correlation_id,
        trace_id=context.trace_id,
    )


@router.get("/health", response_model=HealthResponse, summary="Foundation health")
async def health(request: Request) -> HealthResponse:
    """Confirm the process can serve the foundation API."""
    return _health(request, "healthy")


@router.get("/readiness", response_model=HealthResponse, summary="Foundation readiness")
async def readiness(request: Request) -> HealthResponse:
    """Confirm only Phase 1-local prerequisites; future stores are intentionally not checked."""
    return _health(request, "ready")


@router.get("/liveness", response_model=HealthResponse, summary="Foundation liveness")
async def liveness(request: Request) -> HealthResponse:
    """Confirm the event loop is responsive."""
    return _health(request, "alive")


@router.get("/metadata", response_model=MetadataResponse, summary="Foundation metadata")
async def metadata(request: Request) -> MetadataResponse:
    """Expose accurate foundation metadata without implying business capabilities."""
    settings = request.app.state.settings
    return MetadataResponse(
        service=settings.service_name,
        environment=settings.environment,
        api_version="v1",
        phase="1",
        capabilities=["health", "readiness", "liveness", "metadata", "openapi"],
        deferred_capabilities=["ingestion", "parsing", "normalization", "streaming", "persistence"],
    )
