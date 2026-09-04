"""Phase 2 HTTP raw-intake route with no payload semantic interpretation."""

from datetime import datetime

from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict
from ulpf_ingestion.adapters import IntakeAuthorizationError, RateLimitedError, read_bounded_body
from ulpf_ingestion.evidence import (
    EvidenceCapacityError,
    EvidenceIntegrityError,
    EvidenceNotFoundError,
)
from ulpf_ingestion.service import CaptureContractError, PayloadTooLargeError
from ulpf_platform.correlation import request_context
from ulpf_platform.errors import ApiError, ErrorCode, api_error_response

router = APIRouter(prefix="/intake", tags=["raw-intake"])


class RawIntakeAcknowledgement(BaseModel):
    """Acknowledgement means durable local capture, never semantic processing."""

    model_config = ConfigDict(extra="forbid")

    accepted: bool
    status: str
    event_id: str
    receipt_id: str
    received_at: datetime
    request_id: str
    correlation_id: str
    trace_id: str


def _peer_address(request: Request) -> str | None:
    """Format only the transport peer address exposed by the ASGI server."""
    if request.client is None:
        return None
    return f"{request.client.host}:{request.client.port}"


@router.post("/raw", response_model=RawIntakeAcknowledgement, status_code=202)
async def capture_raw(request: Request) -> RawIntakeAcknowledgement | JSONResponse:
    """Capture one HTTP request body as opaque raw evidence bytes."""
    runtime = request.app.state.intake_runtime
    settings = request.app.state.settings
    try:
        runtime.authorizer.authorize(request.headers.get("authorization"))
        runtime.rate_limiter.check()
        payload = await read_bounded_body(request.stream(), settings.intake_max_event_bytes)
        context = request_context()
        acknowledgement = await run_in_threadpool(
            runtime.http.capture,
            payload,
            _peer_address(request),
            request.headers.get("content-type"),
            context.request_id,
            context.correlation_id,
            context.trace_id,
        )
    except IntakeAuthorizationError as exc:
        return api_error_response(ApiError(401, ErrorCode.INTAKE_UNAUTHORIZED, str(exc)))
    except RateLimitedError as exc:
        return api_error_response(ApiError(429, ErrorCode.INTAKE_RATE_LIMITED, str(exc), True))
    except PayloadTooLargeError as exc:
        return api_error_response(ApiError(413, ErrorCode.INTAKE_PAYLOAD_TOO_LARGE, str(exc)))
    except EvidenceCapacityError as exc:
        return api_error_response(ApiError(503, ErrorCode.INTAKE_CAPTURE_FAILURE, str(exc), True))
    except CaptureContractError as exc:
        return api_error_response(ApiError(500, ErrorCode.INTAKE_CAPTURE_FAILURE, str(exc)))
    except Exception:
        return api_error_response(
            ApiError(500, ErrorCode.INTAKE_CAPTURE_FAILURE, "Raw evidence capture failed.", True)
        )
    return RawIntakeAcknowledgement(
        accepted=True,
        status=acknowledgement.status.value,
        event_id=acknowledgement.event_id,
        receipt_id=acknowledgement.receipt_id,
        received_at=acknowledgement.received_at,
        request_id=acknowledgement.request_id,
        correlation_id=acknowledgement.correlation_id,
        trace_id=acknowledgement.trace_id,
    )


@router.get("/raw/{event_id}", include_in_schema=False, response_model=None)
async def retrieve_raw(event_id: str, request: Request) -> Response | JSONResponse:
    """Return exact bytes only when explicit development retrieval is enabled."""
    runtime = request.app.state.intake_runtime
    settings = request.app.state.settings
    if not settings.intake_development_retrieval_enabled:
        return api_error_response(
            ApiError(404, ErrorCode.INTAKE_EVIDENCE_NOT_FOUND, "Evidence record was not found.")
        )
    try:
        runtime.authorizer.authorize(request.headers.get("authorization"))
        record = await run_in_threadpool(runtime.evidence_sink.retrieve, event_id)
        payload_metadata = record.raw_event_contract["payload"]
        media_type = payload_metadata.get("media_type", "application/octet-stream")
        if not isinstance(media_type, str):
            media_type = "application/octet-stream"
        return Response(
            content=record.payload,
            media_type=media_type,
            headers={
                "X-ULPF-Raw-Event-ID": event_id,
                "X-ULPF-Payload-SHA256": str(payload_metadata["sha256"]),
            },
        )
    except IntakeAuthorizationError as exc:
        return api_error_response(ApiError(401, ErrorCode.INTAKE_UNAUTHORIZED, str(exc)))
    except EvidenceNotFoundError:
        return api_error_response(
            ApiError(404, ErrorCode.INTAKE_EVIDENCE_NOT_FOUND, "Evidence record was not found.")
        )
    except (EvidenceIntegrityError, ValueError):
        return api_error_response(
            ApiError(
                409, ErrorCode.INTAKE_CAPTURE_FAILURE, "Evidence integrity verification failed."
            )
        )
