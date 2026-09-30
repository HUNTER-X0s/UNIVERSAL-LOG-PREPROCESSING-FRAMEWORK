"""Safe, version-independent HTTP error foundation."""

from datetime import UTC, datetime
from enum import Enum

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from ulpf_contracts.foundation import ErrorEnvelope

from ulpf_platform.correlation import request_context


class ErrorCode(str, Enum):
    """Stable public error code vocabulary for the foundation API."""

    VALIDATION_ERROR = "validation_error"
    CONFIGURATION_ERROR = "configuration_error"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    DEPENDENCY_UNAVAILABLE = "dependency_unavailable"
    TIMEOUT = "timeout"
    UNSUPPORTED_OPERATION = "unsupported_operation"
    REQUEST_TOO_LARGE = "request_too_large"
    INTAKE_INVALID_REQUEST = "intake_invalid_request"
    INTAKE_PAYLOAD_TOO_LARGE = "intake_payload_too_large"
    INTAKE_HEADERS_TOO_LARGE = "intake_headers_too_large"
    INTAKE_RATE_LIMITED = "intake_rate_limited"
    INTAKE_UNAUTHORIZED = "intake_unauthorized"
    INTAKE_CAPTURE_FAILURE = "intake_capture_failure"
    INTAKE_EVIDENCE_NOT_FOUND = "intake_evidence_not_found"
    INTERNAL_ERROR = "internal_error"
    UNAUTHORIZED = "unauthorized"
    FORBIDDEN = "forbidden"


class ApiError(Exception):
    """Expected error carrying only client-safe attributes."""

    def __init__(
        self, status_code: int, code: ErrorCode, message: str, retryable: bool = False
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.retryable = retryable

    @classmethod
    def internal(cls, request: Request, cause: Exception) -> "ApiError":
        del request, cause
        return cls(500, ErrorCode.INTERNAL_ERROR, "An unexpected internal error occurred.")


def api_error_response(error: ApiError, details: dict[str, str] | None = None) -> JSONResponse:
    """Create a safe response envelope and omit implementation details."""
    context = request_context()
    body = ErrorEnvelope(
        code=error.code.value,
        message=error.message,
        request_id=context.request_id,
        correlation_id=context.correlation_id,
        trace_id=context.trace_id,
        retryable=error.retryable,
        timestamp=datetime.now(UTC),
        details=details,
    )
    return JSONResponse(status_code=error.status_code, content=body.model_dump(mode="json"))


def validation_error_response(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Return bounded field names, never raw request bodies or exception paths."""
    del request
    details: dict[str, str] = {}
    for index, error in enumerate(exc.errors()[:5]):
        location = (
            ".".join(str(value) for value in error.get("loc", []) if value != "body") or "request"
        )
        details[f"field_{index + 1}"] = location[:128]
    return api_error_response(
        ApiError(422, ErrorCode.VALIDATION_ERROR, "Request validation failed."),
        details or None,
    )


def http_error_response(exc: StarletteHTTPException) -> JSONResponse:
    """Normalize framework routing errors without exposing raw internal implementation details."""
    if exc.status_code == 404:
        code = ErrorCode.NOT_FOUND
        message = str(exc.detail) if exc.detail and exc.detail != "Not Found" else "Requested resource was not found."
    elif exc.status_code == 401:
        code = ErrorCode.UNAUTHORIZED
        message = str(exc.detail) if exc.detail else "Authentication failed."
    elif exc.status_code == 403:
        code = ErrorCode.FORBIDDEN
        message = str(exc.detail) if exc.detail else "Access denied."
    elif exc.status_code in (400, 422):
        code = ErrorCode.VALIDATION_ERROR
        message = str(exc.detail) if exc.detail else "Request validation failed."
    else:
        code = ErrorCode.UNSUPPORTED_OPERATION
        message = str(exc.detail) if exc.detail else "Requested operation is not supported."
    return api_error_response(ApiError(exc.status_code, code, message))
