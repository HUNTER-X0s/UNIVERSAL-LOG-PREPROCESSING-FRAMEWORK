"""HTTP safety, headers, and correlation middleware for the API shell."""

from time import monotonic

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response
from starlette.types import ASGIApp

from ulpf_platform.config import AppSettings
from ulpf_platform.correlation import build_context, reset_request_context, set_request_context
from ulpf_platform.errors import ApiError, ErrorCode, api_error_response
from ulpf_platform.logging import get_logger


class FoundationMiddleware(BaseHTTPMiddleware):
    """Enforce bounded request metadata before future input routes are added."""

    def __init__(self, app: ASGIApp, settings: AppSettings) -> None:
        super().__init__(app)
        self._settings = settings
        self._logger = get_logger("api.middleware")

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        content_length = request.headers.get("content-length")
        if (
            content_length
            and content_length.isdigit()
            and int(content_length) > self._settings.request_max_bytes
        ):
            return api_error_response(
                ApiError(
                    413, ErrorCode.REQUEST_TOO_LARGE, "Request body exceeds the configured limit."
                )
            )
        header_bytes = sum(len(name) + len(value) + 4 for name, value in request.headers.items())
        if header_bytes > self._settings.intake_max_http_header_bytes:
            return api_error_response(
                ApiError(
                    431,
                    ErrorCode.INTAKE_HEADERS_TOO_LARGE,
                    "Request headers exceed the configured limit.",
                )
            )
        trace_id = request.headers.get("x-trace-id")
        context = build_context(
            request.headers.get("x-request-id"), request.headers.get("x-correlation-id"), trace_id
        )
        token = set_request_context(context)
        started_at = monotonic()
        try:
            response = await call_next(request)
        finally:
            elapsed_ms = round((monotonic() - started_at) * 1000, 2)
            self._logger.info(
                "request_completed",
                extra={"component": "api", "duration_ms": elapsed_ms},
            )
            reset_request_context(token)
        response.headers["X-Request-ID"] = context.request_id
        response.headers["X-Correlation-ID"] = context.correlation_id
        response.headers["X-Trace-ID"] = context.trace_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response
