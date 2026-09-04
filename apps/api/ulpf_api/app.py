"""FastAPI composition root for the Phase 2 raw-intake service."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from ulpf_ingestion.runtime import IntakeRuntime
from ulpf_platform.config import AppSettings, get_settings
from ulpf_platform.errors import (
    ApiError,
    api_error_response,
    http_error_response,
    validation_error_response,
)
from ulpf_platform.logging import configure_logging, get_logger
from ulpf_platform.middleware import FoundationMiddleware

from ulpf_api.routes.foundation import router as foundation_router
from ulpf_api.routes.intake import router as intake_router


def create_app(settings: AppSettings | None = None) -> FastAPI:
    """Create the API with raw capture and without parser or stream dependencies."""
    resolved_settings = settings or get_settings()
    configure_logging(resolved_settings)
    logger = get_logger("api.lifecycle")
    intake_runtime = IntakeRuntime(resolved_settings)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        await intake_runtime.start()
        logger.info("service_started", extra={"component": "api"})
        try:
            yield
        finally:
            await intake_runtime.stop()

            logger.info("service_stopped", extra={"component": "api"})
    app = FastAPI(
        title="ULPF Raw Intake API",
        description="Phase 2 opaque raw-event capture; parsing and normalization are deferred.",
        version="0.1.0",
        docs_url=f"{resolved_settings.api_prefix}/docs"
        if resolved_settings.api_documentation_enabled
        else None,
        openapi_url=f"{resolved_settings.api_prefix}/openapi.json",
        redoc_url=None,
        lifespan=lifespan,
    )
    app.state.settings = resolved_settings
    app.state.intake_runtime = intake_runtime
    app.add_middleware(FoundationMiddleware, settings=resolved_settings)
    app.include_router(foundation_router, prefix=resolved_settings.api_prefix)
    app.include_router(intake_router, prefix=resolved_settings.api_prefix)

    @app.exception_handler(ApiError)
    async def handle_api_error(_: Request, exc: ApiError) -> JSONResponse:
        return api_error_response(exc)

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return validation_error_response(request, exc)

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        return http_error_response(exc)

    @app.exception_handler(Exception)
    async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        logger.exception(
            "unhandled_request_error", extra={"component": "api", "error_code": "internal_error"}
        )
        return api_error_response(ApiError.internal(request=request, cause=exc))

    return app


app = create_app()
