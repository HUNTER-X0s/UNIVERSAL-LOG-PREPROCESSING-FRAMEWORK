"""Structured application logging without raw payload or secret emission."""

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

from ulpf_platform.config import AppSettings
from ulpf_platform.correlation import request_context


class JsonFormatter(logging.Formatter):
    """Emit the small, stable JSON log schema required by Phase 1."""

    def format(self, record: logging.LogRecord) -> str:
        context = request_context()
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "service": getattr(record, "service", "ulpf-api"),
            "environment": getattr(record, "environment", "development"),
            "message": record.getMessage(),
            "request_id": context.request_id,
            "correlation_id": context.correlation_id,
            "trace_id": context.trace_id,
            "error_code": getattr(record, "error_code", None),
            "component": getattr(record, "component", record.name),
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str)


def configure_logging(settings: AppSettings) -> None:
    """Configure one stdout handler suitable for container and local collection."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(settings.log_level)


def get_logger(component: str) -> logging.Logger:
    """Return a named logger; contextual values are attached by the formatter."""
    return logging.getLogger(component)
