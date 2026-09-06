"""Structured logging with correlation tracking and secret redaction for ULPF Phase 6.

Enforces:
- Rule 46: Structured logs with correlation ID, stage, status, error code
- Rule 48: Secret and sensitive token redaction; no full sensitive payload dumping
"""

import json
import logging
import re
from datetime import UTC, datetime
from typing import Any

# Sensitive token patterns: passwords, api keys, auth tokens, secrets
_SECRET_PATTERNS = [
    re.compile(r"(?i)(password|secret|token|apikey|authorization)\s*[:=]\s*['\"]?([^'\"\s,]+)"),
    re.compile(r"(?i)bearer\s+([a-zA-Z0-9_\-\.=]+)"),
]


def redact_sensitive_text(text: str) -> str:
    """Redact passwords, bearer tokens, and secrets from log strings."""
    redacted = text
    for pat in _SECRET_PATTERNS:
        redacted = pat.sub(r"\1=[REDACTED]", redacted)
    return redacted


class StructuredJsonFormatter(logging.Formatter):
    """Formats log records as structured JSON with correlation IDs and redaction."""

    def format(self, record: logging.LogRecord) -> str:
        msg = redact_sensitive_text(record.getMessage())

        data: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "component": getattr(record, "component", record.name),
            "message": msg,
        }

        # Include operational correlation fields if attached to extra
        for field in (
            "correlation_id",
            "event_id",
            "stage",
            "status",
            "error_code",
            "duration_ms",
            "source",
        ):
            if hasattr(record, field):
                data[field] = getattr(record, field)

        if record.exc_info and record.exc_text:
            data["exception"] = redact_sensitive_text(record.exc_text)

        return json.dumps(data)
