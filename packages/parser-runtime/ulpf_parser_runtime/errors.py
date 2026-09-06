"""Structured, bounded error taxonomy for ULPF Phase 3 parsing and normalization.

Adheres to:
- Spec §37: Error Taxonomy
- Spec §71: Error Handling (no unhandled raw parser exceptions escape)
- Spec §116: Test Data Privacy (never leak raw secrets or raw payloads through error messages)
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class ErrorCode(StrEnum):
    """Authoritative, bounded error codes for parsing and normalization."""

    UNKNOWN_FORMAT = "UNKNOWN_FORMAT"
    UNKNOWN_SOURCE = "UNKNOWN_SOURCE"
    AMBIGUOUS_FORMAT = "AMBIGUOUS_FORMAT"
    AMBIGUOUS_SOURCE = "AMBIGUOUS_SOURCE"
    INVALID_ENCODING = "INVALID_ENCODING"
    MALFORMED_RECORD = "MALFORMED_RECORD"
    MALFORMED_JSON = "MALFORMED_JSON"
    MALFORMED_XML = "MALFORMED_XML"
    INVALID_CSV = "INVALID_CSV"
    INVALID_KV = "INVALID_KV"
    INVALID_SYSLOG = "INVALID_SYSLOG"
    INVALID_TIMESTAMP = "INVALID_TIMESTAMP"
    FIELD_TYPE_ERROR = "FIELD_TYPE_ERROR"
    SCHEMA_ERROR = "SCHEMA_ERROR"
    NORMALIZATION_ERROR = "NORMALIZATION_ERROR"
    OVERSIZED_RECORD = "OVERSIZED_RECORD"
    NESTING_LIMIT_EXCEEDED = "NESTING_LIMIT_EXCEEDED"
    MULTILINE_LIMIT_EXCEEDED = "MULTILINE_LIMIT_EXCEEDED"
    PARSER_TIMEOUT = "PARSER_TIMEOUT"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    SECURITY_POLICY_VIOLATION = "SECURITY_POLICY_VIOLATION"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class ErrorSeverity(StrEnum):
    """Operational severity of an error condition."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    FATAL = "fatal"


@dataclass(frozen=True, slots=True)
class ParseError:
    """Structured parse or normalization diagnostic.

    Safe for operator logs, metrics, DLQ events, and API error envelopes.
    Never stores untrusted raw payload bytes or credentials in the message.
    """

    code: ErrorCode
    stage: str
    message: str
    severity: ErrorSeverity = ErrorSeverity.ERROR
    recoverable: bool = False
    retryable: bool = False
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    details: dict[str, Any] = field(default_factory=dict)

    def to_contract_dict(self) -> dict[str, Any]:
        """Convert to JSON Schema compliant error definition (ulpf-common.v1.schema.json)."""
        return {
            "code": self.code.value,
            "stage": self.stage,
            "message": self.message[:4096],
            "recoverable": self.recoverable,
            "occurred_at": self.occurred_at.isoformat(),
        }


class ParserException(Exception):
    """Base exception for all internal parsing failures."""

    def __init__(self, parse_error: ParseError) -> None:
        super().__init__(f"[{parse_error.stage}] {parse_error.code}: {parse_error.message}")
        self.parse_error = parse_error


class OversizedRecordException(ParserException):
    """Record exceeds maximum allowed bytes."""


class NestingLimitExceededException(ParserException):
    """Structured record exceeds maximum allowed recursion depth."""


class ParserTimeoutException(ParserException):
    """Parsing operation exceeded allocated time budget."""


class SecurityPolicyViolationException(ParserException):
    """Input triggered security protection (e.g. XXE, ReDoS, injection)."""
