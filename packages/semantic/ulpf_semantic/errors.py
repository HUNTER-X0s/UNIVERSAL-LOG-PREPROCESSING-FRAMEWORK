"""ULPF Phase 4 Semantic Intelligence Error Taxonomy.

Strict taxonomy of error codes, severities, and sanitization utilities
preventing sensitive data leakage in diagnostics.
"""

from dataclasses import dataclass
from enum import Enum


class SemanticErrorCode(str, Enum):
    """Controlled error codes for semantic processing and projections."""

    SEMANTIC_MAPPING_ERROR = "SEMANTIC_MAPPING_ERROR"
    UNKNOWN_EVENT_TYPE = "UNKNOWN_EVENT_TYPE"
    AMBIGUOUS_SEMANTICS = "AMBIGUOUS_SEMANTICS"
    ENTITY_EXTRACTION_ERROR = "ENTITY_EXTRACTION_ERROR"
    RELATIONSHIP_ERROR = "RELATIONSHIP_ERROR"
    INDICATOR_ERROR = "INDICATOR_ERROR"
    OCSF_MAPPING_ERROR = "OCSF_MAPPING_ERROR"
    OTEL_MAPPING_ERROR = "OTEL_MAPPING_ERROR"
    PROJECTION_VALIDATION_ERROR = "PROJECTION_VALIDATION_ERROR"
    TAXONOMY_VERSION_ERROR = "TAXONOMY_VERSION_ERROR"
    MAPPING_VERSION_ERROR = "MAPPING_VERSION_ERROR"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    SECURITY_POLICY_VIOLATION = "SECURITY_POLICY_VIOLATION"
    UNSUPPORTED_PROJECTION = "UNSUPPORTED_PROJECTION"
    UNSUPPORTED_EVENT_CLASS = "UNSUPPORTED_EVENT_CLASS"
    MISSING_REQUIRED_FIELD = "MISSING_REQUIRED_FIELD"


class ErrorSeverity(str, Enum):
    """Severity classification for semantic and projection errors."""

    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class SemanticError(Exception):
    """Structured error object for semantic interpretation and projection failures."""

    code: SemanticErrorCode
    stage: str
    message: str
    severity: ErrorSeverity = ErrorSeverity.ERROR
    recoverable: bool = True
    context: str | None = None

    def __str__(self) -> str:
        return f"[{self.stage}:{self.code.value}] {self.message}"

    def to_dict(self) -> dict[str, str]:
        """Convert error to contract dictionary with sanitized message."""
        d = {
            "code": self.code.value,
            "stage": self.stage,
            "message": self._sanitize(self.message),
            "severity": self.severity.value,
        }
        if self.context:
            d["context"] = self._sanitize(self.context)
        return d

    @staticmethod
    def _sanitize(msg: str) -> str:
        """Sanitize error messages to truncate excessive length and scrub patterns."""
        if len(msg) > 512:
            msg = msg[:509] + "..."
        return msg
