"""Base Output Projection Interface and Result Models for ULPF Phase 4.

Defines the contract for all outbound projection engines (OCSF, OpenTelemetry, Analytics).
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ulpf_semantic.models import SemanticEvent


class ProjectionStatus(str, Enum):
    """Validation and execution status of an outbound projection."""

    VALID = "VALID"
    PARTIAL = "PARTIAL"
    INVALID = "INVALID"
    UNSUPPORTED_CLASS = "UNSUPPORTED_CLASS"
    FAILED = "FAILED"


@dataclass(frozen=True)
class ProjectionResult:
    """Encapsulates the result of projecting a SemanticEvent to an external schema."""

    projection_id: str
    version: str
    status: ProjectionStatus
    output: dict[str, Any]
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "projection_id": self.projection_id,
            "version": self.version,
            "status": self.status.value,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "output": self.output,
            "metadata": self.metadata,
        }


class BaseProjection(ABC):
    """Abstract base class for all standard schema output projections."""

    projection_id: str
    version: str

    @abstractmethod
    def project(
        self,
        semantic_event: SemanticEvent,
        uce_event: dict[str, Any],
    ) -> ProjectionResult:
        """Project a SemanticEvent and raw UCE into the target schema."""
        pass
