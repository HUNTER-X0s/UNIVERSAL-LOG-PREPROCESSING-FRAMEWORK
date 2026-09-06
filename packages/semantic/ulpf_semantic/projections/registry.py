"""Projection Registry for ULPF Phase 4.

Coordinates dynamic discovery, registration, and dispatch for all output projections.
"""

from typing import Any

from ulpf_semantic.errors import SemanticError, SemanticErrorCode
from ulpf_semantic.models import SemanticEvent
from ulpf_semantic.projections.base import BaseProjection, ProjectionResult
from ulpf_semantic.projections.ocsf.mapper import OCSFProjection
from ulpf_semantic.projections.otel.mapper import OTelProjection


class ProjectionRegistry:
    """Registry maintaining available output projections."""

    def __init__(self) -> None:
        self._projections: dict[str, BaseProjection] = {}

    def register(self, projection: BaseProjection) -> None:
        """Register a projection engine."""
        self._projections[projection.projection_id] = projection

    def lookup(self, projection_id: str) -> BaseProjection:
        """Look up a projection by ID or raise SemanticError."""
        if projection_id not in self._projections:
            raise SemanticError(
                code=SemanticErrorCode.UNSUPPORTED_PROJECTION,
                stage="projection_registry",
                message=f"Projection '{projection_id}' is not registered",
            )
        return self._projections[projection_id]

    def list_projections(self) -> tuple[str, ...]:
        """Return deterministic tuple of registered projection IDs."""
        return tuple(sorted(self._projections.keys()))

    def project_all(
        self,
        semantic_event: SemanticEvent,
        uce_event: dict[str, Any],
    ) -> dict[str, ProjectionResult]:
        """Execute all registered projections safely with isolation guarantees."""
        results: dict[str, ProjectionResult] = {}
        for pid in sorted(self._projections.keys()):
            proj = self._projections[pid]
            try:
                res = proj.project(semantic_event, uce_event)
                results[pid] = res
            except Exception as exc:
                from ulpf_semantic.projections.base import ProjectionStatus

                results[pid] = ProjectionResult(
                    projection_id=pid,
                    version=proj.version,
                    status=ProjectionStatus.FAILED,
                    output={},
                    errors=(f"Projection execution failed: {str(exc)[:256]}",),
                )
        return results


def create_default_projection_registry() -> ProjectionRegistry:
    """Create and configure a ProjectionRegistry with standard OCSF and OTel engines."""
    reg = ProjectionRegistry()
    reg.register(OCSFProjection())
    reg.register(OTelProjection())
    return reg
