"""Semantic Processing Service for ULPF Phase 4.

Coordinates the end-to-end semantic pipeline:
UCE -> Semantic Interpretation -> Entity/Relationship Graph -> Outbound Projections (OCSF, OTel).
"""

from typing import Any

from ulpf_semantic.mapping.engine import SemanticMapper
from ulpf_semantic.models import SemanticEvent
from ulpf_semantic.projections.registry import (
    ProjectionRegistry,
    create_default_projection_registry,
)
from ulpf_semantic.validation import SemanticEventValidator


class SemanticService:
    """End-to-end service interface for semantic intelligence and outbound projections."""

    def __init__(
        self,
        mapper: SemanticMapper | None = None,
        projection_registry: ProjectionRegistry | None = None,
        validator: SemanticEventValidator | None = None,
        registry: Any = None,
    ) -> None:
        self.mapper = mapper or SemanticMapper(registry=registry)
        self.projection_registry = projection_registry or create_default_projection_registry()
        self.validator = validator or SemanticEventValidator()

    def process_uce(
        self,
        uce_event: dict[str, Any],
        project: bool = True,
    ) -> SemanticEvent:
        """Process a single UCE dictionary into an explainable SemanticEvent with projections."""
        # 1. Map UCE to SemanticEvent
        sem_event = self.mapper.map_uce_to_semantic(uce_event)

        # 2. Execute Outbound Projections (Isolation Guaranteed)
        if project:
            proj_results = self.projection_registry.project_all(sem_event, uce_event)
            for pid, res in proj_results.items():
                sem_event.projections[pid] = res.to_dict()

        return sem_event

    def process_batch(
        self,
        uce_events: list[dict[str, Any]],
        project: bool = True,
    ) -> list[SemanticEvent]:
        """Process a bounded batch of UCE records sequentially with no cross-event mutation."""
        return [self.process_uce(ev, project=project) for ev in uce_events]
