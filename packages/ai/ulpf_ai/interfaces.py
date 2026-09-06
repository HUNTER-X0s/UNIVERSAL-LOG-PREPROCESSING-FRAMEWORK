"""Abstract AI Advisor Interface for ULPF Phase 5.

Guarantees:
- AI is optional and exists exclusively on the onboarding side
- Zero runtime hot-path execution
- All outputs are treated as untrusted candidates requiring human approval
- Full offline capability
"""

from abc import ABC, abstractmethod
from typing import Any

from ulpf_ai.models import AISuggestion, FieldSemanticsSuggestion


class AISemanticAdvisor(ABC):
    """Abstract interface for offline or local AI semantic onboarding advisors."""

    @property
    @abstractmethod
    def provider_id(self) -> str:
        """Unique identifier for this AI provider."""

    @property
    @abstractmethod
    def model_version(self) -> str:
        """Model or heuristic version identifier."""

    @abstractmethod
    def infer_field_semantics(
        self,
        field_name: str,
        sample_values: list[Any],
        context: dict[str, Any] | None = None,
    ) -> FieldSemanticsSuggestion:
        """Suggest canonical field target and data type for an unmapped field."""

    @abstractmethod
    def suggest_mapping(
        self,
        sample_events: list[dict[str, Any]],
        source_hint: dict[str, Any] | None = None,
    ) -> AISuggestion:
        """Generate a candidate semantic mapping definition from sample logs."""

    @abstractmethod
    def explain_suggestion(
        self,
        candidate_mapping: dict[str, Any],
    ) -> str:
        """Generate human-readable rationale for an onboarding suggestion."""
