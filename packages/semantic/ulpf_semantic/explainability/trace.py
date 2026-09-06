"""Structured Explainability and Decision Trace for ULPF Phase 4.

Provides detailed reasoning for every semantic classification, action mapping,
and projection decision.
"""

from ulpf_semantic.models import DecisionTrace, SemanticProvenance


class DecisionTraceBuilder:
    """Builder for explainable semantic decision traces."""

    @staticmethod
    def build(
        rule_id: str,
        rule_version: str = "1.0.0",
        mapping_id: str = "ulpf.semantic.map.v1",
        provenance_type: SemanticProvenance = SemanticProvenance.DERIVED,
        evidence: tuple[str, ...] = (),
        explanation: str | None = None,
    ) -> DecisionTrace:
        """Construct an immutable DecisionTrace instance."""
        return DecisionTrace(
            rule_id=rule_id,
            rule_version=rule_version,
            mapping_id=mapping_id,
            provenance_type=provenance_type,
            evidence=evidence,
            explanation=explanation,
        )
