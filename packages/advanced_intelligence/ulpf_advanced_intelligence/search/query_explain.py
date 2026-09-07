"""Query Explanation and Cost Estimation Plan for ULPF Phase 9."""

from __future__ import annotations

from dataclasses import dataclass

from ulpf_advanced_intelligence.search.query_builder import (
    LogicalGroup,
    QueryNode,
    StructuredQueryEngine,
)


@dataclass(frozen=True)
class QueryExplainPlan:
    """Safe, non-sensitive execution explanation for an analyst structured query."""

    depth: int
    total_terms: int
    filtered_fields: tuple[str, ...]
    estimated_complexity: str  # LOW, MEDIUM, HIGH
    tenant_enforced: bool
    explanation_summary: str


class QueryExplainer:
    """Produces explainable execution plan for structured queries without exposing database internals."""

    @classmethod
    def explain(
        cls,
        root: QueryNode | LogicalGroup,
        tenant_id: str | None = None,
    ) -> QueryExplainPlan:
        terms = StructuredQueryEngine.validate_query(root)
        fields: list[str] = []
        cls._collect_fields(root, fields)

        complexity = "LOW"
        if terms > 15:
            complexity = "HIGH"
        elif terms > 5:
            complexity = "MEDIUM"

        return QueryExplainPlan(
            depth=cls._measure_depth(root),
            total_terms=terms,
            filtered_fields=tuple(sorted(set(fields))),
            estimated_complexity=complexity,
            tenant_enforced=tenant_id is not None,
            explanation_summary=(
                f"Query executes across {len(set(fields))} fields ({', '.join(sorted(set(fields))[:5])}) "
                f"with {terms} predicate(s) and {complexity} estimated resource overhead."
            ),
        )

    @classmethod
    def _collect_fields(cls, node: QueryNode | LogicalGroup, fields: list[str]) -> None:
        if isinstance(node, QueryNode):
            fields.append(node.field)
        elif isinstance(node, LogicalGroup):
            for c in node.children:
                cls._collect_fields(c, fields)

    @classmethod
    def _measure_depth(cls, node: QueryNode | LogicalGroup, current: int = 1) -> int:
        if isinstance(node, QueryNode):
            return current
        if not node.children:
            return current
        return max(cls._measure_depth(c, current + 1) for c in node.children)
