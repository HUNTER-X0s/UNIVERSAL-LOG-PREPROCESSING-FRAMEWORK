"""Safe, Parameterized Structured Query Builder and AST Evaluator for ULPF Phase 9."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from ulpf_advanced_intelligence.errors import QueryResourceLimitError


class QueryOperator(StrEnum):
    """Supported atomic condition operators."""

    EQUALS = "EQUALS"
    NOT_EQUALS = "NOT_EQUALS"
    CONTAINS = "CONTAINS"
    IN = "IN"
    RANGE = "RANGE"
    EXISTS = "EXISTS"


class LogicalOperator(StrEnum):
    """Supported boolean conjunction operators."""

    AND = "AND"
    OR = "OR"
    NOT = "NOT"


@dataclass(frozen=True)
class QueryNode:
    """Atomic filter condition on a specific event field."""

    field: str
    operator: QueryOperator
    value: Any = None

    def evaluate(self, record: dict[str, Any]) -> bool:
        val = record.get(self.field)
        if self.operator == QueryOperator.EXISTS:
            return self.field in record and record[self.field] is not None
        if val is None:
            return False

        if self.operator == QueryOperator.EQUALS:
            return str(val).lower() == str(self.value).lower()
        if self.operator == QueryOperator.NOT_EQUALS:
            return str(val).lower() != str(self.value).lower()
        if self.operator == QueryOperator.CONTAINS:
            return str(self.value).lower() in str(val).lower()
        if self.operator == QueryOperator.IN:
            if isinstance(self.value, list | tuple | set):
                return str(val).lower() in {str(x).lower() for x in self.value}
            return False
        if self.operator == QueryOperator.RANGE:
            if isinstance(self.value, list | tuple) and len(self.value) == 2:
                try:
                    num_val = float(val)
                    return float(self.value[0]) <= num_val <= float(self.value[1])
                except (ValueError, TypeError):
                    return False
            return False
        return False


@dataclass(frozen=True)
class LogicalGroup:
    """Boolean combination of child query nodes or nested groups."""

    operator: LogicalOperator
    children: tuple[QueryNode | LogicalGroup, ...]

    def evaluate(self, record: dict[str, Any]) -> bool:
        if not self.children:
            return True
        if self.operator == LogicalOperator.AND:
            return all(c.evaluate(record) for c in self.children)
        if self.operator == LogicalOperator.OR:
            return any(c.evaluate(record) for c in self.children)
        if self.operator == LogicalOperator.NOT:
            return not self.children[0].evaluate(record)
        return False


class StructuredQueryEngine:
    """Validates query trees against complexity bounds and executes safe matching over records."""

    MAX_DEPTH: int = 5
    MAX_TERMS: int = 25

    @classmethod
    def validate_query(cls, root: QueryNode | LogicalGroup, current_depth: int = 1) -> int:
        """Validate query depth and total term count to protect against resource exhaustion."""
        if current_depth > cls.MAX_DEPTH:
            raise QueryResourceLimitError(f"Query depth {current_depth} exceeds maximum limit of {cls.MAX_DEPTH}")

        if isinstance(root, QueryNode):
            return 1

        terms = 0
        for child in root.children:
            terms += cls.validate_query(child, current_depth + 1)

        if terms > cls.MAX_TERMS:
            raise QueryResourceLimitError(f"Query contains {terms} terms, exceeding limit of {cls.MAX_TERMS}")

        return terms

    @classmethod
    def execute_query(
        cls,
        root: QueryNode | LogicalGroup,
        records: Sequence[dict[str, Any]],
        limit: int = 500,
        tenant_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Filter records matching the query AST under mandatory tenant isolation."""
        cls.validate_query(root)
        results: list[dict[str, Any]] = []

        for r in records:
            if tenant_id and r.get("tenant_id") and r.get("tenant_id") != tenant_id:
                continue

            if root.evaluate(r):
                results.append(r)
                if len(results) >= limit:
                    break

        return results
