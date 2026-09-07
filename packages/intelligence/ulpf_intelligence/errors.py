"""Domain exceptions for ULPF Phase 8 Intelligence Plane."""

from __future__ import annotations


class IntelligenceError(Exception):
    """Base exception for all intelligence plane operations."""


class RuleValidationError(IntelligenceError):
    """Raised when a detection rule definition is invalid or unsafe."""


class RuleExecutionError(IntelligenceError):
    """Raised when a rule cannot be evaluated against an event."""


class CorrelationError(IntelligenceError):
    """Raised when event correlation processing fails."""


class AnomalyComputationError(IntelligenceError):
    """Raised when statistical anomaly baseline calculation fails."""


class RiskComputationError(IntelligenceError):
    """Raised when risk score calculation encounters an error."""


class GraphError(IntelligenceError):
    """Raised when entity graph operations encounter an error."""


class CycleDetectedError(GraphError):
    """Raised when a circular graph dependency is detected where forbidden."""


class GraphDepthExceededError(GraphError):
    """Raised when graph query exceeds maximum traversal depth."""


class HuntingQueryError(IntelligenceError):
    """Raised when a threat hunting query is malformed or invalid."""


class QueryResourceLimitExceededError(HuntingQueryError):
    """Raised when a query exceeds time window or result count limits."""


class CaseStateError(IntelligenceError):
    """Raised when an invalid investigation case state transition is attempted."""


class ModelGovernanceError(IntelligenceError):
    """Raised when model lifecycle or validation rules are breached."""


class EnrichmentError(IntelligenceError):
    """Raised when an enrichment provider fails."""
