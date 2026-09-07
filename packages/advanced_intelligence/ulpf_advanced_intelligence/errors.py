"""Exception hierarchy for ULPF Phase 9 Advanced Security Analytics Plane."""

from __future__ import annotations


class AdvancedIntelligenceError(Exception):
    """Base exception for all Phase 9 errors."""


class ThreatIntelValidationError(AdvancedIntelligenceError):
    """Raised when an indicator or feed fails schema or normalization validation."""


class FeedIngestionError(AdvancedIntelligenceError):
    """Raised when a threat intelligence feed cannot be parsed or decoded."""


class IndicatorExpiredError(AdvancedIntelligenceError):
    """Raised when attempting to activate or match against an expired indicator."""


class ConflictDetectionError(AdvancedIntelligenceError):
    """Raised when detection rules or indicators contain unresolvable contradictions."""


class PathTraversalBoundError(AdvancedIntelligenceError):
    """Raised when attack path graph traversal exceeds configured depth or node limits."""


class QueryStructureError(AdvancedIntelligenceError):
    """Raised when structured analyst query AST contains invalid operators or cycles."""


class QueryResourceLimitError(AdvancedIntelligenceError):
    """Raised when query execution exceeds time window, record, or complexity caps."""


class EvidenceIntegrityError(AdvancedIntelligenceError):
    """Raised when forensic package checksums or backward lineage checks fail."""


class ActionExecutionError(AdvancedIntelligenceError):
    """Raised when an automated SOAR action fails execution."""


class IncidentWorkflowError(AdvancedIntelligenceError):
    """Raised when an illegal incident lifecycle transition or SLA violation occurs."""


class ModelGovernanceError(AdvancedIntelligenceError):
    """Raised when an unapproved or unsafe model artifact is invoked."""


class BaselineDriftError(AdvancedIntelligenceError):
    """Raised when an entity baseline has drifted and requires analyst-controlled reset."""
