"""Typed error hierarchy for ULPF Phase 5 Mapping Plane."""


class MappingError(Exception):
    """Base exception for all mapping-related errors."""


class MappingSchemaError(MappingError):
    """Raised when a mapping definition fails JSON schema validation."""


class MappingSafetyError(MappingError):
    """Raised when an unsafe construct (ReDoS, code execution attempt) is detected."""


class MappingConflictError(MappingError):
    """Raised when a mapping conflicts with or shadows another active mapping."""


class MappingCompilationError(MappingError):
    """Raised when compilation of a mapping DSL fails."""


class MappingActivationError(MappingError):
    """Raised when activating a mapping fails due to unapproved state or policy violation."""


class MappingCompatibilityError(MappingError):
    """Raised when a mapping is backward-incompatible with existing contracts."""


class MappingRollbackError(MappingError):
    """Raised when rollback of a mapping fails."""
