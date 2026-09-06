"""Validation service for normalized and canonical telemetry events.

Adheres to:
- Spec §33: Universal Canonical Event (UCE) Schema
- Spec §72: Schema Validation
- Contracts: contracts/jsonschema/normalized-event.v1.schema.json
"""

from typing import Any

from ulpf_contracts.registry import ContractRegistry, ValidationResult

CANONICAL_SCHEMA_NAME = "normalized-event.v1.schema.json"
PARSED_SCHEMA_NAME = "parsed-event.v1.schema.json"


class CanonicalEventValidator:
    """Validates Universal Canonical Event dictionary instances against JSON schemas."""

    def __init__(self, registry: ContractRegistry | None = None) -> None:
        self._registry = registry or ContractRegistry()

    def validate_canonical(self, instance: dict[str, Any]) -> ValidationResult:
        """Validate a NormalizedEvent instance against normalized-event.v1.schema.json."""
        return self._registry.validate(CANONICAL_SCHEMA_NAME, instance)

    def validate_parsed(self, instance: dict[str, Any]) -> ValidationResult:
        """Validate a ParsedEvent instance against parsed-event.v1.schema.json."""
        return self._registry.validate(PARSED_SCHEMA_NAME, instance)
