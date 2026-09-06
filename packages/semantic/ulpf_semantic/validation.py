"""Schema Validation for ULPF Phase 4 Semantic Events.

Validates SemanticEvent contract dictionaries against:
packages/semantic/ulpf_semantic/schemas/semantic-event.v1.schema.json
"""

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from ulpf_contracts.registry import ValidationResult

SCHEMA_PATH = Path(__file__).resolve().parent / "schemas" / "semantic-event.v1.schema.json"


class SemanticEventValidator:
    """Validates SemanticEvent dictionary instances against authoritative JSON schemas."""

    def __init__(self, schema_file: Path | None = None) -> None:
        path = schema_file or SCHEMA_PATH
        schema_dict = json.loads(path.read_text(encoding="utf-8"))
        self._validator = Draft202012Validator(schema_dict)

    def validate_semantic(self, instance: dict[str, Any]) -> ValidationResult:
        """Validate a SemanticEvent instance against semantic-event.v1.schema.json."""
        errors: list[str] = []
        for err in self._validator.iter_errors(instance):
            loc = ".".join(str(p) for p in err.absolute_path) or "$"
            errors.append(f"{loc}: {err.message}")

        return ValidationResult(
            valid=len(errors) == 0,
            errors=tuple(errors),
        )
