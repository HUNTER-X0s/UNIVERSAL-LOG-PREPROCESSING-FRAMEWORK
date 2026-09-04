"""Read-only validation against the frozen Phase 0 JSON Schema contracts."""

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource


@dataclass(frozen=True, slots=True)
class ValidationResult:
    """Result returned instead of allowing callers to ignore validation failures."""

    valid: bool
    errors: tuple[str, ...]


class ContractRegistry:
    """Loads existing schemas without copying their semantics into code."""

    def __init__(self, schema_directory: Path | None = None) -> None:
        configured_directory = os.getenv("ULPF_CONTRACTS_DIR")
        default_directory = self._default_schema_directory()
        self._schema_directory = (
            Path(configured_directory)
            if configured_directory
            else schema_directory or default_directory
        )
        self._schemas = self._load_schemas()
        self._registry = Registry().with_resources(
            (schema["$id"], Resource.from_contents(schema)) for schema in self._schemas.values()
        )

    @property
    def names(self) -> tuple[str, ...]:
        """Return stable schema filenames in deterministic order."""
        return tuple(sorted(self._schemas))

    def validate(self, name: str, instance: Any) -> ValidationResult:
        """Validate an instance using the authoritative frozen contract."""
        schema = self._schemas[name]
        validator = Draft202012Validator(
            schema, registry=self._registry, format_checker=FormatChecker()
        )
        errors = tuple(
            sorted((error.message for error in validator.iter_errors(instance)), key=str)
        )
        return ValidationResult(valid=not errors, errors=errors)

    def check_schemas(self) -> None:
        """Raise immediately when a stored contract itself is invalid."""
        for schema in self._schemas.values():
            Draft202012Validator.check_schema(schema)

    def _load_schemas(self) -> dict[str, dict[str, Any]]:
    @staticmethod
    def _default_schema_directory() -> Path:
        """Resolve source-tree schemas first, then a container/check-out working directory."""
        source_tree_candidate = (
            Path(__file__).resolve().parents[3] / "contracts" / "jsonschema"
        )
        working_directory_candidate = Path.cwd() / "contracts" / "jsonschema"
        for candidate in (source_tree_candidate, working_directory_candidate):
            if candidate.is_dir():
                return candidate
        return source_tree_candidate

        if not self._schema_directory.is_dir():
            raise FileNotFoundError(
                f"ULPF contract directory does not exist: {self._schema_directory}"
            )
        schemas: dict[str, dict[str, Any]] = {}
        for path in sorted(self._schema_directory.glob("*.json")):
            with path.open(encoding="utf-8") as schema_file:
                schema = json.load(schema_file)
            if "$id" not in schema:
                raise ValueError(f"ULPF schema has no $id: {path.name}")
            schemas[path.name] = schema
        if not schemas:
            raise ValueError("ULPF contract directory contains no JSON Schemas")
        return schemas
