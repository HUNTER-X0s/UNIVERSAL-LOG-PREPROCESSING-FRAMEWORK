"""Mapping Compiler for ULPF Phase 5.

Compiles declarative MappingDefinition models into immutable, deterministic
executable CompiledMapping structures with static safety analysis and SHA-256 verification.
"""

import hashlib
import json
from pathlib import Path
from typing import Any

import jsonschema

from ulpf_mapping.dsl.operators import (
    evaluate_condition,
    get_nested_field,
    validate_regex_safety,
)
from ulpf_mapping.errors import (
    MappingCompilationError,
    MappingSafetyError,
    MappingSchemaError,
)
from ulpf_mapping.models import (
    CompiledMapping,
    MappingDefinition,
)


class MappingCompiler:
    """Compiles declarative mapping definitions into deterministic executable objects."""

    def __init__(self, schema_path: Path | None = None) -> None:
        if schema_path is None:
            # Default schema path
            schema_path = (
                Path(__file__).resolve().parent.parent.parent.parent.parent
                / "contracts"
                / "jsonschema"
                / "semantic-mapping.v1.schema.json"
            )
        self.schema_path = schema_path
        self._schema: dict[str, Any] | None = None

    def _get_schema(self) -> dict[str, Any]:
        if self._schema is None:
            if not self.schema_path.exists():
                raise MappingCompilationError(
                    f"Mapping JSON Schema not found at {self.schema_path}"
                )
            with open(self.schema_path, encoding="utf-8") as f:
                self._schema = json.load(f)
        return self._schema

    def validate_schema(self, mapping_dict: dict[str, Any]) -> None:
        """Validate mapping dictionary against official JSON schema contract."""
        schema = self._get_schema()
        try:
            jsonschema.validate(instance=mapping_dict, schema=schema)
        except jsonschema.ValidationError as e:
            raise MappingSchemaError(f"Schema validation failed: {e.message}") from e

    def compute_checksum(self, mapping_def: MappingDefinition) -> str:
        """Calculate canonical, deterministic SHA-256 digest over mapping definition."""
        d = mapping_def.to_dict()
        d.pop("checksum", None)
        canonical_json = json.dumps(d, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    def compile(
        self,
        mapping_def: MappingDefinition | dict[str, Any] | None = None,
    ) -> CompiledMapping:
        """Compile a MappingDefinition or dict into an immutable, executable CompiledMapping."""
        if mapping_def is None and isinstance(self, MappingDefinition | dict):
            inst = MappingCompiler()
            return inst.compile(self)

        inst = self
        target_spec = mapping_def
        if isinstance(target_spec, dict):
            inst.validate_schema(target_spec)
            mdef = MappingDefinition.from_dict(target_spec)
        elif isinstance(target_spec, MappingDefinition):
            mdef = target_spec
            inst.validate_schema(mdef.to_dict())
        else:
            raise MappingCompilationError(f"Invalid mapping specification: {type(target_spec)}")

        # 2. Static Safety Analysis
        if mdef.match.conditions:
            for cond in mdef.match.conditions:
                if cond.op in ("regex_bounded", "regex_match"):
                    if not isinstance(cond.value, str):
                        raise MappingSafetyError(
                            f"{cond.op} condition requires string value, got {type(cond.value)}"
                        )
                    validate_regex_safety(cond.value)

        # 3. Compute Checksum
        csum = inst.compute_checksum(mdef)
        mdef.checksum = csum

        # 4. Generate Deterministic Matching Function
        match_criteria = mdef.match

        def match_fn(uce_event: dict[str, Any]) -> bool:
            ev = uce_event.get("event", {})
            meta = ev.get("metadata", {}) if isinstance(ev, dict) else {}

            # Vendor match
            if match_criteria.vendor:
                v = meta.get("vendor") or uce_event.get("observer", {}).get("vendor")
                if not v or str(v).lower() != match_criteria.vendor.lower():
                    return False

            # Product match
            if match_criteria.product:
                p = meta.get("product") or uce_event.get("observer", {}).get("product")
                if not p or str(p).lower() != match_criteria.product.lower():
                    return False

            # Parser ID match
            if match_criteria.parser_id:
                pid = meta.get("parser_id")
                if not pid or str(pid).lower() != match_criteria.parser_id.lower():
                    return False

            # Event type match
            if match_criteria.event_type:
                et = ev.get("type") or ev.get("category")
                if not et or str(et).lower() != match_criteria.event_type.lower():
                    return False

            # Conditions match
            if match_criteria.conditions:
                for cond in match_criteria.conditions:
                    actual_val = get_nested_field(uce_event, cond.field)
                    if not evaluate_condition(actual_val, cond.op, cond.value):
                        return False

            return True

        return CompiledMapping(
            mapping_id=mdef.mapping_id,
            version=mdef.version,
            priority=mdef.priority,
            confidence=mdef.confidence,
            provenance=mdef.provenance,
            semantic=mdef.semantic,
            checksum=csum,
            field_mappings=tuple(mdef.field_mappings),
            entity_rules=tuple(mdef.entity_rules),
            indicator_rules=tuple(mdef.indicator_rules),
            match_fn=match_fn,
        )
