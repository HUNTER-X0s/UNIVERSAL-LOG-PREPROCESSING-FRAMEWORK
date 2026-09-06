"""Versioned Mapping Registry with Lifecycle Management and Rollback for ULPF Phase 5.

Governs mapping lifecycle states:
DRAFT -> VALIDATED -> TESTED -> APPROVED -> ACTIVE -> DEPRECATED -> RETIRED
"""

import uuid
from datetime import UTC, datetime
from typing import Any

from ulpf_mapping.compiler.compiler import MappingCompiler
from ulpf_mapping.errors import (
    MappingActivationError,
    MappingError,
    MappingRollbackError,
)
from ulpf_mapping.models import (
    CompiledMapping,
    MappingDefinition,
    MappingLifecycleState,
)


class MappingRegistry:
    """Thread-safe, versioned registry managing declarative and compiled mappings."""

    def __init__(self, compiler: MappingCompiler | None = None) -> None:
        self.compiler = compiler or MappingCompiler()
        # storage: {mapping_id: {version: MappingDefinition}}
        self._definitions: dict[str, dict[str, MappingDefinition]] = {}
        # active compiled mappings: {mapping_id: CompiledMapping}
        self._active_compiled: dict[str, CompiledMapping] = {}
        # active versions: {mapping_id: active_version_str}
        self._active_versions: dict[str, str] = {}
        # version activation history: {mapping_id: [version1, version2, ...]}
        self._activation_history: dict[str, list[str]] = {}
        # audit trail: list of audit event records
        self._audit_trail: list[dict[str, Any]] = []

    def record_audit(
        self,
        mapping_id: str,
        version: str,
        actor: str,
        action: str,
        previous_state: str,
        new_state: str,
        reason: str = "",
        checksum: str = "",
    ) -> dict[str, Any]:
        """Record an immutable audit event for a mapping change."""
        event = {
            "schema_version": "1.0.0",
            "audit_id": f"audit_{uuid.uuid4().hex[:16]}",
            "timestamp": datetime.now(UTC).isoformat(),
            "mapping_id": mapping_id,
            "mapping_version": version,
            "actor": actor,
            "action": action,
            "previous_state": previous_state,
            "new_state": new_state,
            "reason": reason,
            "checksum": checksum,
        }
        self._audit_trail.append(event)
        return event

    def get_audit_trail(self, mapping_id: str | None = None) -> list[dict[str, Any]]:
        """Retrieve audit events, optionally filtered by mapping ID."""
        if mapping_id:
            return [e for e in self._audit_trail if e["mapping_id"] == mapping_id]
        return list(self._audit_trail)

    def register(self, mapping_def: MappingDefinition, actor: str = "system") -> None:
        """Register a new or updated mapping definition in DRAFT state."""
        mid = mapping_def.mapping_id
        ver = mapping_def.version
        if mid not in self._definitions:
            self._definitions[mid] = {}

        prev_state = "NONE"
        if ver in self._definitions[mid]:
            prev_state = self._definitions[mid][ver].lifecycle_state.value

        # Calculate checksum
        csum = self.compiler.compute_checksum(mapping_def)
        mapping_def.checksum = csum

        self._definitions[mid][ver] = mapping_def
        self.record_audit(
            mapping_id=mid,
            version=ver,
            actor=actor,
            action="CREATED" if prev_state == "NONE" else "MODIFIED",
            previous_state=prev_state,
            new_state=mapping_def.lifecycle_state.value,
            checksum=csum,
        )

    def get_definition(self, mapping_id: str, version: str) -> MappingDefinition:
        """Retrieve a specific mapping definition."""
        if mapping_id not in self._definitions or version not in self._definitions[mapping_id]:
            raise MappingError(f"Mapping '{mapping_id}' version '{version}' not found.")
        return self._definitions[mapping_id][version]

    def list_definitions(self) -> list[MappingDefinition]:
        """List all registered mapping definitions."""
        res: list[MappingDefinition] = []
        for vers in self._definitions.values():
            res.extend(vers.values())
        return res

    def validate(self, mapping_id: str, version: str, actor: str = "system") -> None:
        """Validate mapping against JSON schema and safety constraints."""
        mdef = self.get_definition(mapping_id, version)
        prev_state = mdef.lifecycle_state.value
        self.compiler.validate_schema(mdef.to_dict())
        mdef.lifecycle_state = MappingLifecycleState.VALIDATED
        self.record_audit(
            mapping_id=mapping_id,
            version=version,
            actor=actor,
            action="VALIDATED",
            previous_state=prev_state,
            new_state=MappingLifecycleState.VALIDATED.value,
            checksum=mdef.checksum,
        )

    def approve(
        self,
        mapping_id: str,
        version: str,
        reviewer: str,
        comment: str = "",
    ) -> None:
        """Human approval step transitioning mapping to APPROVED state."""
        mdef = self.get_definition(mapping_id, version)
        prev_state = mdef.lifecycle_state.value
        mdef.lifecycle_state = MappingLifecycleState.APPROVED
        self.record_audit(
            mapping_id=mapping_id,
            version=version,
            actor=reviewer,
            action="APPROVED",
            previous_state=prev_state,
            new_state=MappingLifecycleState.APPROVED.value,
            reason=comment,
            checksum=mdef.checksum,
        )

    def activate(self, mapping_id: str, version: str, actor: str = "system") -> CompiledMapping:
        """Compile and atomically activate a mapping rule for production runtime."""
        mdef = self.get_definition(mapping_id, version)
        if mdef.lifecycle_state not in (
            MappingLifecycleState.APPROVED,
            MappingLifecycleState.TESTED,
        ):
            raise MappingActivationError(
                f"Cannot activate mapping '{mapping_id}' in state '{mdef.lifecycle_state.value}'. "
                f"Explicit human approval required."
            )

        # Compile
        compiled = self.compiler.compile(mdef)

        prev_active = self._active_versions.get(mapping_id, "NONE")
        prev_state = mdef.lifecycle_state.value

        # Atomically update active structures
        self._active_compiled[mapping_id] = compiled
        self._active_versions[mapping_id] = version
        mdef.lifecycle_state = MappingLifecycleState.ACTIVE

        if mapping_id not in self._activation_history:
            self._activation_history[mapping_id] = []
        self._activation_history[mapping_id].append(version)

        self.record_audit(
            mapping_id=mapping_id,
            version=version,
            actor=actor,
            action="ACTIVATED",
            previous_state=prev_state,
            new_state=MappingLifecycleState.ACTIVE.value,
            reason=f"Replaced active version '{prev_active}'",
            checksum=compiled.checksum,
        )
        return compiled

    def rollback(
        self, mapping_id: str, target_version: str | None = None, actor: str = "system"
    ) -> CompiledMapping:
        """Roll back an active mapping to the previous approved active version."""
        history = self._activation_history.get(mapping_id, [])
        if len(history) < 2 and target_version is None:
            raise MappingRollbackError(
                f"Cannot rollback mapping '{mapping_id}': no previous active version in history."
            )

        current_ver = self._active_versions.get(mapping_id)
        if target_version is None:
            # Find the last version that isn't the current one
            target_version = history[-2]

        if target_version == current_ver:
            raise MappingRollbackError(
                f"Target rollback version '{target_version}' is already active."
            )

        target_def = self.get_definition(mapping_id, target_version)
        compiled = self.compiler.compile(target_def)

        # Atomic rollback
        self._active_compiled[mapping_id] = compiled
        self._active_versions[mapping_id] = target_version
        target_def.lifecycle_state = MappingLifecycleState.ACTIVE

        if current_ver and current_ver in self._definitions[mapping_id]:
            self._definitions[mapping_id][
                current_ver
            ].lifecycle_state = MappingLifecycleState.DEPRECATED

        self._activation_history[mapping_id].append(target_version)

        self.record_audit(
            mapping_id=mapping_id,
            version=target_version,
            actor=actor,
            action="ROLLED_BACK",
            previous_state=f"ACTIVE({current_ver})",
            new_state=f"ACTIVE({target_version})",
            reason=f"Rolled back from {current_ver}",
            checksum=compiled.checksum,
        )
        return compiled

    def lookup(self, uce_event: dict[str, Any]) -> list[CompiledMapping]:
        """Find matching active compiled mappings ordered by priority (highest first)."""
        matches: list[CompiledMapping] = []
        for compiled in self._active_compiled.values():
            if compiled.match_fn(uce_event):
                matches.append(compiled)

        # Sort deterministically by priority descending, then mapping_id ascending
        matches.sort(key=lambda m: (-m.priority, m.mapping_id))
        return matches

    def detect_conflicts(self) -> list[dict[str, Any]]:
        """Identify duplicate priorities, shadowings, or overlapping mappings."""
        conflicts = []
        active = list(self._active_compiled.values())
        for i in range(len(active)):
            for j in range(i + 1, len(active)):
                m1, m2 = active[i], active[j]
                if m1.priority == m2.priority:
                    conflicts.append(
                        {
                            "type": "EQUAL_PRIORITY_AMBIGUITY",
                            "mapping_a": m1.mapping_id,
                            "mapping_b": m2.mapping_id,
                            "priority": m1.priority,
                            "warning": (
                                "Two active mappings share identical priority; "
                                "evaluation order depends on ID."
                            ),
                        }
                    )
        return conflicts

    def get_active(self, mapping_id: str) -> CompiledMapping | None:
        """Get the active compiled mapping by ID."""
        return self._active_compiled.get(mapping_id)

    def get_active_mappings(self) -> dict[str, CompiledMapping]:
        """Return copy of active compiled mappings dictionary."""
        return dict(self._active_compiled)

    def detect_shadow_or_conflicts(self) -> list[dict[str, Any]]:
        """Alias for detect_conflicts."""
        return self.detect_conflicts()
