"""Tests for the ULPF Versioned Mapping Registry and Lifecycle Management."""

import pytest
from ulpf_mapping.errors import MappingActivationError
from ulpf_mapping.models import (
    MappingDefinition,
    MappingLifecycleState,
    MappingProvenance,
    MatchCriteria,
    SemanticTarget,
)
from ulpf_mapping.registry.registry import MappingRegistry


def _create_sample_def(
    mapping_id: str,
    version: str,
    priority: int = 50,
    state: MappingLifecycleState = MappingLifecycleState.DRAFT,
) -> MappingDefinition:
    return MappingDefinition(
        mapping_id=mapping_id,
        version=version,
        vendor="TestVendor",
        product="TestProduct",
        lifecycle_state=state,
        priority=priority,
        match=MatchCriteria(vendor="TestVendor", product="TestProduct"),
        semantic=SemanticTarget(category="NETWORK", class_name="TRAFFIC", type_name="ALLOW"),
        provenance=MappingProvenance.USER_AUTHORED,
    )


def test_registry_registration_and_lookup() -> None:
    reg = MappingRegistry()
    mdef = _create_sample_def("map.alpha", "1.0.0")

    reg.register(mdef)
    fetched = reg.get_definition("map.alpha", "1.0.0")
    assert fetched.mapping_id == "map.alpha"
    assert fetched.version == "1.0.0"

    all_defs = reg.list_definitions()
    assert len(all_defs) == 1


def test_registry_lifecycle_transitions() -> None:
    reg = MappingRegistry()
    mdef = _create_sample_def("map.beta", "1.0.0")
    reg.register(mdef)

    # Cannot activate DRAFT directly
    with pytest.raises(MappingActivationError, match="Cannot activate mapping"):
        reg.activate("map.beta", "1.0.0")

    # Step 1: Validate
    reg.validate("map.beta", "1.0.0", actor="ci")
    assert (
        reg.get_definition("map.beta", "1.0.0").lifecycle_state == MappingLifecycleState.VALIDATED
    )

    # Step 2: Approve
    reg.approve("map.beta", "1.0.0", reviewer="secops_lead", comment="Approved for production")
    assert reg.get_definition("map.beta", "1.0.0").lifecycle_state == MappingLifecycleState.APPROVED

    # Step 3: Activate
    compiled = reg.activate("map.beta", "1.0.0", actor="deployer")
    assert compiled.mapping_id == "map.beta"
    assert reg.get_active("map.beta") is not None
    assert reg.get_definition("map.beta", "1.0.0").lifecycle_state == MappingLifecycleState.ACTIVE

    # Check audit trail recorded
    trail = reg.get_audit_trail("map.beta")
    assert len(trail) >= 3
    actions = [e["action"] for e in trail]
    assert "VALIDATED" in actions
    assert "APPROVED" in actions
    assert "ACTIVATED" in actions


def test_registry_atomic_rollback() -> None:
    reg = MappingRegistry()

    # V1 lifecycle
    m1 = _create_sample_def("map.gamma", "1.0.0", priority=10, state=MappingLifecycleState.APPROVED)
    reg.register(m1)
    reg.activate("map.gamma", "1.0.0")

    # V2 lifecycle
    m2 = _create_sample_def("map.gamma", "2.0.0", priority=15, state=MappingLifecycleState.APPROVED)
    reg.register(m2)
    reg.activate("map.gamma", "2.0.0")

    active_now = reg.get_active("map.gamma")
    assert active_now is not None
    assert active_now.version == "2.0.0"

    # Rollback to previous version (1.0.0)
    rolled_back = reg.rollback("map.gamma", actor="incident_responder")
    assert rolled_back.version == "1.0.0"

    current = reg.get_active("map.gamma")
    assert current is not None
    assert current.version == "1.0.0"


def test_registry_conflict_and_shadow_detection() -> None:
    reg = MappingRegistry()

    # Two active mappings with identical priority
    m1 = _create_sample_def(
        "map.paloalto", "1.0.0", priority=50, state=MappingLifecycleState.APPROVED
    )
    m2 = _create_sample_def(
        "map.fortinet", "1.0.0", priority=50, state=MappingLifecycleState.APPROVED
    )

    reg.register(m1)
    reg.register(m2)
    reg.activate("map.paloalto", "1.0.0")
    reg.activate("map.fortinet", "1.0.0")

    conflicts = reg.detect_shadow_or_conflicts()
    assert len(conflicts) == 1
    assert conflicts[0]["type"] == "EQUAL_PRIORITY_AMBIGUITY"
