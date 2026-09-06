"""Tests for the ULPF Mapping Replay Engine and Regression Verification."""

from ulpf_mapping.models import (
    MappingCondition,
    MappingDefinition,
    MappingLifecycleState,
    MappingProvenance,
    MatchCriteria,
    SemanticTarget,
)
from ulpf_onboarding.replay import MappingReplayEngine


def test_replay_matching_and_accuracy() -> None:
    mapping_def = MappingDefinition(
        mapping_id="replay.test.mapping",
        version="1.0.0",
        vendor="TestVendor",
        product="TestProduct",
        lifecycle_state=MappingLifecycleState.APPROVED,
        priority=100,
        match=MatchCriteria(
            vendor="TestVendor",
            product="TestProduct",
            conditions=(MappingCondition(field="event.action", op="equals", value="block"),),
        ),
        semantic=SemanticTarget(
            category="NETWORK",
            class_name="TRAFFIC",
            type_name="DENY",
            action="DENY",
            result="DENIED",
        ),
        provenance=MappingProvenance.USER_AUTHORED,
    )

    samples = [
        {
            "event_id": "s1",
            "event": {
                "metadata": {"vendor": "TestVendor", "product": "TestProduct"},
                "action": "block",
            },
        },
        {
            "event_id": "s2",
            "event": {
                "metadata": {"vendor": "TestVendor", "product": "TestProduct"},
                "action": "block",
            },
        },
        {
            "event_id": "s3",
            "event": {
                "metadata": {"vendor": "TestVendor", "product": "TestProduct"},
                "action": "allow",
            },
        },
    ]

    expected = [
        {"matched": True},
        {"matched": True},
        {"matched": False},
    ]

    engine = MappingReplayEngine()
    result = engine.replay(mapping_def, samples, expected_outputs=expected)

    assert result.total_events == 3
    assert result.passed_events == 3
    assert result.failed_events == 0
    assert result.success_rate == 1.0
    assert len(result.semantic_diffs) == 0


def test_replay_regression_detection() -> None:
    mapping_def = MappingDefinition(
        mapping_id="replay.regression.mapping",
        version="1.0.0",
        vendor="TestVendor",
        product="TestProduct",
        lifecycle_state=MappingLifecycleState.APPROVED,
        priority=100,
        match=MatchCriteria(
            vendor="TestVendor",
            product="TestProduct",
            conditions=(MappingCondition(field="event.action", op="equals", value="block"),),
        ),
        semantic=SemanticTarget(
            category="SYSTEM",
            class_name="EVENT",
            type_name="INFO",
        ),
        provenance=MappingProvenance.USER_AUTHORED,
    )

    samples = [
        {
            "event_id": "s1",
            "event": {
                "metadata": {"vendor": "TestVendor", "product": "TestProduct"},
                "action": "block",
            },
        },
    ]

    # We expect matched=False, but it will match -> failure recorded
    expected = [
        {"matched": False},
    ]

    engine = MappingReplayEngine()
    result = engine.replay(mapping_def, samples, expected_outputs=expected)

    assert result.failed_events == 1
    assert result.success_rate == 0.0
    assert len(result.semantic_diffs) > 0
