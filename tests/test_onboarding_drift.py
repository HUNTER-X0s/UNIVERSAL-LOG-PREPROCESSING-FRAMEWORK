"""Tests for the ULPF Schema Drift Detector."""

from ulpf_onboarding.drift import DriftState, SchemaDriftDetector
from ulpf_onboarding.models import FieldProfile, SourceProfile


def _create_profile(fields: dict[str, str]) -> SourceProfile:
    field_objs = [
        FieldProfile(
            path=name,
            inferred_type=ftype,
            sample_values=("val",),
            cardinality=1,
            null_frequency=0.0,
        )
        for name, ftype in fields.items()
    ]
    return SourceProfile(
        profile_id="test.profile",
        version="1.0.0",
        vendor="VendorX",
        product="ProductY",
        format="json",
        fields=field_objs,
        checksum="abcdef",
        created_at="2026-03-01T12:00:00Z",
        updated_at="2026-03-01T12:00:00Z",
    )


def test_drift_stable() -> None:
    p1 = _create_profile({"src_ip": "ip", "dst_ip": "ip", "action": "string"})
    p2 = _create_profile({"src_ip": "ip", "dst_ip": "ip", "action": "string"})

    report = SchemaDriftDetector.detect_drift(p1, p2)
    assert report.drift_state == DriftState.STABLE
    assert len(report.fields_added) == 0
    assert len(report.fields_removed) == 0
    assert len(report.type_changes) == 0


def test_drift_minor_fields_added() -> None:
    baseline = _create_profile({"src_ip": "ip", "dst_ip": "ip"})
    candidate = _create_profile({"src_ip": "ip", "dst_ip": "ip", "user_agent": "string"})

    report = SchemaDriftDetector.detect_drift(baseline, candidate)
    assert report.drift_state == DriftState.MINOR_DRIFT
    assert report.fields_added == ["user_agent"]
    assert len(report.fields_removed) == 0


def test_drift_major_fields_removed() -> None:
    baseline = _create_profile({"src_ip": "ip", "dst_ip": "ip", "action": "string"})
    candidate = _create_profile({"src_ip": "ip", "dst_ip": "ip"})

    report = SchemaDriftDetector.detect_drift(baseline, candidate)
    assert report.drift_state == DriftState.MAJOR_DRIFT
    assert report.fields_removed == ["action"]


def test_drift_breaking_type_changed() -> None:
    baseline = _create_profile({"src_ip": "ip", "port": "integer"})
    candidate = _create_profile({"src_ip": "ip", "port": "string"})

    report = SchemaDriftDetector.detect_drift(baseline, candidate)
    assert report.drift_state == DriftState.BREAKING_DRIFT
    assert len(report.type_changes) == 1
    assert report.type_changes[0]["field"] == "port"
    assert report.type_changes[0]["old_type"] == "integer"
    assert report.type_changes[0]["new_type"] == "string"
