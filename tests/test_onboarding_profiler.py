"""Tests for the ULPF Sample Profiler and Source Profile Generation."""

from ulpf_onboarding.profiler import SampleProfiler


def test_detect_format_heuristics() -> None:
    # JSON
    assert SampleProfiler.detect_format('{"event": "firewall", "id": 123}') == "json"
    assert SampleProfiler.detect_format(b'{"src_ip": "10.0.0.1"}') == "json"

    # Syslog
    assert (
        SampleProfiler.detect_format("<34>1 2026-03-01T12:00:00Z myhost app 1234 - msg")
        == "syslog.rfc5424"
    )
    assert (
        SampleProfiler.detect_format("<13>Feb 5 17:32:18 10.0.0.1 sshd[242]: Failed password")
        == "syslog.rfc3164"
    )

    # CEF & LEEF
    assert (
        SampleProfiler.detect_format("CEF:0|Vendor|Product|1.0|100|Event|3|src=10.0.0.1") == "cef"
    )
    assert SampleProfiler.detect_format("LEEF:2.0|Vendor|Product|1.0|Event|src=10.0.0.1") == "leef"

    # KV pairs
    assert (
        SampleProfiler.detect_format("src=10.0.0.1 dst=192.168.1.1 proto=TCP action=deny") == "kv"
    )


def test_infer_value_types() -> None:
    assert SampleProfiler.infer_value_type(None) == "null"
    assert SampleProfiler.infer_value_type(True) == "boolean"
    assert SampleProfiler.infer_value_type(42) == "integer"
    assert SampleProfiler.infer_value_type(3.14159) == "float"
    assert SampleProfiler.infer_value_type("192.168.1.1") == "ip"
    assert SampleProfiler.infer_value_type("2026-03-01T15:30:00Z") == "timestamp"
    assert SampleProfiler.infer_value_type({"nested": "dict"}) == "object"
    assert SampleProfiler.infer_value_type(["a", "b"]) == "array"
    assert SampleProfiler.infer_value_type("regular string") == "string"


def test_generate_source_profile() -> None:
    events = [
        {
            "src_ip": "192.168.1.10",
            "dst_ip": "10.0.0.1",
            "dst_port": 443,
            "action": "allow",
            "timestamp": "2026-03-01T12:00:00Z",
        },
        {
            "src_ip": "192.168.1.20",
            "dst_ip": "10.0.0.2",
            "dst_port": 80,
            "action": "deny",
            "timestamp": "2026-03-01T12:01:00Z",
            "rule_id": 999,
        },
        {
            "src_ip": "192.168.1.30",
            "dst_ip": "10.0.0.3",
            "dst_port": 22,
            "action": "deny",
            "timestamp": "2026-03-01T12:02:00Z",
        },
    ]

    profile = SampleProfiler.profile_samples(
        samples=events,
        vendor="CheckPoint",
        product="GaiaFW",
        format_id="json",
    )

    assert profile.vendor == "CheckPoint"
    assert profile.product == "GaiaFW"
    assert profile.format == "json"
    assert len(profile.fields) >= 5
    assert len(profile.checksum) == 64

    # Check field statistics
    fields_dict = {f.path: f for f in profile.fields}
    assert "src_ip" in fields_dict
    assert fields_dict["src_ip"].inferred_type == "ip"
    assert fields_dict["src_ip"].null_frequency == 0.0

    # Optional field rule_id
    assert "rule_id" in fields_dict
    assert (
        fields_dict["rule_id"].null_frequency == round(1 / 3, 4)
        or fields_dict["rule_id"].null_frequency > 0
    )
