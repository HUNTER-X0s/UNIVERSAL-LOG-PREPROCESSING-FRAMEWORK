"""Tests for the ULPF Mapping Compiler and DSL Operators."""

import pytest
from ulpf_mapping.compiler.compiler import MappingCompiler
from ulpf_mapping.dsl.operators import evaluate_condition, get_nested_field
from ulpf_mapping.errors import MappingSafetyError, MappingSchemaError


def test_nested_field_lookup() -> None:
    data = {
        "event": {
            "metadata": {"vendor": "Fortinet", "score": 95},
            "network": {"ip": "10.0.0.1"},
            "tags": ["firewall", "edge"],
        }
    }
    assert get_nested_field(data, "event.metadata.vendor") == "Fortinet"
    assert get_nested_field(data, "event.metadata.score") == 95
    assert get_nested_field(data, "event.tags.0") == "firewall"
    assert get_nested_field(data, "event.tags.1") == "edge"
    assert get_nested_field(data, "nonexistent.field") is None


def test_dsl_operator_evaluation() -> None:
    # equals & numeric
    assert evaluate_condition("100", "equals", 100) is True
    assert evaluate_condition("ALLOW", "equals", "allow") is True
    assert evaluate_condition("DENY", "not_equals", "allow") is True

    # in & not_in
    assert evaluate_condition("drop", "in", ["deny", "drop", "reject"]) is True
    assert evaluate_condition("accept", "not_in", ["deny", "drop"]) is True

    # contains, prefix, suffix
    assert evaluate_condition("firewall-deny-rule", "contains", "deny") is True
    assert evaluate_condition("https://example.com", "prefix", "https://") is True
    assert evaluate_condition("payload.exe", "suffix", ".exe") is True

    # numeric compare
    assert evaluate_condition(8080, "greater_than", 80) is True
    assert evaluate_condition(22, "less_than_equal", 22) is True
    assert evaluate_condition("443", "greater_than_equal", 443) is True
    assert evaluate_condition(8080, "numeric_compare", {"cmp": ">", "val": 1024}) is True

    # regex bounded
    assert evaluate_condition("192.168.1.5", "regex_bounded", r"^192\.168\.\d+\.\d+$") is True
    assert evaluate_condition("10.0.0.1", "regex_bounded", r"^192\.168\.") is False

    # exists / not_exists
    assert evaluate_condition("val", "exists", True) is True
    assert evaluate_condition(None, "exists", True) is False
    assert evaluate_condition(None, "not_exists", True) is True


def test_dsl_operator_safety_limits() -> None:
    # ReDoS rejection in condition evaluation
    evil_regex = r"(a+)+$"
    with pytest.raises(MappingSafetyError, match="ReDoS vulnerability"):
        evaluate_condition("aaaa", "regex_bounded", evil_regex)

    # String length bounding
    long_string = "x" * 15000
    assert evaluate_condition(long_string, "contains", "x" * 100) is True


def test_mapping_compiler_valid() -> None:
    raw_spec = {
        "schema_version": "1.0.0",
        "mapping_id": "test.vendor.firewall",
        "version": "1.0.0",
        "vendor": "AcmeNet",
        "product": "Firewall",
        "confidence": 0.95,
        "lifecycle_state": "APPROVED",
        "priority": 100,
        "match": {
            "vendor": "AcmeNet",
            "product": "Firewall",
            "conditions": [
                {"field": "event.action", "op": "equals", "value": "DENY"},
                {
                    "field": "event.dest_port",
                    "op": "numeric_compare",
                    "value": {"cmp": ">", "val": 1024},
                },
            ],
        },
        "semantic": {
            "category": "NETWORK",
            "class": "TRAFFIC",
            "type": "DENY",
            "action": "DENY",
            "result": "DENIED",
        },
        "field_mappings": [
            {"source_field": "source_ip", "target_field": "src_ip"},
            {"source_field": "dest_ip", "target_field": "dst_ip"},
        ],
        "provenance": "USER_AUTHORED",
    }

    compiled = MappingCompiler.compile(raw_spec)
    assert compiled.mapping_id == "test.vendor.firewall"
    assert compiled.version == "1.0.0"
    assert len(compiled.checksum) == 64  # SHA-256

    # Test match function
    matching_sample = {
        "event": {
            "metadata": {"vendor": "AcmeNet", "product": "Firewall"},
            "action": "DENY",
            "dest_port": 8080,
        },
        "format": "json",
    }
    assert compiled.match_fn(matching_sample) is True

    non_matching_sample = {
        "event": {
            "metadata": {"vendor": "AcmeNet", "product": "Firewall"},
            "action": "ALLOW",
            "dest_port": 8080,
        },
        "format": "json",
    }
    assert compiled.match_fn(non_matching_sample) is False


def test_mapping_compiler_rejects_unsafe_regex() -> None:
    unsafe_spec = {
        "schema_version": "1.0.0",
        "mapping_id": "unsafe.regex.map",
        "version": "1.0.0",
        "vendor": "Generic",
        "product": "IDS",
        "confidence": 0.85,
        "lifecycle_state": "DRAFT",
        "priority": 10,
        "match": {
            "conditions": [
                {"field": "payload", "op": "regex_bounded", "value": r"([a-zA-Z]+)*$"},
            ],
        },
        "semantic": {
            "category": "NETWORK",
            "class": "TRAFFIC",
            "type": "ALLOW",
        },
        "provenance": "AI_SUGGESTED",
    }

    with pytest.raises(MappingSafetyError, match="ReDoS vulnerability"):
        MappingCompiler.compile(unsafe_spec)


def test_mapping_compiler_schema_validation_error() -> None:
    invalid_spec = {
        "mapping_id": "invalid.spec",
        "version": "1.0.0",
        # Missing required 'semantic' and 'schema_version' blocks
    }
    with pytest.raises(MappingSchemaError):
        MappingCompiler.compile(invalid_spec)
