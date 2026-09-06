"""Integration test for end-to-end cross-vendor onboarding and hot-path execution."""

from ulpf_mapping.models import MappingDefinition
from ulpf_mapping.registry.registry import MappingRegistry
from ulpf_onboarding.service import OnboardingService
from ulpf_semantic.service import SemanticService


def test_end_to_end_cross_vendor_onboarding_and_hot_path() -> None:
    # 1. Simulate arrival of unknown vendor telemetry
    raw_samples = [
        {
            "vendor": "PerimeterX",
            "product": "EdgeSensor",
            "action": "drop",
            "src_ip": "203.0.113.195",
            "dst_ip": "198.51.100.22",
            "src_port": 49152,
            "dst_port": 80,
            "domain": "malicious-c2.example.com",
            "process_name": "powershell.exe",
            "target_url": "http://malicious-c2.example.com/beacon",
            "timestamp": "2026-03-01T15:00:00Z",
        },
        {
            "vendor": "PerimeterX",
            "product": "EdgeSensor",
            "action": "drop",
            "src_ip": "203.0.113.196",
            "dst_ip": "198.51.100.23",
            "src_port": 49153,
            "dst_port": 443,
            "domain": "malicious-c2.example.com",
            "process_name": "curl.exe",
            "target_url": "https://malicious-c2.example.com/exfil",
            "timestamp": "2026-03-01T15:01:00Z",
        },
    ]

    registry = MappingRegistry()
    onboarding_svc = OnboardingService(registry=registry)

    # 2. Onboard source
    result = onboarding_svc.onboard_new_source(
        raw_samples=raw_samples,
        vendor_hint="PerimeterX",
        product_hint="EdgeSensor",
    )

    assert result.detected_vendor == "PerimeterX"
    assert result.sample_count == 2
    assert len(result.candidate_mappings) == 1
    candidate_dict = result.candidate_mappings[0]
    assert candidate_dict["semantic"]["action"] == "deny"

    # 3. Human Governance: Convert to MappingDefinition, review and promote to active
    mdef = MappingDefinition.from_dict(candidate_dict)
    # Ensure priority is high so it takes precedence
    mdef.priority = 200
    onboarding_svc.approve_and_activate(
        mapping_def=mdef,
        reviewer="senior_soc_analyst",
        comment="Verified PerimeterX drop action semantics.",
    )
    assert mdef.mapping_id in registry.get_active_mappings()

    # 4. Initialize Semantic Service with active registry
    semantic_svc = SemanticService(registry=registry)

    # 5. Formulate UCE event
    sample_uce = {
        "event_id": "uce-perimeterx-001",
        "timestamp": "2026-03-01T15:00:00Z",
        "event": {
            "metadata": {"vendor": "PerimeterX", "product": "EdgeSensor"},
            "action": "drop",
            "src_ip": "203.0.113.195",
            "dst_ip": "198.51.100.22",
            "src_port": 49152,
            "dest_port": 80,
            "domain": "malicious-c2.example.com",
            "process_name": "powershell.exe",
            "target_url": "http://malicious-c2.example.com/beacon",
        },
    }

    # Execute hot path (deterministic, air-gapped)
    sem_event = semantic_svc.process_uce(sample_uce, project=True)

    # Verify classification matched active mapping
    assert sem_event.semantic_triple.category in ("SECURITY", "NETWORK")
    assert "perimeterx" in sem_event.decision_trace.rule_id

    # Verify expanded entity extraction
    entity_types = {e.entity_type for e in sem_event.entities}
    assert "IP" in entity_types
    assert "PROCESS" in entity_types
    assert "DOMAIN" in entity_types
    assert "URL" in entity_types

    # Verify expanded indicator extraction
    ind_types = {i.indicator_type for i in sem_event.indicators}
    assert "URL" in ind_types

    # Verify projections generated
    assert sem_event.projections is not None
    assert "ocsf.v1" in sem_event.projections
    assert "otel.logs.v1" in sem_event.projections
    assert "output" in sem_event.projections["otel.logs.v1"]
    assert "resource_logs" in sem_event.projections["otel.logs.v1"]["output"]
    assert "output" in sem_event.projections["ocsf.v1"]
