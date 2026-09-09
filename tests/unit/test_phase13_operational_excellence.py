"""Phase 13 Unit Tests for Milestone E: Operational Excellence (Workstreams V, W, Z)."""

import pytest
from ulpf_mission.health.source_health import DataQualityScorer, SourceHealthMonitor


def test_data_quality_scorer_excellent():
    uce = {
        "event.timestamp": "2026-09-09T12:00:00Z",
        "event.action": "allow",
        "source.ip": "10.0.0.1",
        "destination.ip": "172.16.0.2",
        "source.port": 443,
    }
    report = DataQualityScorer.evaluate_event(uce, lineage_count=13)
    assert report.composite_score >= 90.0
    assert report.quality_band == "EXCELLENT"
    assert report.factors.lineage_integrity == 1.0


def test_data_quality_scorer_degraded():
    uce = {
        "timestamp": "invalid_date",
        "source.ip": "999.999.999.999",  # invalid IP
        "unmapped.field1": "val1",
        "unmapped.field2": "val2",
    }
    report = DataQualityScorer.evaluate_event(uce, lineage_count=5)
    assert report.composite_score < 75.0
    assert report.quality_band in ("DEGRADED", "POOR")
    assert any("Invalid IP" in adv for adv in report.remediation_advice)
    assert any("Standardize source timestamp" in adv for adv in report.remediation_advice)


def test_source_health_monitor_lifecycle():
    monitor = SourceHealthMonitor()

    # 1. Healthy batch
    h1 = monitor.record_batch("palo_alto_stream", total_events=1000, failed_events=2, latency_ms=0.5)
    assert h1.status == "HEALTHY"
    assert h1.error_rate < 0.01

    # 2. Degraded batch due to error spike
    h2 = monitor.record_batch("cisco_stream", total_events=100, failed_events=60, latency_ms=2.0)
    assert h2.status == "ERROR_SPIKE"
    assert h2.error_rate == 0.60
    assert len(h2.anomalies_detected) >= 1
