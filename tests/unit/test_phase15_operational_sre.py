"""Phase 15 Unit Tests for Milestone D: Operational / SRE Maturity."""

from pathlib import Path
import pytest
from ulpf_observability.slo_engine import MissionSLOEngine, SLOStatus, MetricCategory

ROOT = Path(__file__).resolve().parent.parent.parent


def test_slo_engine_default_definitions():
    engine = MissionSLOEngine()
    assert len(engine.definitions) == 10
    assert "SLO-INGEST" in engine.definitions
    assert "SLO-EVID" in engine.definitions
    assert "SLO-DLQ" in engine.definitions


def test_slo_engine_healthy_recording():
    engine = MissionSLOEngine()
    for _ in range(100):
        engine.record_event("SLO-INGEST", success=True, latency_ms=2.5)
    
    measurement = engine.evaluate_slo("SLO-INGEST")
    assert measurement.current_percentage == 100.0
    assert measurement.status == SLOStatus.HEALTHY
    assert measurement.is_met is True
    assert measurement.error_budget_remaining == 100.0


def test_slo_engine_burn_rate_and_degradation():
    engine = MissionSLOEngine()
    # Record 90 successes and 10 failures (target is 99.9%, so 90% is burning/breached)
    for _ in range(90):
        engine.record_event("SLO-INGEST", success=True)
    for _ in range(10):
        engine.record_event("SLO-INGEST", success=False)
    
    measurement = engine.evaluate_slo("SLO-INGEST")
    assert measurement.current_percentage == 90.0
    assert measurement.is_met is False
    assert measurement.status in (SLOStatus.EXHAUSTED, SLOStatus.BREACHED)
    assert measurement.burn_rate_1h > 1.0


def test_slo_engine_overall_health_posture():
    engine = MissionSLOEngine()
    # Pristine engine
    health = engine.get_overall_health()
    assert health["overall_posture"] == "HEALTHY"
    assert health["slos_met"] == 10
    assert len(health["breached_slos"]) == 0

    # Inject failure into critical SLO
    for _ in range(50):
        engine.record_event("SLO-EVID", success=False)
    
    degraded_health = engine.get_overall_health()
    assert degraded_health["overall_posture"] == "CRITICAL"
    assert "SLO-EVID" in degraded_health["breached_slos"]


def test_operational_runbooks_presence():
    runbooks_dir = ROOT / "docs" / "runbooks"
    assert runbooks_dir.exists()
    runbooks = list(runbooks_dir.glob("*.md"))
    assert len(runbooks) >= 15

    for rb in runbooks:
        txt = rb.read_text(encoding="utf-8")
        assert "Trigger & Condition" in txt
        assert "Diagnosis & Root Cause" in txt
        assert "Mitigation & Resolution" in txt
        assert "Verification & Health" in txt
        assert "Rollback" in txt
