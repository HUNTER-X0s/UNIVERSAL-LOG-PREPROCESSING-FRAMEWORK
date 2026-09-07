"""Phase 11 Air-Gap & Sovereignty Certification Suite.

Proves 100% offline air-gap compliance:
1. Static source audit ensuring 0 network library imports across packages.
2. Runtime socket interceptor ensuring zero external network connections
   during end-to-end mission pipeline execution, posture calculation, and copilot advisory.
"""

from __future__ import annotations

import socket
from pathlib import Path
from typing import Any

import pytest
from ulpf_mission.copilot.advisor import AIAnalystCopilot
from ulpf_mission.orchestration.pipeline import MissionAnalysisPipeline
from ulpf_mission.posture.engine import SecurityPostureEngine

# ===========================================================================
# 1. Static Source Audit for Prohibited Network Libraries
# ===========================================================================

PROHIBITED_MODULES = ["requests", "httpx", "urllib.request", "aiohttp", "urllib3"]


def test_packages_have_zero_network_imports() -> None:
    """Verify no production package imports external HTTP/cloud clients."""
    packages_dir = Path("packages")
    violations: list[str] = []

    for py_file in packages_dir.rglob("*.py"):
        text = py_file.read_text(encoding="utf-8", errors="ignore")
        for mod in PROHIBITED_MODULES:
            if f"import {mod}" in text or f"from {mod}" in text:
                violations.append(f"{py_file}: {mod}")

    assert len(violations) == 0, f"Found prohibited network imports: {violations}"


# ===========================================================================
# 2. Dynamic Runtime Socket Interception (Hard Air-Gap Assurance)
# ===========================================================================

class AirGapViolationError(RuntimeError):
    """Raised when an outbound socket connection is attempted in an air-gapped system."""


def test_runtime_pipeline_makes_zero_socket_connections(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prove MissionAnalysisPipeline operates 100% offline without opening network sockets."""
    def _forbidden_connect(self: Any, *args: Any, **kwargs: Any) -> None:
        raise AirGapViolationError(f"Prohibited socket connection attempt detected: {args}")

    monkeypatch.setattr(socket.socket, "connect", _forbidden_connect)

    pipeline = MissionAnalysisPipeline()
    batch = [
        {"id": f"ev-{i}", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "message": f"telemetry-{i}"}
        for i in range(50)
    ]

    # Must complete cleanly without calling socket.connect
    res = pipeline.run(batch)
    assert res.processed_events == 50
    assert len(res.stage_errors) == 0


def test_runtime_copilot_makes_zero_socket_connections(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prove AIAnalystCopilot runs strictly locally without external LLM API socket calls."""
    def _forbidden_connect(self: Any, *args: Any, **kwargs: Any) -> None:
        raise AirGapViolationError(f"Prohibited socket connection attempt detected: {args}")

    monkeypatch.setattr(socket.socket, "connect", _forbidden_connect)

    copilot = AIAnalystCopilot()
    summary = copilot.summarise_case(
        case_id="case-airgap-01",
        severity="HIGH",
        description="Air-gap compliance test case",
        affected_assets=["host-sec-01"],
        involved_users=["analyst-root"],
        timeline_events=[],
        detection_rule_ids=["RULE_TEST"],
        kill_chain_phases=["Execution"],
    )

    assert summary.case_id == "case-airgap-01"
    assert summary.what != ""
    assert len(summary.recommended_actions) > 0


def test_runtime_posture_engine_makes_zero_socket_connections(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prove SecurityPostureEngine runs strictly locally without external socket calls."""
    def _forbidden_connect(self: Any, *args: Any, **kwargs: Any) -> None:
        raise AirGapViolationError(f"Prohibited socket connection attempt detected: {args}")

    monkeypatch.setattr(socket.socket, "connect", _forbidden_connect)

    engine = SecurityPostureEngine()
    state = engine.calculate(
        critical_alert_count=3,
        active_campaign_count=1,
        anomaly_event_count=8,
        total_event_count=1000,
        ti_match_count=2,
        unhealthy_source_fraction=0.0,
    )
    assert state.risk_score > 0.0
