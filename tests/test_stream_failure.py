"""Phase 7 Test: Stream Failure Mode.

Verifies:
- Rule D8: Stream failure causes ingest backpressure (fail-closed for stream)
- Rule D5: Stream unavailability does not corrupt already-persisted data
- Failover controller correctly evaluates stream subsystem
"""

import pytest
from ulpf_runtime.failover import DegradedModeController, FailoverBehavior


@pytest.fixture()
def controller() -> DegradedModeController:
    return DegradedModeController()


def test_stream_healthy_allows_ingest(controller: DegradedModeController) -> None:
    decision = controller.evaluate("stream", operation="publish")
    assert decision.allowed is True
    assert decision.behavior == FailoverBehavior.FAIL_CLOSED


def test_stream_failure_blocks_ingest(controller: DegradedModeController) -> None:
    controller.mark_failed("stream", reason="broker unreachable")
    decision = controller.evaluate("stream", operation="publish")
    assert decision.allowed is False
    assert decision.behavior == FailoverBehavior.FAIL_CLOSED


def test_stream_degraded_blocks_ingest(controller: DegradedModeController) -> None:
    """Even degraded stream uses fail-closed (no partial ack)."""
    controller.mark_degraded("stream", reason="high latency")
    decision = controller.evaluate("stream", operation="publish")
    assert decision.allowed is False


def test_stream_recovery_re_enables_ingest(controller: DegradedModeController) -> None:
    controller.mark_failed("stream")
    controller.mark_recovered("stream")
    decision = controller.evaluate("stream")
    assert decision.allowed is True


def test_stream_failure_does_not_affect_database_subsystem(
    controller: DegradedModeController,
) -> None:
    controller.mark_failed("stream")
    db_decision = controller.evaluate("database")
    # Database should still be healthy
    assert db_decision.allowed is True


def test_stream_failure_logged_in_incident_log(controller: DegradedModeController) -> None:
    controller.mark_failed("stream", reason="network partition")
    log = controller.incident_log()
    assert any(e["subsystem"] == "stream" for e in log)


def test_stream_failure_then_recovery_logged(controller: DegradedModeController) -> None:
    controller.mark_failed("stream")
    controller.mark_recovered("stream")
    log = controller.incident_log()
    transitions = [e["transition"] for e in log if e["subsystem"] == "stream"]
    assert any("FAILED" in t for t in transitions)
    assert any("HEALTHY" in t for t in transitions)
