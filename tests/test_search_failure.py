"""Phase 7 Test: Search Subsystem Failure Mode.

Verifies:
- Rule D5: Search failure does NOT stall canonical ingest/storage
- Rule D7: Search failure puts platform in degraded mode (fail-open)
- Platform continues processing events when search is unavailable
"""

import pytest
from ulpf_runtime.failover import DegradedModeController, FailoverBehavior


@pytest.fixture()
def controller() -> DegradedModeController:
    return DegradedModeController()


def test_search_failure_allows_canonical_processing(controller: DegradedModeController) -> None:
    """Search failure must NOT block ingest or storage."""
    controller.mark_failed("search", reason="index server down")

    # Database (canonical) should still be accessible
    db_decision = controller.evaluate("database")
    assert db_decision.allowed is True

    # Stream should still be accessible
    stream_decision = controller.evaluate("stream")
    assert stream_decision.allowed is True


def test_search_failure_uses_fail_open(controller: DegradedModeController) -> None:
    """Search subsystem is fail-open: operations are allowed in degraded mode."""
    controller.mark_failed("search")
    decision = controller.evaluate("search", operation="query")
    assert decision.allowed is True
    assert decision.behavior == FailoverBehavior.FAIL_OPEN


def test_search_degraded_still_open(controller: DegradedModeController) -> None:
    controller.mark_degraded("search", reason="high latency")
    decision = controller.evaluate("search")
    assert decision.allowed is True
    assert decision.behavior == FailoverBehavior.FAIL_OPEN


def test_search_recovery_restores_healthy_status(controller: DegradedModeController) -> None:
    controller.mark_failed("search")
    controller.mark_recovered("search")
    decision = controller.evaluate("search")
    assert decision.allowed is True
    assert "healthy" in decision.reason.lower()


def test_search_failure_contrast_with_database_failure(
    controller: DegradedModeController,
) -> None:
    """Search is fail-open; database is fail-closed. They must behave differently."""
    controller.mark_failed("search")
    controller.mark_failed("database")

    search_decision = controller.evaluate("search")
    db_decision = controller.evaluate("database")

    assert search_decision.allowed is True      # fail-open
    assert db_decision.allowed is False          # fail-closed


def test_auth_failure_is_still_fail_closed_regardless_of_search(
    controller: DegradedModeController,
) -> None:
    controller.mark_failed("search")
    # Auth remains fail-closed even when search is down
    auth_decision = controller.evaluate("auth")
    assert auth_decision.allowed is True  # Auth is healthy
    controller.mark_failed("auth")
    auth_failed_decision = controller.evaluate("auth")
    assert auth_failed_decision.allowed is False
