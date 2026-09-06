"""Tests for ULPF Phase 6 health and readiness endpoints."""

import unittest

from ulpf_runtime.health import HealthRegistry, HealthState


class TestHealthRegistry(unittest.TestCase):
    def test_liveness_check(self) -> None:
        reg = HealthRegistry(service_name="test-svc", version="1.0.0")
        live = reg.check_liveness()
        self.assertEqual(live["status"], "UP")
        self.assertEqual(live["service"], "test-svc")

    def test_readiness_with_all_healthy(self) -> None:
        reg = HealthRegistry()
        reg.register_dependency("db", lambda: (HealthState.HEALTHY, None), is_critical=True)
        reg.register_dependency("cache", lambda: (HealthState.HEALTHY, None), is_critical=False)

        ready = reg.check_readiness()
        self.assertEqual(ready["overall_state"], "HEALTHY")
        self.assertTrue(ready["is_ready"])

    def test_readiness_with_non_critical_degraded(self) -> None:
        reg = HealthRegistry()
        reg.register_dependency("raw_store", lambda: (HealthState.HEALTHY, None), is_critical=True)
        reg.register_dependency("search_index", lambda: (HealthState.UNAVAILABLE, "Search down"), is_critical=False)

        ready = reg.check_readiness()
        self.assertEqual(ready["overall_state"], "DEGRADED")
        self.assertTrue(ready["is_ready"])  # Still ready to process ingestion

    def test_readiness_with_critical_failure(self) -> None:
        reg = HealthRegistry()
        reg.register_dependency("raw_store", lambda: (HealthState.UNAVAILABLE, "Disk write error"), is_critical=True)

        ready = reg.check_readiness()
        self.assertEqual(ready["overall_state"], "UNAVAILABLE")
        self.assertFalse(ready["is_ready"])


if __name__ == "__main__":
    unittest.main()
