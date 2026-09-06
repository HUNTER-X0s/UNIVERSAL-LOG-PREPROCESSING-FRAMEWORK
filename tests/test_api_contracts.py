"""Tests for ULPF Phase 6 REST API endpoints and contracts."""

import unittest

from fastapi.testclient import TestClient
from ulpf_api.app import create_app


class TestApiContracts(unittest.TestCase):
    def setUp(self) -> None:
        self.app = create_app()
        self.client = TestClient(self.app)

    def test_health_endpoints(self) -> None:
        res_live = self.client.get("/health/live")
        self.assertEqual(res_live.status_code, 200)
        self.assertEqual(res_live.json()["status"], "UP")

        res_ready = self.client.get("/health/ready")
        self.assertEqual(res_ready.status_code, 200)
        self.assertTrue(res_ready.json()["is_ready"])

    def test_event_ingest_and_retrieval(self) -> None:
        headers = {"X-Role": "operator"}
        payload = {
            "raw_payload": "Mar 01 12:00:00 asa01 %ASA-4-106023: Deny tcp 1.2.3.4 to 5.6.7.8",
            "source_id": "asa-01",
            "format": "syslog",
        }
        res = self.client.post("/api/v1/events/ingest", json=payload, headers=headers)
        self.assertEqual(res.status_code, 202)
        data = res.json()
        self.assertIn("event_id", data)
        self.assertIn("raw_sha256", data)
        self.assertEqual(data["state"], "ACKNOWLEDGED")

        # Query metrics
        m_res = self.client.get("/api/v1/metrics", headers={"X-Role": "viewer"})
        self.assertEqual(m_res.status_code, 200)
        self.assertIn("counters", m_res.json())

    def test_search_api(self) -> None:
        headers = {"X-Role": "viewer"}
        res = self.client.get("/api/v1/search?limit=10", headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("total_matches", data)
        self.assertIn("events", data)

    def test_dlq_api(self) -> None:
        headers = {"X-Role": "operator"}
        res = self.client.get("/api/v1/dlq", headers=headers)
        self.assertEqual(res.status_code, 200)
        self.assertIn("records", res.json())


if __name__ == "__main__":
    unittest.main()
