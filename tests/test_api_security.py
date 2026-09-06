"""Tests for ULPF Phase 6 API security and authorization controls."""

import unittest

from fastapi.testclient import TestClient
from ulpf_api.app import create_app


class TestApiSecurity(unittest.TestCase):
    def setUp(self) -> None:
        self.app = create_app()
        self.client = TestClient(self.app)

    def test_unauthorized_role_rejected(self) -> None:
        # Viewer attempting to ingest telemetry or trigger replay -> 403 Forbidden
        headers = {"X-Role": "viewer"}
        payload = {
            "raw_payload": "test log",
            "source_id": "src-1",
        }
        res = self.client.post("/api/v1/events/ingest", json=payload, headers=headers)
        self.assertEqual(res.status_code, 403)

        replay_payload = {
            "target_stage": "RAW",
            "mapping_version": "v1.0.0",
            "event_ids": ["raw-1"],
        }
        replay_res = self.client.post("/api/v1/replay", json=replay_payload, headers=headers)
        self.assertEqual(replay_res.status_code, 403)

    def test_search_query_limit_bounds(self) -> None:
        # Query exceeding limit bounds -> 422 Unprocessable Entity
        headers = {"X-Role": "viewer"}
        res = self.client.get("/api/v1/search?limit=9999", headers=headers)
        self.assertEqual(res.status_code, 422)

    def test_nonexistent_raw_evidence_404(self) -> None:
        headers = {"X-Role": "viewer"}
        res = self.client.get("/api/v1/events/raw/non-existent-id", headers=headers)
        self.assertEqual(res.status_code, 404)


if __name__ == "__main__":
    unittest.main()
