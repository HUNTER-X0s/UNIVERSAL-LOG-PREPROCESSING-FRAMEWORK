"""API foundation tests; no business endpoint is exercised or implied."""

import unittest

from fastapi.testclient import TestClient
from ulpf_api.app import create_app
from ulpf_platform.config import AppSettings


class ApiFoundationTests(unittest.TestCase):
    """Validate health, correlation, request bounds, and scope disclosure."""

    @classmethod
    def setUpClass(cls) -> None:
        settings = AppSettings(environment="test", service_name="ulpf-api-test")
        cls.client = TestClient(create_app(settings))

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client.close()

    def test_health_exposes_safe_foundation_metadata(self) -> None:
        response = self.client.get("/api/v1/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "healthy")
        self.assertEqual(response.json()["environment"], "test")
        self.assertIn("X-Request-ID", response.headers)
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")

    def test_oversized_request_is_rejected_before_routing(self) -> None:
        response = self.client.post(
            "/api/v1/metadata", content="x" * 2_000_000, headers={"content-length": "2000000"}
        )
        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json()["code"], "request_too_large")

    def test_metadata_marks_business_capabilities_as_deferred(self) -> None:
        response = self.client.get("/api/v1/metadata")
        self.assertEqual(response.status_code, 200)
        self.assertIn("parsing", response.json()["deferred_capabilities"])

    def test_not_found_uses_standard_error_envelope(self) -> None:
        response = self.client.get("/api/v1/not-implemented")
        body = response.json()
        self.assertEqual(response.status_code, 404)
        self.assertEqual(body["code"], "not_found")
        self.assertNotIn("traceback", str(body).lower())
