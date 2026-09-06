"""Phase 2 tests for opaque capture, bounded HTTP intake, and evidence retrieval."""

import hashlib
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient
from pydantic import SecretStr
from ulpf_api.app import create_app
from ulpf_ingestion.evidence import InMemoryRawEventSink
from ulpf_ingestion.metrics import IntakeMetrics
from ulpf_ingestion.models import RawCaptureInput, TransportMetadata, TransportProtocol
from ulpf_ingestion.service import PayloadTooLargeError, RawCaptureService
from ulpf_platform.config import AppSettings


class RawCaptureServiceTests(unittest.TestCase):
    """Prove capture preserves bytes and creates a new receipt for duplicates."""

    def setUp(self) -> None:
        self.sink = InMemoryRawEventSink()
        self.service = RawCaptureService(self.sink, IntakeMetrics(), maximum_event_bytes=1_024)

    def _capture(self, payload: bytes):  # type: ignore[no-untyped-def]
        return self.service.capture(
            RawCaptureInput(
                payload=payload,
                transport=TransportMetadata(protocol=TransportProtocol.HTTP, intake_id="test-http"),
                request_id="00000000-0000-0000-0000-000000000001",
                correlation_id="00000000-0000-0000-0000-000000000002",
                trace_id="0" * 32,
            )
        )

    def test_exact_bytes_hash_and_contract_are_preserved(self) -> None:
        payload = b'\xff\x00opaque\r\n{"not":"parsed"}\n'
        acknowledgement = self._capture(payload)

        stored = self.sink.retrieve(acknowledgement.event_id)

        self.assertEqual(stored.payload, payload)
        self.assertEqual(
            stored.raw_event_contract["integrity"]["payload_sha256"],
            hashlib.sha256(payload).hexdigest(),
        )
        self.assertEqual(stored.raw_event_contract["payload"]["byte_length"], len(payload))
        self.assertEqual(stored.raw_event_contract["transport"]["protocol"], "http")

    def test_duplicate_bytes_receive_distinct_receipts(self) -> None:
        first = self._capture(b"same bytes")
        second = self._capture(b"same bytes")

        self.assertNotEqual(first.event_id, second.event_id)
        self.assertNotEqual(first.receipt_id, second.receipt_id)

    def test_oversize_payload_is_rejected_without_a_partial_receipt(self) -> None:
        with self.assertRaises(PayloadTooLargeError):
            self._capture(b"x" * 1_025)


class HttpRawIntakeTests(unittest.TestCase):
    """Exercise the HTTP boundary without inspecting any submitted payload semantics."""

    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        settings = AppSettings(
            environment="test",
            service_name="ulpf-api-test",
            request_max_bytes=2_048,
            intake_max_event_bytes=1_024,
            intake_max_http_header_bytes=1_024,
            intake_evidence_directory=Path(self._temporary_directory.name),
            intake_evidence_max_events=20,
            intake_evidence_max_bytes=20_480,
            intake_development_retrieval_enabled=True,
        )
        self.client = TestClient(create_app(settings))

    def tearDown(self) -> None:
        self.client.close()
        self._temporary_directory.cleanup()

    def test_http_capture_and_development_retrieval_round_trip_exact_bytes(self) -> None:
        payload = b'{"src_ip":"10.0.0.1"}\r\n\xff'

        accepted = self.client.post(
            "/api/v1/intake/raw", content=payload, headers={"content-type": "application/json"}
        )

        self.assertEqual(accepted.status_code, 202)
        acknowledgement = accepted.json()
        self.assertTrue(acknowledgement["accepted"])
        self.assertEqual(acknowledgement["status"], "captured")
        self.assertNotIn("src_ip", str(acknowledgement))

        recovered = self.client.get(f"/api/v1/intake/raw/{acknowledgement['event_id']}")

        self.assertEqual(recovered.status_code, 200)
        self.assertEqual(recovered.content, payload)
        self.assertEqual(
            recovered.headers["X-ULPF-Payload-SHA256"], hashlib.sha256(payload).hexdigest()
        )

    def test_http_payload_above_event_limit_is_refused(self) -> None:
        response = self.client.post("/api/v1/intake/raw", content=b"x" * 1_025)

        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json()["code"], "intake_payload_too_large")

    def test_http_headers_above_limit_are_refused_before_capture(self) -> None:
        response = self.client.post(
            "/api/v1/intake/raw", content=b"opaque", headers={"x-long": "x" * 2_000}
        )

        self.assertEqual(response.status_code, 431)
        self.assertEqual(response.json()["code"], "intake_headers_too_large")

    def test_development_retrieval_requires_explicit_enablement(self) -> None:
        disabled_settings = AppSettings(
            environment="test",
            service_name="ulpf-api-test",
            intake_evidence_directory=Path(self._temporary_directory.name) / "disabled",
        )
        with TestClient(create_app(disabled_settings)) as client:
            response = client.get("/api/v1/intake/raw/00000000-0000-0000-0000-000000000000")
        self.assertEqual(response.status_code, 404)

    def test_static_token_is_required_when_configured(self) -> None:
        token_settings = AppSettings(
            environment="test",
            service_name="ulpf-api-test",
            intake_evidence_directory=Path(self._temporary_directory.name) / "token",
            intake_auth_token=SecretStr("test-token"),
        )
        with TestClient(create_app(token_settings)) as client:
            denied = client.post("/api/v1/intake/raw", content=b"opaque")
            accepted = client.post(
                "/api/v1/intake/raw",
                content=b"opaque",
                headers={"authorization": "Bearer test-token"},
            )
        self.assertEqual(denied.status_code, 401)
        self.assertEqual(accepted.status_code, 202)

    def test_global_local_rate_limit_refuses_excess_request(self) -> None:
        rate_settings = AppSettings(
            environment="test",
            service_name="ulpf-api-test",
            intake_evidence_directory=Path(self._temporary_directory.name) / "rate",
            intake_http_requests_per_minute=1,
        )
        with TestClient(create_app(rate_settings)) as client:
            first = client.post("/api/v1/intake/raw", content=b"first")
            second = client.post("/api/v1/intake/raw", content=b"second")
        self.assertEqual(first.status_code, 202)
        self.assertEqual(second.status_code, 429)
        self.assertEqual(second.json()["code"], "intake_rate_limited")
