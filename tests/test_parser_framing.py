"""Unit tests for Phase 3 encoding, record framing, domain models, and error taxonomy."""

import unittest

from ulpf_contracts.registry import ContractRegistry
from ulpf_parser_runtime.encoding import EncodingStatus, prepare_payload
from ulpf_parser_runtime.errors import ErrorCode, ErrorSeverity, ParseError
from ulpf_parser_runtime.framing import RecordFramer
from ulpf_parser_runtime.models import (
    ExtractedField,
    FieldProvenance,
    Origin,
    ParseResult,
    ParseStatus,
)


class TestEncodingPreprocessing(unittest.TestCase):
    """Test suite for safe payload decoding and loss accounting."""

    def test_clean_utf8(self) -> None:
        raw = b"2026-09-06T01:00:00Z firewall allow src=10.0.0.1\n"
        decoded = prepare_payload(raw)
        self.assertEqual(decoded.status, EncodingStatus.VALID)
        self.assertFalse(decoded.bom_detected)
        self.assertFalse(decoded.lossy)
        self.assertEqual(decoded.text, raw.decode("utf-8"))
        self.assertEqual(decoded.raw_bytes, raw)

    def test_utf8_with_bom(self) -> None:
        raw = b'\xef\xbb\xbf{"event": "auth_success", "user": "admin"}\n'
        decoded = prepare_payload(raw)
        self.assertEqual(decoded.status, EncodingStatus.VALID_WITH_BOM)
        self.assertTrue(decoded.bom_detected)
        self.assertFalse(decoded.lossy)
        self.assertTrue(decoded.text.startswith('{"event"'))
        self.assertEqual(decoded.raw_bytes, raw)

    def test_invalid_utf8_lossy_accounting(self) -> None:
        # Invalid UTF-8 sequence \xff\xfe
        raw = b"Log entry with invalid byte \xff\xfe here\n"
        decoded = prepare_payload(raw)
        self.assertEqual(decoded.status, EncodingStatus.LOSSY_DECODE_REQUIRED)
        self.assertTrue(decoded.lossy)
        self.assertIn("\ufffd", decoded.text)
        self.assertEqual(decoded.raw_bytes, raw)

    def test_oversized_payload_rejection(self) -> None:
        raw = b"x" * 1000
        with self.assertRaises(ValueError):
            prepare_payload(raw, max_bytes=500)


class TestRecordFraming(unittest.TestCase):
    """Test suite for bounded record framing (LF, CRLF, single, multiline)."""

    def setUp(self) -> None:
        self.framer = RecordFramer(
            max_record_bytes=1024,
            max_line_bytes=256,
            max_multiline_lines=10,
            max_total_records=50,
        )

    def test_frame_single(self) -> None:
        text = '{"root": {"child": "value"}}'
        result = self.framer.frame_single(text)
        self.assertEqual(result.total_records, 1)
        self.assertEqual(result.records[0].text, text)
        self.assertFalse(result.records[0].is_truncated)

    def test_frame_lines_lf_and_crlf(self) -> None:
        text = "line1\nline2\r\nline3\n"
        result = self.framer.frame_lines(text)
        self.assertEqual(result.total_records, 3)
        self.assertEqual(result.records[0].text, "line1")
        self.assertEqual(result.records[1].text, "line2")
        self.assertEqual(result.records[2].text, "line3")

    def test_frame_multiline_stacktrace(self) -> None:
        text = (
            "2026-09-06 01:00:00 [ERROR] Application failed\n"
            "  java.lang.NullPointerException: object was null\n"
            "    at com.example.service.Process.run(Process.java:42)\n"
            "    Caused by: java.io.IOException: disk full\n"
            "2026-09-06 01:00:01 [INFO] Normal event\n"
        )
        result = self.framer.frame_multiline(text)
        self.assertEqual(result.total_records, 2)
        # Record 0 must contain the full 4 lines of exception
        self.assertEqual(result.records[0].line_count, 4)
        self.assertTrue(result.records[0].is_multiline)
        self.assertIn("java.lang.NullPointerException", result.records[0].text)
        self.assertIn("Caused by: java.io.IOException", result.records[0].text)

        # Record 1 is single line
        self.assertEqual(result.records[1].line_count, 1)
        self.assertFalse(result.records[1].is_multiline)
        self.assertEqual(result.records[1].text, "2026-09-06 01:00:01 [INFO] Normal event")

    def test_frame_bounded_line_truncation(self) -> None:
        framer = RecordFramer(max_line_bytes=20)
        long_line = "A" * 50 + "\n"
        result = framer.frame_lines(long_line)
        self.assertEqual(result.total_records, 1)
        self.assertTrue(result.records[0].is_truncated)
        self.assertLessEqual(len(result.records[0].raw_bytes), 20)


class TestDomainModelsAndContracts(unittest.TestCase):
    """Test suite verifying ParseResult conforms to parsed-event.v1.schema.json."""

    def setUp(self) -> None:
        self.registry = ContractRegistry()

    def test_parse_error_contract_shape(self) -> None:
        err = ParseError(
            code=ErrorCode.MALFORMED_JSON,
            stage="json_parser",
            message="Unexpected trailing comma at position 42",
            severity=ErrorSeverity.ERROR,
            recoverable=False,
        )
        doc = err.to_contract_dict()
        self.assertEqual(doc["code"], "MALFORMED_JSON")
        self.assertEqual(doc["stage"], "json_parser")
        self.assertFalse(doc["recoverable"])
        self.assertIn("occurred_at", doc)

    def test_parse_result_contract_validation(self) -> None:
        prov = FieldProvenance(
            origin=Origin.OBSERVED,
            transformation_id="json_pointer",
            raw_paths=("/src_ip",),
            confidence=1.0,
        )
        src_field = ExtractedField(
            name="src_ip",
            value="192.168.1.50",
            provenance=prov,
            raw_locator="offset:12-24",
        )
        res = ParseResult(
            status=ParseStatus.PARSED,
            parser_id="parser.generic.json",
            parser_version="1.0.0",
            format="json",
            extracted_fields={"src_ip": src_field},
            unmapped_fields={"custom_vendor_flag": True},
            raw_evidence_ref="evidence://storage/123",
        )

        doc = res.to_parsed_event_contract(
            raw_event_id="raw-evt-001",
            source_id="src-fw-01",
        )

        # Validate against authoritative JSON Schema
        validation = self.registry.validate("parsed-event.v1.schema.json", doc)
        self.assertTrue(
            validation.valid,
            f"ParsedEvent schema validation failed: {validation.errors}",
        )


if __name__ == "__main__":
    unittest.main()
