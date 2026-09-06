"""Security, resource bounds, and adversarial robustness tests for ULPF Phase 3.

Adheres to:
- Spec §23: JSON and XML Security (XXE, Billion Laughs, quadratic blowup)
- Spec §41: Resource Bounds (OOM, ReDoS, memory safety)
- Spec §71: Error Handling (no unhandled raw parser exceptions)
- Spec §116: Test Data Privacy (never leak secrets in errors)
"""

import time
import unittest

from ulpf_parser_runtime.encoding import prepare_payload
from ulpf_parser_runtime.errors import ErrorCode
from ulpf_parser_runtime.framing import FramedRecord, RecordFramer
from ulpf_parser_runtime.models import ParseStatus
from ulpf_parser_runtime.parsers.json_parser import GenericJsonParser
from ulpf_parser_runtime.parsers.kv_parser import KeyValueParser
from ulpf_parser_runtime.parsers.xml_parser import XmlParser


def _record(text: str) -> FramedRecord:
    raw = text.encode()
    return FramedRecord(
        record_index=0,
        text=text,
        raw_bytes=raw,
        start_byte_offset=0,
        end_byte_offset=len(raw),
        line_count=text.count("\n") + 1,
    )


class TestReDoSSafety(unittest.TestCase):
    """Verify that regex engines execute linearly and do not suffer catastrophic backtracking."""

    def test_redos_adversarial_keyvalue(self) -> None:
        parser = KeyValueParser()
        # Pathological key-value pattern with unclosed quotes and repeating characters
        pathological = 'a="' + "b" * 10000 + ' c="' + "d" * 10000
        rec = _record(pathological)

        t0 = time.perf_counter()
        result = parser.parse(rec)
        elapsed = time.perf_counter() - t0

        # Must finish under 200 milliseconds (linear scan)
        self.assertLess(elapsed, 0.2)
        self.assertIn(result.status, [ParseStatus.PARSED, ParseStatus.PARTIAL])

    def test_redos_unmatched_delimiters(self) -> None:
        parser = KeyValueParser()
        pathological = "key=" + "foo=bar " * 500
        rec = _record(pathological)

        t0 = time.perf_counter()
        result = parser.parse(rec)
        elapsed = time.perf_counter() - t0

        self.assertLess(elapsed, 0.2)
        self.assertEqual(result.status, ParseStatus.PARSED)


class TestXXESafety(unittest.TestCase):
    """Verify XML External Entity (XXE) and billion-laughs injection protections."""

    def setUp(self) -> None:
        self.parser = XmlParser()

    def test_xxe_doctype_system_entity(self) -> None:
        xxe_payload = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE root [<!ENTITY secret SYSTEM "file:///etc/shadow">]>'
            "<root><data>&secret;</data></root>"
        )
        rec = _record(xxe_payload)
        result = self.parser.parse(rec)

        self.assertEqual(result.status, ParseStatus.FAILED)
        self.assertTrue(any(e.code == ErrorCode.SECURITY_POLICY_VIOLATION for e in result.errors))
        # Ensure secret path or contents are never in error message
        for err in result.errors:
            self.assertNotIn("/etc/shadow", err.message)

    def test_billion_laughs_dos_prevention(self) -> None:
        billion_laughs = (
            '<?xml version="1.0"?>'
            "<!DOCTYPE lolz ["
            ' <!ENTITY lol "lol">'
            ' <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
            ' <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">'
            "]>"
            "<lolz>&lol2;</lolz>"
        )
        rec = _record(billion_laughs)
        result = self.parser.parse(rec)

        self.assertEqual(result.status, ParseStatus.FAILED)
        self.assertTrue(any(e.code == ErrorCode.SECURITY_POLICY_VIOLATION for e in result.errors))


class TestResourceBoundsAndNestingLimits(unittest.TestCase):
    """Verify nesting limits, oversized payload boundaries, and memory protection."""

    def test_json_extreme_nesting_depth(self) -> None:
        # Depth of 100 exceeds default limit of 30
        deep_json = '{"level":' * 50 + '{"val": "bottom"}' + "}" * 50
        parser = GenericJsonParser(max_depth=10)
        rec = _record(deep_json)
        result = parser.parse(rec)

        # Must not crash, should produce warnings about nesting limit
        self.assertIn(result.status, [ParseStatus.PARSED, ParseStatus.PARTIAL])
        self.assertTrue(any(w.code == ErrorCode.NESTING_LIMIT_EXCEEDED for w in result.warnings))

    def test_xml_extreme_nesting_depth(self) -> None:
        deep_xml = "<r>" + "<sublevel>" * 50 + "<item>data</item>" + "</sublevel>" * 50 + "</r>"
        parser = XmlParser(max_depth=10)
        rec = _record(deep_xml)
        result = parser.parse(rec)

        self.assertIn(result.status, [ParseStatus.PARSED, ParseStatus.PARTIAL])
        self.assertTrue(any(w.code == ErrorCode.NESTING_LIMIT_EXCEEDED for w in result.warnings))

    def test_oversized_payload_intake_rejection(self) -> None:
        # Enforce max_payload_bytes
        huge_bytes = b"X" * (2 * 1024 * 1024)  # 2MB
        with self.assertRaises(ValueError):
            prepare_payload(huge_bytes, max_bytes=1024 * 1024)

    def test_framing_bounded_line_truncation(self) -> None:
        long_line = "A" * 10000 + "\n" + "B" * 100
        framer = RecordFramer(max_line_bytes=1000)
        res = framer.frame_lines(long_line)

        self.assertEqual(len(res.records), 2)
        self.assertTrue(res.records[0].is_truncated)
        self.assertEqual(len(res.records[0].text), 1000)


class TestPrivacyAndSecretIsolation(unittest.TestCase):
    """Verify that sensitive values or passwords are not leaked into error diagnostics."""

    def test_password_not_in_json_syntax_error(self) -> None:
        parser = GenericJsonParser()
        malformed = '{"username": "admin", "password": "SuperSecretPassword123!", broken}'
        rec = _record(malformed)
        result = parser.parse(rec)

        self.assertEqual(result.status, ParseStatus.FAILED)
        for err in result.errors:
            self.assertNotIn("SuperSecretPassword123!", err.message)


if __name__ == "__main__":
    unittest.main()
