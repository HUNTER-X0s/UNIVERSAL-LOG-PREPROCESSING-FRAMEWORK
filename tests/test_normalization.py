"""Unit tests for Phase 3 Normalization Plane and Universal Canonical Event (UCE).

Tests:
- Timestamp normalizer (ISO8601, RFC3164, CLF, epoch s/ms/us/ns, date+time)
- Severity normalizer (Syslog 0-7, CEF, text keywords)
- Network normalizer (IPv4, IPv6, port bounds, protocol mapping, metrics)
- Action normalizer (taxonomy mapping)
- Classification normalizer (category, type, class)
- UnknownFieldPreserver (zero loss)
- CanonicalEventBuilder (UCE contract generation)
- CanonicalEventValidator (validates against normalized-event.v1.schema.json)
- DLQEventBuilder (validates against dlq-event.v1.schema.json)
"""

import unittest

from ulpf_contracts.registry import ContractRegistry
from ulpf_normalization.canonical import CanonicalEventBuilder
from ulpf_normalization.dlq import DLQEventBuilder
from ulpf_normalization.normalizers.action import normalize_action
from ulpf_normalization.normalizers.classification import classify_event
from ulpf_normalization.normalizers.network import (
    normalize_direction,
    normalize_ip,
    normalize_metric,
    normalize_port,
    normalize_protocol,
)
from ulpf_normalization.normalizers.severity import normalize_severity
from ulpf_normalization.normalizers.timestamp import normalize_timestamp
from ulpf_normalization.unknown_fields import UnknownFieldPreserver
from ulpf_normalization.validation import CanonicalEventValidator
from ulpf_parser_runtime.errors import ErrorCode, ParseError
from ulpf_parser_runtime.framing import FramedRecord
from ulpf_parser_runtime.parsers.specialized.fortigate import FortiGateParser
from ulpf_parser_runtime.parsers.specialized.paloalto import PaloAltoPanOSParser


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


class TestTimestampNormalizer(unittest.TestCase):
    def test_iso8601_utc(self) -> None:
        raw = "2026-09-05T14:00:01Z"
        res = normalize_timestamp(raw)
        self.assertIn("2026-09-05T14:00:01", res)

    def test_iso8601_with_offset(self) -> None:
        raw = "2026-09-05T14:00:01+0000"
        res = normalize_timestamp(raw)
        self.assertIn("2026-09-05T14:00:01", res)

    def test_epoch_seconds(self) -> None:
        raw = 1620000000
        res = normalize_timestamp(raw)
        self.assertIn("2021-05-03T", res)

    def test_epoch_milliseconds(self) -> None:
        raw = 1620000000000
        res = normalize_timestamp(raw)
        self.assertIn("2021-05-03T", res)

    def test_syslog_rfc3164(self) -> None:
        raw = "Sep  5 14:00:00"
        res = normalize_timestamp(raw, reference_year=2026)
        self.assertIn("2026-09-05T14:00:00", res)

    def test_apache_clf(self) -> None:
        raw = "10/Oct/2026:13:55:36 +0000"
        res = normalize_timestamp(raw)
        self.assertIn("2026-10-10T13:55:36", res)

    def test_date_and_time_pair(self) -> None:
        res = normalize_timestamp(None, date_val="2026-09-05", time_val="14:00:00")
        self.assertIn("2026-09-05T14:00:00", res)


class TestSeverityNormalizer(unittest.TestCase):
    def test_syslog_severity_inverted(self) -> None:
        # Syslog 0 (Emergency) -> 10
        self.assertEqual(normalize_severity(0, is_syslog=True), 10)
        # Syslog 1 (Alert) -> 9
        self.assertEqual(normalize_severity(1, is_syslog=True), 9)
        # Syslog 2 (Critical) -> 8
        self.assertEqual(normalize_severity(2, is_syslog=True), 8)
        # Syslog 3 (Error) -> 7
        self.assertEqual(normalize_severity(3, is_syslog=True), 7)
        # Syslog 4 (Warning) -> 5
        self.assertEqual(normalize_severity(4, is_syslog=True), 5)
        # Syslog 6 (Informational) -> 2
        self.assertEqual(normalize_severity(6, is_syslog=True), 2)
        # Syslog 7 (Debug) -> 1
        self.assertEqual(normalize_severity(7, is_syslog=True), 1)

    def test_text_severity(self) -> None:
        self.assertEqual(normalize_severity("critical"), 8)
        self.assertEqual(normalize_severity("warning"), 5)
        self.assertEqual(normalize_severity("info"), 2)
        self.assertEqual(normalize_severity("emergency"), 10)


class TestNetworkNormalizer(unittest.TestCase):
    def test_valid_ipv4(self) -> None:
        self.assertEqual(normalize_ip("192.168.1.1"), "192.168.1.1")

    def test_valid_ipv6(self) -> None:
        self.assertEqual(normalize_ip("2001:db8::1"), "2001:db8::1")

    def test_invalid_ip(self) -> None:
        self.assertIsNone(normalize_ip("999.999.999.999"))
        self.assertIsNone(normalize_ip("not-an-ip"))

    def test_valid_port(self) -> None:
        self.assertEqual(normalize_port(443), 443)
        self.assertEqual(normalize_port("80"), 80)

    def test_invalid_port(self) -> None:
        self.assertIsNone(normalize_port(70000))
        self.assertIsNone(normalize_port(-1))
        self.assertIsNone(normalize_port("invalid"))

    def test_protocol_mapping(self) -> None:
        self.assertEqual(normalize_protocol("6"), "TCP")
        self.assertEqual(normalize_protocol("17"), "UDP")
        self.assertEqual(normalize_protocol("1"), "ICMP")
        self.assertEqual(normalize_protocol("tcp"), "TCP")

    def test_direction_normalization(self) -> None:
        self.assertEqual(normalize_direction("inbound"), "inbound")
        self.assertEqual(normalize_direction("out"), "outbound")
        self.assertEqual(normalize_direction("internal"), "internal")
        self.assertEqual(normalize_direction("unknown"), "unknown")

    def test_metric_normalization(self) -> None:
        self.assertEqual(normalize_metric(1024), 1024)
        self.assertEqual(normalize_metric("-5"), 0)
        self.assertEqual(normalize_metric(None), 0)


class TestActionNormalizer(unittest.TestCase):
    def test_action_taxonomy(self) -> None:
        self.assertEqual(normalize_action("allow"), "allow")
        self.assertEqual(normalize_action("permit"), "allow")
        self.assertEqual(normalize_action("accept"), "allow")
        self.assertEqual(normalize_action("deny"), "deny")
        self.assertEqual(normalize_action("block"), "deny")
        self.assertEqual(normalize_action("drop"), "drop")
        self.assertEqual(normalize_action("reject"), "reject")
        self.assertEqual(normalize_action("alert"), "alert")
        self.assertEqual(normalize_action("quarantine"), "quarantine")
        self.assertEqual(normalize_action("unknown"), "unknown")


class TestClassificationNormalizer(unittest.TestCase):
    def test_classify_paloalto(self) -> None:
        cat, ev_type, ev_class = classify_event(
            {}, "parser.paloalto.panos", vendor="Palo Alto Networks"
        )
        self.assertEqual(cat, "security")
        self.assertEqual(ev_type, "firewall")

    def test_classify_suricata_alert(self) -> None:
        cat, ev_type, ev_class = classify_event({"event_type": "alert"}, "parser.suricata.eve")
        self.assertEqual(cat, "security")
        self.assertEqual(ev_type, "alert")

    def test_classify_web_access(self) -> None:
        cat, ev_type, ev_class = classify_event({}, "parser.web.access")
        self.assertEqual(cat, "web")
        self.assertEqual(ev_type, "access")


class TestUnknownFieldPreservation(unittest.TestCase):
    def test_unmapped_keys_retained(self) -> None:
        extracted = {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "custom_vendor_flag": "0x40001",
            "internal_session_token": "abc-123",
        }
        mapped = {"src_ip", "dst_ip"}
        unmapped = UnknownFieldPreserver.preserve(extracted, mapped)
        self.assertIn("custom_vendor_flag", unmapped)
        self.assertEqual(unmapped["custom_vendor_flag"], "0x40001")
        self.assertIn("internal_session_token", unmapped)
        self.assertNotIn("src_ip", unmapped)


class TestCanonicalEventBuilderAndValidation(unittest.TestCase):
    def setUp(self) -> None:
        self.builder = CanonicalEventBuilder()
        self.validator = CanonicalEventValidator()
        self.dlq_builder = DLQEventBuilder()
        self.contracts = ContractRegistry()

    def test_build_and_validate_uce_from_paloalto(self) -> None:
        raw = "1,2026/09/05 14:00:01,001801000001,TRAFFIC,drop,2304,2026/09/05 14:00:00,198.51.100.25,203.0.113.10,0.0.0.0,0.0.0.0,Block_External_Scan,,,not-applicable,vsys1,untrust,trust,ethernet1/1,,Syslog_Forwarder,2026/09/05 14:00:01,0,1,54321,23,0,0,0x0,tcp,deny,60,60,0,1,2026/09/05 14:00:00,0,any,0,12345678,0x0,United States,India,0,1,0,policy-deny,0,0,0,0,,PA-VM,from-policy"
        parser = PaloAltoPanOSParser()
        rec = _record(raw)
        res = parser.parse(rec)

        uce = self.builder.build_uce(
            res,
            raw_payload_bytes=raw.encode(),
            vendor="Palo Alto Networks",
            product="PAN-OS",
        )

        self.assertEqual(uce["contract_version"], "1.0.0")
        self.assertIn("event", uce)
        self.assertEqual(uce["event"]["source"]["ip"], "198.51.100.25")
        self.assertEqual(uce["event"]["destination"]["ip"], "203.0.113.10")
        self.assertEqual(uce["event"]["action"], "deny")

        # Validate against authoritative JSON Schema
        val_res = self.validator.validate_canonical(uce)
        self.assertTrue(val_res.valid, f"Validation errors: {val_res.errors}")

    def test_build_and_validate_uce_from_fortigate(self) -> None:
        raw = 'date=2026-09-05 time=14:00:00 devname="FGT-CORP-01" devid="FGT60E4Q17012345" eventtime=1620000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.10.10.25 srcport=51234 srcintf="port1" dstip=198.51.100.40 dstport=443 dstintf="port2" proto=6 action="accept" sentbyte=1250 rcvdbyte=8900'
        parser = FortiGateParser()
        rec = _record(raw)
        res = parser.parse(rec)

        uce = self.builder.build_uce(
            res,
            raw_payload_bytes=raw.encode(),
            vendor="Fortinet",
            product="FortiGate",
        )

        val_res = self.validator.validate_canonical(uce)
        self.assertTrue(val_res.valid, f"Validation errors: {val_res.errors}")

    def test_build_and_validate_dlq_event(self) -> None:
        err = ParseError(
            code=ErrorCode.MALFORMED_JSON,
            stage="json_parser",
            message="Invalid JSON token",
            recoverable=False,
        )
        raw_bytes = b'{"broken: json'
        dlq = self.dlq_builder.build_dlq_event(
            error=err,
            raw_payload_bytes=raw_bytes,
            parser_id="parser.generic.json",
        )

        val_res = self.contracts.validate("dlq-event.v1.schema.json", dlq)
        self.assertTrue(val_res.valid, f"DLQ validation errors: {val_res.errors}")


if __name__ == "__main__":
    unittest.main()
