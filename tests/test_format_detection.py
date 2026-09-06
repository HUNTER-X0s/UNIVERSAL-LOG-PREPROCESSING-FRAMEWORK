"""Unit tests for format detection, source detection, and ParserRegistry."""

import unittest

from ulpf_parser_runtime.detection.format_detector import FormatDetector
from ulpf_parser_runtime.detection.source_detector import SourceDetector
from ulpf_parser_runtime.framing import FramedRecord
from ulpf_parser_runtime.models import ParseResult, ParserMetadata, ParseStatus
from ulpf_parser_runtime.parsers.base import BaseParser
from ulpf_parser_runtime.registry import ParserRegistry


class DummyGenericJsonParser(BaseParser):
    metadata = ParserMetadata(
        parser_id="parser.generic.json",
        version="1.0.0",
        supported_formats=("json", "ndjson"),
        supported_vendors=(),
        supported_products=(),
        tier="A",
        description="Generic JSON parser",
    )

    def parse(self, record: FramedRecord) -> ParseResult:
        return ParseResult(
            status=ParseStatus.PARSED,
            parser_id=self.metadata.parser_id,
            parser_version=self.metadata.version,
            format="json",
        )


class DummySuricataParser(BaseParser):
    metadata = ParserMetadata(
        parser_id="parser.suricata.eve",
        version="1.0.0",
        supported_formats=("json", "ndjson"),
        supported_vendors=("Suricata",),
        supported_products=("EVE",),
        tier="B",
        description="Suricata EVE JSON parser",
    )

    def parse(self, record: FramedRecord) -> ParseResult:
        return ParseResult(
            status=ParseStatus.PARSED,
            parser_id=self.metadata.parser_id,
            parser_version=self.metadata.version,
            format="json",
        )


class TestFormatDetector(unittest.TestCase):
    """Test suite for deterministic scored format detection."""

    def setUp(self) -> None:
        self.detector = FormatDetector()

    def test_detect_cef(self) -> None:
        sample = "CEF:0|Cisco|ASA|9.14|106023|Deny tcp src|5|src=10.0.0.1 dst=192.168.1.1\n"
        best, candidates, ambiguous = self.detector.detect(sample)
        self.assertEqual(best.format_name, "cef")
        self.assertGreaterEqual(best.score, 0.95)
        self.assertFalse(ambiguous)

    def test_detect_leef(self) -> None:
        sample = "LEEF:2.0|Microsoft|MSExchange|2013|AuthFail|src=10.0.0.5\n"
        best, candidates, ambiguous = self.detector.detect(sample)
        self.assertEqual(best.format_name, "leef")
        self.assertGreaterEqual(best.score, 0.95)

    def test_detect_json(self) -> None:
        sample = '{"event": "firewall_drop", "src_ip": "10.0.0.1", "action": "deny"}\n'
        best, candidates, ambiguous = self.detector.detect(sample)
        self.assertEqual(best.format_name, "json")
        self.assertGreaterEqual(best.score, 0.95)

    def test_detect_ndjson(self) -> None:
        sample = '{"id": 1}\n{"id": 2}\n{"id": 3}\n'
        best, candidates, ambiguous = self.detector.detect(sample)
        self.assertEqual(best.format_name, "ndjson")
        self.assertGreaterEqual(best.score, 0.95)

    def test_detect_syslog_5424(self) -> None:
        sample = '<165>1 2026-09-06T01:00:00.000Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3"] BOMAn application event'
        best, candidates, ambiguous = self.detector.detect(sample)
        self.assertEqual(best.format_name, "syslog_rfc5424")
        self.assertGreaterEqual(best.score, 0.95)

    def test_detect_syslog_3164(self) -> None:
        sample = "<34>Oct 11 22:14:15 mymachine su[123]: 'su root' failed for lonvick\n"
        best, candidates, ambiguous = self.detector.detect(sample)
        self.assertEqual(best.format_name, "syslog_rfc3164")
        self.assertGreaterEqual(best.score, 0.90)

    def test_detect_xml(self) -> None:
        sample = '<?xml version="1.0" encoding="utf-8"?><Event><EventID>4624</EventID></Event>\n'
        best, candidates, ambiguous = self.detector.detect(sample)
        self.assertEqual(best.format_name, "xml")
        self.assertGreaterEqual(best.score, 0.95)

    def test_detect_w3c(self) -> None:
        sample = "#Software: Microsoft Internet Information Services 8.5\n#Version: 1.0\n#Fields: date time s-ip cs-method cs-uri-stem\n2026-09-06 01:00:00 10.0.0.1 GET /index.html\n"
        best, candidates, ambiguous = self.detector.detect(sample)
        self.assertEqual(best.format_name, "w3c")
        self.assertGreaterEqual(best.score, 0.95)

    def test_detect_cri(self) -> None:
        sample = "2026-09-06T01:00:00.123456789Z stdout F Container log message line\n"
        best, candidates, ambiguous = self.detector.detect(sample)
        self.assertEqual(best.format_name, "cri")
        self.assertGreaterEqual(best.score, 0.90)

    def test_detect_clf(self) -> None:
        sample = '127.0.0.1 - frank [10/Oct/2026:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326\n'
        best, candidates, ambiguous = self.detector.detect(sample)
        self.assertEqual(best.format_name, "clf")
        self.assertGreaterEqual(best.score, 0.90)

    def test_detect_kv(self) -> None:
        sample = "device=router1 interface=eth0 status=up proto=ospf area=0\n"
        best, candidates, ambiguous = self.detector.detect(sample)
        self.assertEqual(best.format_name, "kv")
        self.assertGreaterEqual(best.score, 0.70)

    def test_detect_empty_unknown(self) -> None:
        best, candidates, ambiguous = self.detector.detect("   \n\t")
        self.assertEqual(best.format_name, "unknown")
        self.assertEqual(best.score, 0.0)


class TestSourceDetector(unittest.TestCase):
    """Test suite for decoupled source and vendor detection."""

    def setUp(self) -> None:
        self.detector = SourceDetector()

    def test_detect_cisco_asa(self) -> None:
        msg = "<166>Sep 06 2026 01:00:00: %ASA-6-302013: Built inbound TCP connection 12345 for outside:192.168.1.1/443"
        source, candidates = self.detector.detect(msg)
        self.assertIsNotNone(source)
        assert source is not None
        self.assertEqual(source.vendor, "Cisco")
        self.assertEqual(source.product, "ASA")

    def test_detect_fortigate(self) -> None:
        msg = 'date=2026-09-06 time=01:00:00 devname="FGT60D4614041793" type="traffic" subtype="forward" level="notice" action="accept"'
        source, candidates = self.detector.detect(msg)
        self.assertIsNotNone(source)
        assert source is not None
        self.assertEqual(source.vendor, "Fortinet")
        self.assertEqual(source.product, "FortiGate")

    def test_detect_paloalto(self) -> None:
        msg = "1,2026/09/06 01:00:00,001234567890,TRAFFIC,drop,1,2026/09/06 01:00:00,10.0.0.1,172.16.0.1"
        source, candidates = self.detector.detect(msg)
        self.assertIsNotNone(source)
        assert source is not None
        self.assertEqual(source.vendor, "Palo Alto Networks")
        self.assertEqual(source.product, "PAN-OS")

    def test_detect_suricata_eve(self) -> None:
        msg = '{"timestamp":"2026-09-06T01:00:00.000000+0000","flow_id":123456789,"event_type":"alert","src_ip":"10.0.0.1","alert":{"action":"allowed"}}'
        source, candidates = self.detector.detect(msg, format_name="json")
        self.assertIsNotNone(source)
        assert source is not None
        self.assertEqual(source.vendor, "Suricata")
        self.assertEqual(source.product, "EVE")

    def test_detect_aws_cloudtrail(self) -> None:
        msg = '{"eventVersion":"1.08","userIdentity":{"type":"IAMUser"},"eventSource":"s3.amazonaws.com","eventName":"GetObject","awsRegion":"us-east-1"}'
        source, candidates = self.detector.detect(msg, format_name="json")
        self.assertIsNotNone(source)
        assert source is not None
        self.assertEqual(source.vendor, "AWS")
        self.assertEqual(source.product, "CloudTrail")

    def test_detect_opnsense_filterlog(self) -> None:
        msg = "filterlog: 5,,,1000000103,igb0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,192.168.1.100,10.0.0.1,54321,443,0,S,12345,,65535,,mss;sackOK;TS"
        source, candidates = self.detector.detect(msg)
        self.assertIsNotNone(source)
        assert source is not None
        self.assertEqual(source.vendor, "OPNsense")


class TestParserRegistry(unittest.TestCase):
    """Test suite for parser registration, discovery, priority resolution, and catalog."""

    def setUp(self) -> None:
        self.registry = ParserRegistry()
        self.generic_json = DummyGenericJsonParser()
        self.suricata = DummySuricataParser()
        self.registry.register(self.generic_json, priority=10)
        self.registry.register(self.suricata, priority=60)

    def test_list_parsers(self) -> None:
        parsers = self.registry.list_parsers()
        self.assertEqual(len(parsers), 2)
        ids = [p.parser_id for p in parsers]
        self.assertEqual(ids, ["parser.generic.json", "parser.suricata.eve"])

    def test_select_specialized_over_generic(self) -> None:
        # For Suricata event (json, vendor=Suricata, product=EVE), suricata parser should win
        selection = self.registry.select_parser("json", vendor="Suricata", product="EVE")
        self.assertIsNotNone(selection)
        assert selection is not None
        self.assertEqual(selection.selected_parser.parser_id, "parser.suricata.eve")

    def test_select_generic_fallback(self) -> None:
        # For generic json with unknown vendor, generic json parser should be selected
        selection = self.registry.select_parser("json", vendor="UnknownVendor")
        self.assertIsNotNone(selection)
        assert selection is not None
        self.assertEqual(selection.selected_parser.parser_id, "parser.generic.json")

    def test_self_description_catalog(self) -> None:
        desc = self.registry.self_description()
        self.assertEqual(desc["total_parsers"], 2)
        self.assertIn("json", desc["supported_formats"])
        self.assertIn("Suricata", desc["supported_vendors"])


if __name__ == "__main__":
    unittest.main()
