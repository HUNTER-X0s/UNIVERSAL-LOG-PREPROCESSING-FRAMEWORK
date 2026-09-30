"""Regression test suite for ULPF Ground Truth Expected Output Fixtures.

Validates that every vendor parser in data/reference/expected_outputs/
correctly transforms raw vendor logs into expected Universal Canonical Event (UCE) v1
structures with full schema adherence and field integrity.
"""

import json
import unittest
from pathlib import Path

from ulpf_parser_runtime.framing import RecordFramer
from ulpf_normalization.canonical import CanonicalEventBuilder

from ulpf_parser_runtime.parsers.specialized.paloalto import PaloAltoPanOSParser
from ulpf_parser_runtime.parsers.specialized.fortigate import FortiGateParser
from ulpf_parser_runtime.parsers.specialized.cisco import CiscoSyslogParser
from ulpf_parser_runtime.parsers.specialized.suricata import SuricataEveParser
from ulpf_parser_runtime.parsers.specialized.zeek import ZeekParser
from ulpf_parser_runtime.parsers.specialized.snort import SnortFastParser
from ulpf_parser_runtime.parsers.specialized.opnsense import OPNsenseFilterlogParser
from ulpf_parser_runtime.parsers.specialized.linux_auditd import LinuxAuditdParser
from ulpf_parser_runtime.parsers.specialized.cloud_audit import CloudAuditParser
from ulpf_parser_runtime.parsers.specialized.web_access import WebAccessLogParser

from ulpf_parser_runtime.parsers.cef_parser import CefParser
from ulpf_parser_runtime.parsers.leef_parser import LeefParser
from ulpf_parser_runtime.parsers.syslog_rfc5424 import SyslogRFC5424Parser
from ulpf_parser_runtime.parsers.syslog_rfc3164 import SyslogRFC3164Parser
from ulpf_parser_runtime.parsers.json_parser import GenericJsonParser
from ulpf_parser_runtime.parsers.xml_parser import XmlParser

FIXTURES_DIR = Path("data/reference/expected_outputs")

PARSER_MAP = {
    "paloalto": (PaloAltoPanOSParser(), "raw_input.log", "Palo Alto Networks", "PA-Series Firewall"),
    "fortigate": (FortiGateParser(), "raw_input.log", "Fortinet", "FortiGate UTM"),
    "cisco_asa": (CiscoSyslogParser(), "raw_input.log", "Cisco", "Adaptive Security Appliance (ASA)"),
    "suricata": (SuricataEveParser(), "raw_input.json", "OISF", "Suricata EVE IDS/IPS"),
    "zeek": (ZeekParser(), "raw_input.tsv", "Zeek", "Zeek Network Security Monitor"),
    "snort": (SnortFastParser(), "raw_input.log", "Cisco / Sourcefire", "Snort IDS"),
    "opnsense": (OPNsenseFilterlogParser(), "raw_input.log", "Deciso", "OPNsense Firewall"),
    "linux_auditd": (LinuxAuditdParser(), "raw_input.log", "Linux Foundation", "Linux Kernel Auditd"),
    "aws_cloudtrail": (CloudAuditParser(), "raw_input.json", "Amazon Web Services", "AWS CloudTrail"),
    "web_access": (WebAccessLogParser(), "raw_input.log", "Apache / Nginx", "Combined Web Access Log"),
    "cef": (CefParser(), "raw_input.log", "Micro Focus / ArcSight", "Common Event Format (CEF)"),
    "leef": (LeefParser(), "raw_input.log", "IBM", "QRadar LEEF"),
    "syslog_rfc5424": (SyslogRFC5424Parser(), "raw_input.log", "IETF", "RFC 5424 Syslog Protocol"),
    "syslog_rfc3164": (SyslogRFC3164Parser(), "raw_input.log", "IETF", "RFC 3164 BSD Syslog"),
    "windows_security": (XmlParser(), "raw_input.xml", "Microsoft", "Windows Security / Sysmon XML"),
    "gcp_audit": (GenericJsonParser(), "raw_input.json", "Google Cloud", "GCP Cloud Audit Logs"),
    "azure_activity": (GenericJsonParser(), "raw_input.json", "Microsoft Azure", "Azure Monitor Activity Log"),
    "okta": (GenericJsonParser(), "raw_input.json", "Okta", "Okta Identity Cloud"),
    "crowdstrike": (GenericJsonParser(), "raw_input.json", "CrowdStrike", "CrowdStrike Falcon Sensor"),
    "falco": (GenericJsonParser(), "raw_input.json", "CNCF / Sysdig", "Falco Runtime Security"),
}


class TestExpectedOutputFixtures(unittest.TestCase):
    def setUp(self):
        self.framer = RecordFramer()
        self.builder = CanonicalEventBuilder()

    def _verify_vendor_fixture(self, vendor_id: str):
        self.assertIn(vendor_id, PARSER_MAP, f"Vendor {vendor_id} not configured in test map")
        parser, raw_filename, vendor, product = PARSER_MAP[vendor_id]
        
        vendor_dir = FIXTURES_DIR / vendor_id
        self.assertTrue(vendor_dir.exists(), f"Fixture directory for {vendor_id} does not exist")
        
        raw_path = vendor_dir / raw_filename
        expected_path = vendor_dir / "expected_uce.json"
        
        self.assertTrue(raw_path.exists(), f"Raw sample {raw_path} not found")
        self.assertTrue(expected_path.exists(), f"Expected UCE {expected_path} not found")
        
        raw_text = raw_path.read_text(encoding="utf-8").strip()
        with open(expected_path, "r", encoding="utf-8") as f:
            expected_uce = json.load(f)
            
        # Parse and build UCE
        framed = self.framer.frame_single(raw_text)
        self.assertGreater(len(framed.records), 0, f"Failed to frame record for {vendor_id}")
        
        record = framed.records[0]
        parse_result = parser.parse(record)
        self.assertEqual(parse_result.status.value, "parsed", f"Parser status for {vendor_id} is not 'parsed'")
        
        actual_uce = self.builder.build_uce(
            parse_result=parse_result,
            raw_payload_bytes=record.raw_bytes,
            vendor=vendor,
            product=product
        )
        
        # Verify schema invariants
        self.assertEqual(actual_uce["contract_version"], "1.0.0")
        self.assertIn("event", actual_uce)
        self.assertIn("time", actual_uce["event"])
        self.assertIn("category", actual_uce["event"])
        self.assertIn("metadata", actual_uce["event"])
        self.assertIn("processing", actual_uce)
        self.assertIn("field_provenance", actual_uce)
        self.assertIn("unmapped_fields", actual_uce)
        
        # Compare core semantic extractions against ground truth
        self.assertEqual(actual_uce["event"]["category"], expected_uce["event"]["category"])
        self.assertEqual(actual_uce["event"]["type"], expected_uce["event"]["type"])
        
        if "action" in expected_uce["event"] and expected_uce["event"]["action"]:
            self.assertEqual(actual_uce["event"].get("action"), expected_uce["event"]["action"])
            
        if "source" in expected_uce["event"] and "ip" in expected_uce["event"]["source"]:
            self.assertEqual(actual_uce["event"]["source"]["ip"], expected_uce["event"]["source"]["ip"])
            
        if "destination" in expected_uce["event"] and "ip" in expected_uce["event"]["destination"]:
            self.assertEqual(actual_uce["event"]["destination"]["ip"], expected_uce["event"]["destination"]["ip"])
            
        # Check unmapped fields coverage
        self.assertEqual(
            set(actual_uce["unmapped_fields"].keys()),
            set(expected_uce["unmapped_fields"].keys()),
            f"Unmapped fields keys mismatch for {vendor_id}"
        )


# Dynamically generate individual test methods for all 20 vendors
def _make_test(v_id):
    def test(self):
        self._verify_vendor_fixture(v_id)
    return test

for vendor_id in PARSER_MAP:
    setattr(TestExpectedOutputFixtures, f"test_fixture_{vendor_id}", _make_test(vendor_id))

if __name__ == "__main__":
    unittest.main()
