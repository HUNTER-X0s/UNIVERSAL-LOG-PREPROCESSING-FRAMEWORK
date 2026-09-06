"""Unit tests for Phase 3 Tier B and Tier C specialized parsers using real-world fixtures.

Tests:
- PaloAltoPanOSParser on panos_traffic.log and panos_threat.log
- FortiGateParser on fortigate_utm.log
- CiscoSyslogParser on cisco_asa.log
- SuricataEveParser on suricata_eve.json
- OPNsenseFilterlogParser on opnsense_filterlog.log
- SnortFastParser on snort_fast.log
- WebAccessLogParser on Apache/NGINX CLF
- ZeekParser on Zeek TSV / JSON
- CloudAuditParser on AWS CloudTrail and VPC Flow
- LinuxAuditdParser on Linux auditd lines
"""

import unittest
from pathlib import Path

from ulpf_parser_runtime.framing import FramedRecord
from ulpf_parser_runtime.models import ParseStatus
from ulpf_parser_runtime.parsers.specialized.cisco import CiscoSyslogParser
from ulpf_parser_runtime.parsers.specialized.cloud_audit import CloudAuditParser
from ulpf_parser_runtime.parsers.specialized.fortigate import FortiGateParser
from ulpf_parser_runtime.parsers.specialized.linux_auditd import LinuxAuditdParser
from ulpf_parser_runtime.parsers.specialized.opnsense import OPNsenseFilterlogParser
from ulpf_parser_runtime.parsers.specialized.paloalto import PaloAltoPanOSParser
from ulpf_parser_runtime.parsers.specialized.snort import SnortFastParser
from ulpf_parser_runtime.parsers.specialized.suricata import SuricataEveParser
from ulpf_parser_runtime.parsers.specialized.web_access import WebAccessLogParser
from ulpf_parser_runtime.parsers.specialized.zeek import ZeekParser
from ulpf_parser_runtime.registry import create_default_registry

FIXTURES_DIR = Path("data/fixtures/real_world")


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


class TestPaloAltoParser(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = PaloAltoPanOSParser()

    def test_parse_panos_traffic_fixture(self) -> None:
        fixture_path = FIXTURES_DIR / "network_security" / "paloalto" / "panos_traffic.log"
        if not fixture_path.exists():
            self.skipTest("Fixture missing")

        lines = fixture_path.read_text(encoding="utf-8").splitlines()
        first_line = lines[0]
        rec = _record(first_line)
        result = self.parser.parse(rec)

        self.assertEqual(result.status, ParseStatus.PARSED)
        self.assertEqual(result.extracted_fields["type"].value, "TRAFFIC")
        self.assertEqual(result.extracted_fields["src_ip"].value, "198.51.100.25")
        self.assertEqual(result.extracted_fields["dst_ip"].value, "203.0.113.10")
        self.assertEqual(result.extracted_fields["action"].value, "deny")
        self.assertEqual(result.extracted_fields["protocol"].value, "tcp")

    def test_parse_panos_threat_fixture(self) -> None:
        fixture_path = FIXTURES_DIR / "network_security" / "paloalto" / "panos_threat.log"
        if not fixture_path.exists():
            self.skipTest("Fixture missing")

        lines = fixture_path.read_text(encoding="utf-8").splitlines()
        first_line = lines[0]
        rec = _record(first_line)
        result = self.parser.parse(rec)

        self.assertEqual(result.status, ParseStatus.PARSED)
        self.assertEqual(result.extracted_fields["type"].value, "THREAT")


class TestFortiGateParser(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = FortiGateParser()

    def test_parse_fortigate_utm_fixture(self) -> None:
        fixture_path = FIXTURES_DIR / "network_security" / "fortinet" / "fortigate_utm.log"
        if not fixture_path.exists():
            self.skipTest("Fixture missing")

        lines = fixture_path.read_text(encoding="utf-8").splitlines()
        first_line = lines[0]
        rec = _record(first_line)
        result = self.parser.parse(rec)

        self.assertEqual(result.status, ParseStatus.PARSED)
        self.assertEqual(result.extracted_fields["devname"].value, "FGT-CORP-01")
        self.assertEqual(result.extracted_fields["srcip"].value, "10.10.10.25")
        self.assertEqual(result.extracted_fields["dstip"].value, "198.51.100.40")
        self.assertEqual(result.extracted_fields["action"].value, "accept")
        self.assertEqual(result.extracted_fields["type"].value, "traffic")


class TestCiscoSyslogParser(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = CiscoSyslogParser()

    def test_parse_cisco_asa_fixture(self) -> None:
        fixture_path = FIXTURES_DIR / "network_security" / "cisco_asa" / "cisco_asa.log"
        if not fixture_path.exists():
            self.skipTest("Fixture missing")

        lines = fixture_path.read_text(encoding="utf-8").splitlines()
        first_line = lines[0]
        rec = _record(first_line)
        result = self.parser.parse(rec)

        self.assertEqual(result.status, ParseStatus.PARSED)
        self.assertEqual(result.extracted_fields["cisco_facility"].value, "ASA")
        self.assertEqual(result.extracted_fields["cisco_severity"].value, 6)
        self.assertEqual(result.extracted_fields["cisco_mnemonic"].value, "302013")
        self.assertEqual(result.extracted_fields["action"].value, "built")
        self.assertEqual(result.extracted_fields["src_ip"].value, "198.51.100.50")
        self.assertEqual(result.extracted_fields["src_port"].value, "54321")

    def test_parse_cisco_deny(self) -> None:
        raw = 'Sep  5 14:00:02 fw %ASA-4-106023: Deny tcp src outside:203.0.113.88/61234 dst inside:10.0.0.1/445 by access-group "OUTSIDE-IN"'
        rec = _record(raw)
        result = self.parser.parse(rec)

        self.assertEqual(result.status, ParseStatus.PARSED)
        self.assertEqual(result.extracted_fields["action"].value, "deny")
        self.assertEqual(result.extracted_fields["access_group"].value, "OUTSIDE-IN")


class TestSuricataParser(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = SuricataEveParser()

    def test_parse_suricata_eve_fixture(self) -> None:
        fixture_path = FIXTURES_DIR / "network_security" / "suricata" / "suricata_eve.json"
        if not fixture_path.exists():
            self.skipTest("Fixture missing")

        lines = [
            line for line in fixture_path.read_text(encoding="utf-8").splitlines() if line.strip()
        ]
        first_line = lines[0]
        rec = _record(first_line)
        result = self.parser.parse(rec)

        self.assertEqual(result.status, ParseStatus.PARSED)
        self.assertEqual(result.extracted_fields["event_type"].value, "alert")
        self.assertEqual(result.extracted_fields["src_ip"].value, "198.51.100.200")
        self.assertEqual(result.extracted_fields["alert.signature_id"].value, 2010935)
        self.assertEqual(result.extracted_fields["alert.severity"].value, 3)


class TestOPNsenseParser(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = OPNsenseFilterlogParser()

    def test_parse_opnsense_filterlog_fixture(self) -> None:
        fixture_path = FIXTURES_DIR / "network_security" / "opnsense" / "opnsense_filterlog.log"
        if not fixture_path.exists():
            self.skipTest("Fixture missing")

        lines = fixture_path.read_text(encoding="utf-8").splitlines()
        first_line = lines[0]
        rec = _record(first_line)
        result = self.parser.parse(rec)

        self.assertEqual(result.status, ParseStatus.PARSED)
        self.assertEqual(result.extracted_fields["action"].value, "block")
        self.assertEqual(result.extracted_fields["interface"].value, "vtnet0")
        self.assertEqual(result.extracted_fields["src_ip"].value, "198.51.100.99")
        self.assertEqual(result.extracted_fields["dst_port"].value, "445")


class TestSnortParser(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = SnortFastParser()

    def test_parse_snort_fast_fixture(self) -> None:
        fixture_path = FIXTURES_DIR / "network_security" / "snort" / "snort_fast.log"
        if not fixture_path.exists():
            self.skipTest("Fixture missing")

        lines = fixture_path.read_text(encoding="utf-8").splitlines()
        first_line = lines[0]
        rec = _record(first_line)
        result = self.parser.parse(rec)

        self.assertEqual(result.status, ParseStatus.PARSED)
        self.assertEqual(result.extracted_fields["gid"].value, "1")
        self.assertEqual(result.extracted_fields["sid"].value, "1000001")
        self.assertIn("COMMUNITY WEB-ATTACK", result.extracted_fields["signature"].value)
        self.assertEqual(result.extracted_fields["src_ip"].value, "198.51.100.15")
        self.assertEqual(result.extracted_fields["src_port"].value, "49152")
        self.assertEqual(result.extracted_fields["dst_port"].value, "80")


class TestWebAccessParser(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = WebAccessLogParser()

    def test_parse_combined_access_log(self) -> None:
        raw = '192.168.1.100 - admin [10/Oct/2026:13:55:36 +0000] "GET /api/v1/health HTTP/1.1" 200 1024 "https://example.com" "Mozilla/5.0"'
        rec = _record(raw)
        result = self.parser.parse(rec)

        self.assertEqual(result.status, ParseStatus.PARSED)
        self.assertEqual(result.extracted_fields["client_ip"].value, "192.168.1.100")
        self.assertEqual(result.extracted_fields["remote_user"].value, "admin")
        self.assertEqual(result.extracted_fields["http_method"].value, "GET")
        self.assertEqual(result.extracted_fields["request_uri"].value, "/api/v1/health")
        self.assertEqual(result.extracted_fields["status_code"].value, 200)
        self.assertEqual(result.extracted_fields["response_bytes"].value, 1024)


class TestZeekParser(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = ZeekParser()

    def test_parse_zeek_tsv(self) -> None:
        raw = "1620000000.123\tC123456\t192.168.1.10\t49152\t10.0.0.1\t443\ttcp\tssl\t12.5\t1024\t8192\tSF\t-\t-\t0\tShADadfF\t10\t1500\t14\t8600\t-"
        rec = _record(raw)
        result = self.parser.parse(rec)

        self.assertEqual(result.status, ParseStatus.PARSED)
        self.assertEqual(result.extracted_fields["uid"].value, "C123456")
        self.assertEqual(result.extracted_fields["id.orig_h"].value, "192.168.1.10")
        self.assertEqual(result.extracted_fields["id.resp_p"].value, "443")
        self.assertEqual(result.extracted_fields["proto"].value, "tcp")


class TestCloudAuditParser(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = CloudAuditParser()

    def test_parse_aws_cloudtrail(self) -> None:
        raw = '{"eventVersion":"1.08","userIdentity":{"type":"IAMUser","userName":"alice"},"eventTime":"2026-09-05T14:00:00Z","eventSource":"s3.amazonaws.com","eventName":"GetObject","awsRegion":"us-east-1","sourceIPAddress":"198.51.100.1"}'
        rec = _record(raw)
        result = self.parser.parse(rec)

        self.assertEqual(result.status, ParseStatus.PARSED)
        self.assertEqual(result.extracted_fields["eventSource"].value, "s3.amazonaws.com")
        self.assertEqual(result.extracted_fields["eventName"].value, "GetObject")
        self.assertEqual(result.extracted_fields["userIdentity.userName"].value, "alice")
        self.assertEqual(result.extracted_fields["cloud_provider"].value, "AWS")

    def test_parse_aws_vpc_flow(self) -> None:
        raw = "2 123456789010 eni-1235b8ca123456789 198.51.100.10 10.0.0.5 49152 443 6 20 8400 1620000000 1620000060 ACCEPT OK"
        rec = _record(raw)
        result = self.parser.parse(rec)

        self.assertEqual(result.status, ParseStatus.PARSED)
        self.assertEqual(result.extracted_fields["src_addr"].value, "198.51.100.10")
        self.assertEqual(result.extracted_fields["dst_addr"].value, "10.0.0.5")
        self.assertEqual(result.extracted_fields["action"].value, "ACCEPT")


class TestLinuxAuditdParser(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = LinuxAuditdParser()

    def test_parse_auditd_syscall(self) -> None:
        raw = 'type=SYSCALL msg=audit(1620000000.123:456): arch=c000003e syscall=59 success=yes exit=0 a0=7ffd01 a1=7ffd02 a2=7ffd03 a3=7ffd04 items=2 ppid=1000 pid=1234 auid=1000 uid=0 gid=0 euid=0 comm="sudo" exe="/usr/bin/sudo" key="priv_esc"'
        rec = _record(raw)
        result = self.parser.parse(rec)

        self.assertEqual(result.status, ParseStatus.PARSED)
        self.assertEqual(result.extracted_fields["record_type"].value, "SYSCALL")
        self.assertEqual(result.extracted_fields["audit_epoch"].value, "1620000000.123")
        self.assertEqual(result.extracted_fields["comm"].value, "sudo")
        self.assertEqual(result.extracted_fields["exe"].value, "/usr/bin/sudo")
        self.assertEqual(result.extracted_fields["key"].value, "priv_esc")


class TestSpecializedRegistryIntegration(unittest.TestCase):
    def test_registry_specialized_selection(self) -> None:
        reg = create_default_registry()
        # Verify Palo Alto PAN-OS selection over generic CSV
        sel_pa = reg.select_parser("csv", vendor="Palo Alto Networks", product="PAN-OS")
        self.assertIsNotNone(sel_pa)
        assert sel_pa is not None
        self.assertEqual(sel_pa.selected_parser.parser_id, "parser.paloalto.panos")

        # Verify FortiGate selection over generic key_value
        sel_fg = reg.select_parser("key_value", vendor="Fortinet", product="FortiGate")
        self.assertIsNotNone(sel_fg)
        assert sel_fg is not None
        self.assertEqual(sel_fg.selected_parser.parser_id, "parser.fortinet.fortigate")

        # Verify Suricata selection over generic JSON
        sel_suri = reg.select_parser("json", vendor="Suricata", product="EVE")
        self.assertIsNotNone(sel_suri)
        assert sel_suri is not None
        self.assertEqual(sel_suri.selected_parser.parser_id, "parser.suricata.eve")


if __name__ == "__main__":
    unittest.main()
