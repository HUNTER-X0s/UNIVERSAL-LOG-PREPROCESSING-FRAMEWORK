"""Cross-vendor semantic convergence tests for ULPF Phase 4.

Demonstrates that heterogeneous vendor telemetry (Palo Alto, Fortinet, Cisco, Suricata,
Zeek, AWS, NGINX) converges on unified semantic triples and normalized actions while
fully preserving vendor-specific attributes and projecting into OCSF and OTel.
"""

import unittest

from ulpf_normalization.canonical import CanonicalEventBuilder
from ulpf_parser_runtime.framing import FramedRecord
from ulpf_parser_runtime.parsers.specialized.cisco import CiscoSyslogParser
from ulpf_parser_runtime.parsers.specialized.cloud_audit import CloudAuditParser
from ulpf_parser_runtime.parsers.specialized.fortigate import FortiGateParser
from ulpf_parser_runtime.parsers.specialized.paloalto import PaloAltoPanOSParser
from ulpf_parser_runtime.parsers.specialized.suricata import SuricataEveParser
from ulpf_parser_runtime.parsers.specialized.web_access import WebAccessLogParser
from ulpf_semantic.service import SemanticService
from ulpf_semantic.validation import SemanticEventValidator


class TestCrossVendorSemanticConvergence(unittest.TestCase):
    def setUp(self) -> None:
        self.canonical_builder = CanonicalEventBuilder()
        self.service = SemanticService()
        self.validator = SemanticEventValidator()

    def test_firewall_cross_vendor_convergence(self) -> None:
        """Palo Alto, Fortinet, and Cisco ASA all converge on (SECURITY, Firewall, firewall.deny)."""
        # 1. Palo Alto Threat Log (Drop)
        pan_raw = (
            "1,2026/09/06 10:00:00,001801000001,THREAT,vulnerability,1,2026/09/06 10:00:00,"
            "192.168.1.100,10.0.0.1,0.0.0.0,0.0.0.0,rule-block,user1,,web-browsing,vsys1,"
            "trust,untrust,ethernet1/1,ethernet1/2,log-forward,2026/09/06 10:00:00,1,1,"
            "54321,80,0,0,0x0,tcp,drop,test-threat(9999),9999,0x0,informational,client-to-server"
        )
        raw_bytes = pan_raw.encode("utf-8")
        pan_res = PaloAltoPanOSParser().parse(
            FramedRecord(1, pan_raw, raw_bytes, 0, len(raw_bytes), 1)
        )
        pan_uce = self.canonical_builder.build_uce(
            pan_res, vendor="Palo Alto Networks", product="PAN-OS"
        )
        pan_sem = self.service.process_uce(pan_uce)

        # 2. FortiGate UTM Log (Deny)
        forti_raw = (
            'date=2026-09-06 time=10:00:00 devname="FGT-EDGE" type="traffic" subtype="forward" '
            'level="notice" srcip=192.168.1.100 dstip=10.0.0.1 action="deny" proto=6 '
            'srcport=54321 dstport=80 policyid=42 policyname="BLOCK-MALICIOUS"'
        )
        forti_bytes = forti_raw.encode("utf-8")
        forti_res = FortiGateParser().parse(
            FramedRecord(1, forti_raw, forti_bytes, 0, len(forti_bytes), 1)
        )
        forti_uce = self.canonical_builder.build_uce(
            forti_res, vendor="Fortinet", product="FortiGate"
        )
        forti_sem = self.service.process_uce(forti_uce)

        # 3. Cisco ASA Syslog (Deny)
        cisco_raw = (
            "<164>Sep 06 2026 10:00:00 asa-fw01 : %ASA-4-106023: Deny tcp src "
            "inside:192.168.1.100/54321 dst outside:10.0.0.1/80 by access-group 'outside_in'"
        )
        cisco_bytes = cisco_raw.encode("utf-8")
        cisco_res = CiscoSyslogParser().parse(
            FramedRecord(1, cisco_raw, cisco_bytes, 0, len(cisco_bytes), 1)
        )
        cisco_uce = self.canonical_builder.build_uce(cisco_res, vendor="Cisco", product="ASA")
        cisco_sem = self.service.process_uce(cisco_uce)

        # Assert Semantic Convergence across vendors
        for sem in (pan_sem, forti_sem, cisco_sem):
            self.assertEqual(sem.semantic_triple.category, "SECURITY")
            self.assertEqual(sem.semantic_triple.class_name, "Firewall")
            self.assertEqual(sem.semantic_triple.type_name, "firewall.deny")
            self.assertEqual(sem.action.semantic, "deny" if sem != pan_sem else "drop")
            self.assertIn("ocsf.v1", sem.projections)
            self.assertIn("otel.logs.v1", sem.projections)
            self.assertEqual(sem.projections["ocsf.v1"]["status"], "VALID")
            self.assertEqual(sem.projections["otel.logs.v1"]["status"], "VALID")

            # Validate against schema
            val_res = self.validator.validate_semantic(sem.to_contract_dict())
            self.assertTrue(val_res.valid, msg=f"Schema validation failed: {val_res.errors}")

        # Assert Distinct Vendor Field Preservation
        self.assertIn("policyname", forti_sem.unmapped_semantic_fields)
        self.assertEqual(forti_sem.unmapped_semantic_fields["policyname"], "BLOCK-MALICIOUS")

    def test_suricata_ids_convergence(self) -> None:
        """Suricata alert converges on (SECURITY, Detection Finding, ids.alert)."""
        suri_raw = (
            '{"timestamp":"2026-09-06T10:00:00.000Z","event_type":"alert",'
            '"src_ip":"192.168.1.100","src_port":54321,"dest_ip":"10.0.0.1","dest_port":80,'
            '"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2001,'
            '"rev":1,"signature":"GPL EXPLOIT Test","category":"Attempted Attack","severity":1}}'
        )
        suri_bytes = suri_raw.encode("utf-8")
        suri_res = SuricataEveParser().parse(
            FramedRecord(1, suri_raw, suri_bytes, 0, len(suri_bytes), 1)
        )
        suri_uce = self.canonical_builder.build_uce(suri_res, vendor="Suricata", product="EVE")
        suri_sem = self.service.process_uce(suri_uce)

        self.assertEqual(suri_sem.semantic_triple.category, "SECURITY")
        self.assertEqual(suri_sem.semantic_triple.class_name, "Detection Finding")
        self.assertEqual(suri_sem.semantic_triple.type_name, "ids.alert")
        self.assertEqual(suri_sem.projections["ocsf.v1"]["status"], "VALID")

    def test_cloud_and_web_convergence(self) -> None:
        """Verify cross-domain convergence for AWS CloudTrail and NGINX."""
        # NGINX Web Access
        nginx_raw = '192.168.1.5 - - [06/Sep/2026:10:00:00 +0000] "GET /api/v1/health HTTP/1.1" 200 45 "-" "curl/7.68.0"'
        nginx_bytes = nginx_raw.encode("utf-8")
        web_res = WebAccessLogParser().parse(
            FramedRecord(1, nginx_raw, nginx_bytes, 0, len(nginx_bytes), 1)
        )
        web_uce = self.canonical_builder.build_uce(web_res, vendor="NGINX", product="Web Server")
        web_sem = self.service.process_uce(web_uce)

        self.assertEqual(web_sem.semantic_triple.category, "WEB")
        self.assertEqual(web_sem.semantic_triple.class_name, "HTTP Activity")
        self.assertEqual(web_sem.result.status, "SUCCESS")

        # AWS CloudTrail Audit
        aws_raw = (
            '{"eventVersion":"1.08","userIdentity":{"type":"IAMUser","userName":"alice"},'
            '"eventTime":"2026-09-06T10:00:00Z","eventSource":"ec2.amazonaws.com",'
            '"eventName":"DescribeInstances","awsRegion":"us-east-1","sourceIPAddress":"203.0.113.1"}'
        )
        aws_bytes = aws_raw.encode("utf-8")
        aws_res = CloudAuditParser().parse(
            FramedRecord(1, aws_raw, aws_bytes, 0, len(aws_bytes), 1)
        )
        aws_uce = self.canonical_builder.build_uce(aws_res, vendor="AWS", product="CloudTrail")
        aws_sem = self.service.process_uce(aws_uce)

        self.assertEqual(aws_sem.semantic_triple.category, "CLOUD")
        self.assertEqual(aws_sem.semantic_triple.class_name, "Cloud API")
        self.assertEqual(aws_sem.semantic_triple.type_name, "cloud.api_call")


if __name__ == "__main__":
    unittest.main()
