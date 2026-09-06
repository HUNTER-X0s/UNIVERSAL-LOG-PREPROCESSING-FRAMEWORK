"""Unit tests for ULPF Phase 4 OCSF v1.1.0 Output Projection and Validation."""

import unittest

from ulpf_semantic.mapping.engine import SemanticMapper
from ulpf_semantic.projections.base import ProjectionStatus
from ulpf_semantic.projections.ocsf.mapper import OCSFProjection


class TestSemanticOCSFProjection(unittest.TestCase):
    def setUp(self) -> None:
        self.mapper = SemanticMapper()
        self.projection = OCSFProjection()

    def test_ocsf_network_activity_projection(self) -> None:
        uce = {
            "event_id": "evt_test_01",
            "raw_event_id": "raw_test_01",
            "event": {
                "time": "2026-09-06T10:00:00Z",
                "category": "security",
                "type": "firewall",
                "action": "deny",
                "severity": 7,
                "source": {"ip": "192.168.1.10", "port": 40000},
                "destination": {"ip": "10.0.0.1", "port": 443},
                "metadata": {
                    "vendor": "Palo Alto Networks",
                    "product": "PAN-OS",
                    "parser_id": "parser.paloalto.panos",
                },
            },
            "unmapped_fields": {"rule": "default-deny-rule"},
        }
        sem_event = self.mapper.map_uce_to_semantic(uce)
        result = self.projection.project(sem_event, uce)

        self.assertEqual(result.status, ProjectionStatus.VALID)
        self.assertEqual(result.output["category_uid"], 4)
        self.assertEqual(result.output["class_uid"], 4001)  # Network Activity
        self.assertEqual(result.output["severity_id"], 4)  # High
        self.assertIn("src_endpoint", result.output)
        self.assertEqual(result.output["src_endpoint"]["ip"], "192.168.1.10")
        self.assertEqual(result.output["dst_endpoint"]["port"], 443)
        self.assertEqual(result.output["metadata"]["product"]["vendor_name"], "Palo Alto Networks")

    def test_ocsf_detection_finding_projection(self) -> None:
        uce = {
            "event_id": "evt_test_02",
            "raw_event_id": "raw_test_02",
            "event": {
                "time": "2026-09-06T10:00:00Z",
                "category": "security",
                "type": "alert",
                "action": "alert",
                "severity": 9,
                "metadata": {
                    "vendor": "Suricata",
                    "product": "EVE",
                    "parser_id": "parser.suricata.eve",
                },
            },
            "unmapped_fields": {"alert": "ET SCAN Potential SSH Scan", "signature": "2001219"},
        }
        sem_event = self.mapper.map_uce_to_semantic(uce)
        result = self.projection.project(sem_event, uce)

        self.assertEqual(result.status, ProjectionStatus.VALID)
        self.assertEqual(result.output["category_uid"], 2)  # Findings
        self.assertEqual(result.output["class_uid"], 2004)  # Detection Finding per OCSF v1.1.0
        self.assertIn("finding_info", result.output)


if __name__ == "__main__":
    unittest.main()
