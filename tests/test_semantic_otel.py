"""Unit tests for ULPF Phase 4 OpenTelemetry Logs Output Projection and Validation."""

import unittest

from ulpf_semantic.mapping.engine import SemanticMapper
from ulpf_semantic.projections.base import ProjectionStatus
from ulpf_semantic.projections.otel.mapper import OTelProjection


class TestSemanticOTelProjection(unittest.TestCase):
    def setUp(self) -> None:
        self.mapper = SemanticMapper()
        self.projection = OTelProjection()

    def test_otel_logs_projection(self) -> None:
        uce = {
            "event_id": "evt_test_otel_01",
            "raw_event_id": "raw_test_otel_01",
            "event": {
                "time": "2026-09-06T10:00:00Z",
                "category": "security",
                "type": "firewall",
                "action": "drop",
                "severity": 8,
                "source": {"ip": "10.0.1.20"},
                "destination": {"ip": "10.0.2.30"},
                "metadata": {
                    "vendor": "Fortinet",
                    "product": "FortiGate",
                    "parser_id": "parser.fortinet.fortigate",
                },
            },
            "unmapped_fields": {"policyid": "14", "trace_id": "0af7651916cd43dd8448eb211c80319c"},
        }
        sem_event = self.mapper.map_uce_to_semantic(uce)
        result = self.projection.project(sem_event, uce)

        self.assertEqual(result.status, ProjectionStatus.VALID)
        otlp = result.output
        self.assertIn("resource_logs", otlp)
        res_logs = otlp["resource_logs"][0]
        scope_logs = res_logs["scope_logs"][0]
        log_record = scope_logs["log_records"][0]

        # Verify severity mapping
        self.assertEqual(log_record["severity_text"], "ERROR")
        self.assertEqual(log_record["severity_number"], 17)

        # Verify trace ID preservation
        self.assertEqual(log_record.get("trace_id"), "0af7651916cd43dd8448eb211c80319c")

        # Verify attributes
        attr_keys = [a["key"] for a in log_record["attributes"]]
        self.assertIn("event.category", attr_keys)
        self.assertIn("event.type", attr_keys)
        self.assertIn("source.ip", attr_keys)
        self.assertIn("unmapped.policyid", attr_keys)


if __name__ == "__main__":
    unittest.main()
