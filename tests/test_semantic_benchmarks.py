"""Performance and latency benchmark tests for ULPF Phase 4 Semantic Pipeline."""

import time
import unittest

from ulpf_semantic.service import SemanticService


class TestSemanticBenchmarks(unittest.TestCase):
    def setUp(self) -> None:
        self.service = SemanticService()
        self.sample_uce = {
            "event_id": "evt_bench_01",
            "raw_event_id": "raw_bench_01",
            "event": {
                "time": "2026-09-06T10:00:00Z",
                "category": "security",
                "type": "firewall",
                "action": "deny",
                "severity": 7,
                "source": {"ip": "192.168.1.10", "port": 40000},
                "destination": {"ip": "10.0.0.1", "port": 443},
                "network": {"protocol": "TCP"},
                "identity": {"user": {"name": "alice"}},
                "device": {"hostname": "edge-fw01"},
                "metadata": {
                    "vendor": "Palo Alto Networks",
                    "product": "PAN-OS",
                    "parser_id": "parser.paloalto.panos",
                },
            },
            "unmapped_fields": {"rule": "deny_all", "session_id": "987654"},
        }

    def test_semantic_pipeline_throughput(self) -> None:
        """Measure throughput for full UCE -> Semantic -> OCSF -> OTel pipeline."""
        iterations = 1000

        # Warm up
        for _ in range(50):
            self.service.process_uce(self.sample_uce)

        t0 = time.perf_counter()
        for _ in range(iterations):
            self.service.process_uce(self.sample_uce)
        elapsed = time.perf_counter() - t0

        eps = iterations / elapsed
        avg_latency_ms = (elapsed / iterations) * 1000

        # Enforce NTRO government-grade SLA
        self.assertGreaterEqual(
            eps,
            1000.0,
            msg=f"Phase 4 throughput {eps:.1f} eps is below 1,000 eps SLA",
        )
        self.assertLess(
            avg_latency_ms,
            1.0,
            msg=f"Phase 4 latency {avg_latency_ms:.3f} ms exceeds 1.0 ms SLA",
        )


if __name__ == "__main__":
    unittest.main()
