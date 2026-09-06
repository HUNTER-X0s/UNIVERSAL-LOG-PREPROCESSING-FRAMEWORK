"""Tests for ULPF Phase 6 operational observability, metrics, and secret redaction."""

import json
import logging
import unittest

from ulpf_observability.logging import StructuredJsonFormatter, redact_sensitive_text
from ulpf_observability.metrics import OperationalMetricsRegistry
from ulpf_observability.tracing import InProcessTracer


class TestObservability(unittest.TestCase):
    def test_metrics_counters_and_latency_quantiles(self) -> None:
        registry = OperationalMetricsRegistry()
        registry.increment_counter("ingest_total", value=5.0, stage="ingest", result="success")
        registry.increment_counter("ingest_total", value=2.0, stage="ingest", result="success")

        registry.record_latency("pipeline_ms", 10.0)
        registry.record_latency("pipeline_ms", 20.0)
        registry.record_latency("pipeline_ms", 30.0)

        snap = registry.snapshot()
        self.assertEqual(snap["counters"]["ingest_total|stage=ingest|result=success"], 7.0)

        lat = snap["latencies"]["pipeline_ms"]
        self.assertEqual(lat["count"], 3.0)
        self.assertEqual(lat["p50"], 20.0)

    def test_secret_redaction(self) -> None:
        raw_msg = "User login failed with password='Secret123!' and token: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        redacted = redact_sensitive_text(raw_msg)
        self.assertNotIn("Secret123!", redacted)
        self.assertIn("REDACTED", redacted)

    def test_structured_json_formatter(self) -> None:
        formatter = StructuredJsonFormatter()
        record = logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname=__file__,
            lineno=10,
            msg="Processing event",
            args=(),
            exc_info=None,
        )
        record.correlation_id = "corr-999"
        record.stage = "parse"
        out = formatter.format(record)
        parsed = json.loads(out)
        self.assertEqual(parsed["correlation_id"], "corr-999")
        self.assertEqual(parsed["stage"], "parse")

    def test_in_process_tracer_spans(self) -> None:
        tracer = InProcessTracer(max_spans=100)
        with tracer.span("stage_one", trace_id="trace-abc") as sid:
            self.assertIsNotNone(sid)

        spans = tracer.get_spans(trace_id="trace-abc")
        self.assertEqual(len(spans), 1)
        self.assertEqual(spans[0].name, "stage_one")
        self.assertEqual(spans[0].status, "OK")


if __name__ == "__main__":
    unittest.main()
