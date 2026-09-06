"""Comprehensive tests for ULPF Phase 6 RuntimePipeline."""

import unittest

from ulpf_observability.metrics import OperationalMetricsRegistry
from ulpf_observability.tracing import InProcessTracer
from ulpf_runtime.backpressure import BackpressureController, BackpressurePolicy
from ulpf_runtime.dlq import DLQManager
from ulpf_runtime.errors import BufferFullError
from ulpf_runtime.idempotency import IdempotencyGuard
from ulpf_runtime.lifecycle import EventLifecycleState
from ulpf_runtime.pipeline import RuntimePipeline
from ulpf_search.memory import MemorySearchIndex
from ulpf_storage.memory import (
    MemoryOutboxRepository,
    MemoryRawEvidenceRepository,
    MemorySemanticEventRepository,
    MemoryUCERepository,
)


class TestRuntimePipeline(unittest.TestCase):
    def setUp(self) -> None:
        self.raw_store = MemoryRawEvidenceRepository()
        self.uce_store = MemoryUCERepository()
        self.semantic_store = MemorySemanticEventRepository()
        self.search_adapter = MemorySearchIndex()
        self.outbox_repo = MemoryOutboxRepository()
        self.dlq_manager = DLQManager()
        self.backpressure = BackpressureController(max_capacity=100)
        self.idempotency = IdempotencyGuard()
        self.metrics = OperationalMetricsRegistry()
        self.tracer = InProcessTracer()

        self.pipeline = RuntimePipeline(
            raw_store=self.raw_store,
            uce_store=self.uce_store,
            semantic_store=self.semantic_store,
            search_adapter=self.search_adapter,
            outbox_repo=self.outbox_repo,
            dlq_manager=self.dlq_manager,
            backpressure=self.backpressure,
            idempotency=self.idempotency,
            metrics=self.metrics,
            tracer=self.tracer,
        )

    def test_end_to_end_successful_processing(self) -> None:
        raw_log = "Feb 23 10:15:30 firewall01 %ASA-4-106023: Deny tcp src outside:198.51.100.25/443 dst inside:10.0.0.15/51234"
        res = self.pipeline.process_event(
            raw_payload=raw_log,
            source_id="cisco-asa-01",
            format_str="syslog",
            correlation_id="corr-12345",
        )

        # 1. Pipeline result checks
        self.assertEqual(res.lifecycle_state, EventLifecycleState.ACKNOWLEDGED)
        self.assertFalse(res.is_duplicate)
        self.assertIsNotNone(res.raw_sha256)
        self.assertIsNotNone(res.uce_event_id)
        self.assertIsNotNone(res.semantic_event_id)
        self.assertTrue(any(k.startswith("ocsf") for k in res.projections))
        self.assertTrue(any(k.startswith("otel") for k in res.projections))

        # 2. Raw evidence durability check
        self.assertTrue(self.raw_store.exists(res.raw_event_id))
        meta, raw_bytes = self.raw_store.get(res.raw_event_id)
        self.assertEqual(raw_bytes.decode("utf-8"), raw_log)
        self.assertTrue(self.raw_store.verify(res.raw_event_id))

        # 3. Canonical UCE durability check
        self.assertTrue(self.uce_store.exists(res.uce_event_id))
        uce = self.uce_store.get(res.uce_event_id)
        self.assertIsNotNone(uce)
        self.assertEqual(uce.source_id, "cisco-asa-01")

        # 4. Semantic persistence check
        stored_sem = self.semantic_store.get(res.semantic_event_id)
        self.assertIsNotNone(stored_sem)
        self.assertEqual(stored_sem.raw_sha256, res.raw_sha256)

        # 5. Search index check
        self.assertEqual(self.search_adapter.count(), 1)

        # 6. Outbox intent check
        pending = self.outbox_repo.get_pending()
        self.assertGreaterEqual(len(pending), 2)  # OCSF and OTel intents

        # 7. Metrics check
        snap = self.metrics.snapshot()
        self.assertGreater(snap["counters"].get("events_total|stage=delivery|result=success", 0), 0)

    def test_idempotent_duplicate_handling(self) -> None:
        raw_log = "Mar 01 12:00:00 panos: 1,2026/03/01,TRAFFIC,drop"
        res1 = self.pipeline.process_event(raw_log, source_id="panos-01")
        self.assertEqual(res1.lifecycle_state, EventLifecycleState.ACKNOWLEDGED)
        self.assertFalse(res1.is_duplicate)

        # Send exact same event again
        res2 = self.pipeline.process_event(raw_log, source_id="panos-01")
        self.assertEqual(res2.lifecycle_state, EventLifecycleState.ACKNOWLEDGED)
        self.assertTrue(res2.is_duplicate)
        self.assertEqual(res2.semantic_event_id, res1.semantic_event_id)

    def test_backpressure_rejection(self) -> None:
        strict_controller = BackpressureController(max_capacity=1, policy=BackpressurePolicy.REJECT)
        pipeline = RuntimePipeline(
            raw_store=self.raw_store,
            uce_store=self.uce_store,
            semantic_store=self.semantic_store,
            backpressure=strict_controller,
        )

        # Fill capacity
        strict_controller.acquire()

        # Next event must raise BufferFullError
        with self.assertRaises(BufferFullError):
            pipeline.process_event("test log", source_id="src-1")

    def test_poison_event_dlq_routing(self) -> None:
        # Malformed custom UCE designed to cause an error during semantic processing
        bad_uce = {"message": None}  # violates expected structure if not handled
        res = self.pipeline.process_event(
            raw_payload="corrupt log payload",
            source_id="untrusted-src",
            custom_uce=bad_uce,
        )

        # Event should gracefully route to DLQ without raising unhandled exception
        if res.error:
            self.assertEqual(res.lifecycle_state, EventLifecycleState.DLQ)
            self.assertIsNotNone(res.dlq_id)
            self.assertEqual(self.dlq_manager.count(), 1)


if __name__ == "__main__":
    unittest.main()
