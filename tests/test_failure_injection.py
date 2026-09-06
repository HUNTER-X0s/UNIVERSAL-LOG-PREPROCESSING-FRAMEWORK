"""Chaos and failure injection tests for ULPF Phase 6.

Simulates:
- Storage write failure
- Downstream sink failure
- Poison stream message handling
"""

import unittest

from ulpf_delivery.outbox import OutboxDispatcher
from ulpf_delivery.sinks import OCSFJsonSink, SiemMockSink
from ulpf_runtime.dlq import DLQManager
from ulpf_runtime.lifecycle import EventLifecycleState
from ulpf_runtime.pipeline import RuntimePipeline
from ulpf_storage.interfaces import RawEvidenceRecord, RawEvidenceRepository
from ulpf_storage.memory import (
    MemoryOutboxRepository,
    MemoryRawEvidenceRepository,
    MemorySemanticEventRepository,
    MemoryUCERepository,
)


class FailingRawStore(RawEvidenceRepository):
    """Simulated failing raw evidence repository."""

    def put(self, *args, **kwargs) -> RawEvidenceRecord:  # type: ignore[no-untyped-def]
        raise OSError("Disk write failed: I/O Error")

    def get(self, raw_event_id: str):  # type: ignore[no-untyped-def]
        raise OSError("Disk read failed")

    def exists(self, raw_event_id: str) -> bool:
        return False

    def verify(self, raw_event_id: str) -> bool:
        return False

    def get_metadata(self, raw_event_id: str):  # type: ignore[no-untyped-def]
        return None


class TestFailureInjection(unittest.TestCase):
    def test_storage_failure_routes_to_dlq_no_false_ack(self) -> None:
        failing_raw = FailingRawStore()
        uce_store = MemoryUCERepository()
        sem_store = MemorySemanticEventRepository()
        dlq = DLQManager()

        pipeline = RuntimePipeline(
            raw_store=failing_raw,
            uce_store=uce_store,
            semantic_store=sem_store,
            dlq_manager=dlq,
        )

        res = pipeline.process_event("sample payload", source_id="src")
        # Must not be acknowledged
        self.assertNotEqual(res.lifecycle_state, EventLifecycleState.ACKNOWLEDGED)
        self.assertEqual(res.lifecycle_state, EventLifecycleState.DLQ)
        self.assertIsNotNone(res.dlq_id)
        self.assertEqual(dlq.count(), 1)

    def test_downstream_siem_failure_preserves_canonical_truth(self) -> None:
        raw_store = MemoryRawEvidenceRepository()
        uce_store = MemoryUCERepository()
        sem_store = MemorySemanticEventRepository()
        outbox = MemoryOutboxRepository()

        pipeline = RuntimePipeline(
            raw_store=raw_store,
            uce_store=uce_store,
            semantic_store=sem_store,
            outbox_repo=outbox,
        )

        # Process an event successfully through pipeline into outbox
        res = pipeline.process_event("firewall log message", source_id="asa-fw")
        self.assertEqual(res.lifecycle_state, EventLifecycleState.ACKNOWLEDGED)

        # Canonical evidence exists
        self.assertTrue(raw_store.exists(res.raw_event_id))
        self.assertTrue(uce_store.exists(res.uce_event_id))

        # Downstream SIEM fails
        siem_sink = SiemMockSink()
        siem_sink.set_healthy(False)
        ocsf_sink = OCSFJsonSink()

        dispatcher = OutboxDispatcher(outbox_repo=outbox, sinks={"siem": siem_sink, "ocsf": ocsf_sink})
        dispatch_res = dispatcher.dispatch_pending()
        self.assertGreaterEqual(dispatch_res["failed_count"], 1)

        # Canonical UCE and raw evidence remain completely intact
        self.assertTrue(raw_store.verify(res.raw_event_id))
        self.assertIsNotNone(uce_store.get(res.uce_event_id))


if __name__ == "__main__":
    unittest.main()
