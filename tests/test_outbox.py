"""Tests for ULPF Phase 6 Outbox pattern dispatcher."""

import unittest

from ulpf_delivery.outbox import OutboxDispatcher
from ulpf_delivery.sinks import OCSFJsonSink, SiemMockSink
from ulpf_runtime.models import DeliveryIntent
from ulpf_storage.memory import MemoryOutboxRepository


class TestOutbox(unittest.TestCase):
    def test_outbox_reliable_dispatch_and_status(self) -> None:
        outbox_repo = MemoryOutboxRepository()
        ocsf_sink = OCSFJsonSink()
        siem_sink = SiemMockSink()

        dispatcher = OutboxDispatcher(
            outbox_repo=outbox_repo,
            sinks={"ocsf": ocsf_sink, "siem": siem_sink},
        )

        intent1 = DeliveryIntent(
            intent_id="i-1",
            event_id="evt-1",
            sink_name="ocsf",
            payload_type="OCSF",
            payload={"class_uid": 4001},
            created_at="2026-03-01T12:00:00Z",
        )
        outbox_repo.save_intent(intent1)

        # Dispatch pending
        res = dispatcher.dispatch_pending()
        self.assertEqual(res["delivered_count"], 1)
        self.assertEqual(res["failed_count"], 0)

        # Pending queue should now be empty
        self.assertEqual(len(outbox_repo.get_pending()), 0)

    def test_outbox_retry_escalation_to_dlq(self) -> None:
        outbox_repo = MemoryOutboxRepository()
        siem_sink = SiemMockSink()
        siem_sink.inject_failure(count=5)  # Make it fail

        dispatcher = OutboxDispatcher(
            outbox_repo=outbox_repo,
            sinks={"siem": siem_sink},
        )

        intent = DeliveryIntent(
            intent_id="i-flaky",
            event_id="evt-2",
            sink_name="siem",
            payload_type="SIEM",
            payload={"msg": "log"},
            created_at="2026-03-01T12:00:00Z",
            max_attempts=2,
        )
        outbox_repo.save_intent(intent)

        # Attempt 1 -> fails
        res1 = dispatcher.dispatch_pending()
        self.assertEqual(res1["failed_count"], 1)

        # Attempt 2 -> fails and escalates to DLQ
        res2 = dispatcher.dispatch_pending()
        self.assertEqual(res2["failed_count"], 1)
        self.assertEqual(res2["dlq_escalated"], 1)


if __name__ == "__main__":
    unittest.main()
