"""Tests for ULPF Phase 6 Dead Letter Queue (DLQ)."""

import unittest

from ulpf_runtime.dlq import DLQManager


class TestDLQManager(unittest.TestCase):
    def test_record_and_retrieve_dlq(self) -> None:
        dlq = DLQManager(max_capacity=10)
        rec = dlq.record_failure(
            original_event_id="evt-100",
            stage="parsing",
            error=ValueError("Invalid framing delimiter"),
            retry_count=2,
            source_id="paloalto-fw",
            raw_sha256="abc123sha",
            correlation_id="corr-xyz",
            payload_preview="<14>1 2026-03-01T12:00:00Z firewall traffic ...",
        )

        self.assertIsNotNone(rec.dlq_id)
        self.assertEqual(rec.error_type, "ValueError")
        self.assertEqual(rec.retry_count, 2)
        self.assertFalse(rec.replayed)

        fetched = dlq.get(rec.dlq_id)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.original_event_id, "evt-100")

    def test_mark_replayed(self) -> None:
        dlq = DLQManager(max_capacity=10)
        rec = dlq.record_failure(
            original_event_id="evt-101",
            stage="semantic",
            error=RuntimeError("Transient error"),
            retry_count=1,
            source_id="src-1",
            raw_sha256="sha999",
        )

        self.assertTrue(dlq.mark_replayed(rec.dlq_id))
        updated = dlq.get(rec.dlq_id)
        self.assertIsNotNone(updated)
        self.assertTrue(updated.replayed)

    def test_bounded_capacity_eviction(self) -> None:
        dlq = DLQManager(max_capacity=3)
        for i in range(5):
            dlq.record_failure(
                original_event_id=f"evt-{i}",
                stage="storage",
                error=RuntimeError("Disk full"),
                retry_count=1,
                source_id="src",
                raw_sha256=f"sha-{i}",
            )

        self.assertEqual(dlq.count(), 3)
        # evt-0 and evt-1 should have been evicted
        recs = dlq.list_records()
        event_ids = [r.original_event_id for r in recs]
        self.assertNotIn("evt-0", event_ids)
        self.assertIn("evt-4", event_ids)


if __name__ == "__main__":
    unittest.main()
