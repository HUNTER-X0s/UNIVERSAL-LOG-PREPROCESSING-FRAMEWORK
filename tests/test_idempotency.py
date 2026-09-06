"""Tests for ULPF Phase 6 IdempotencyGuard."""

import unittest

from ulpf_runtime.idempotency import IdempotencyGuard


class TestIdempotency(unittest.TestCase):
    def test_deduplication_detection(self) -> None:
        guard = IdempotencyGuard(max_entries=100)
        key = IdempotencyGuard.generate_key("source-fw", "sha256-hash-12345")

        # First encounter -> not duplicate
        is_dup, rec = guard.check_and_record(key, "evt-1", "sha256-hash-12345")
        self.assertFalse(is_dup)
        self.assertIsNone(rec)

        guard.update_result(key, "sem-100", state="PROCESSED")

        # Second encounter -> duplicate
        is_dup2, rec2 = guard.check_and_record(key, "evt-2", "sha256-hash-12345")
        self.assertTrue(is_dup2)
        self.assertIsNotNone(rec2)
        self.assertEqual(rec2.semantic_event_id, "sem-100")
        self.assertEqual(rec2.attempt_count, 2)

    def test_bounded_eviction(self) -> None:
        guard = IdempotencyGuard(max_entries=3)
        for i in range(5):
            k = IdempotencyGuard.generate_key(f"src-{i}", f"sha-{i}")
            guard.check_and_record(k, f"evt-{i}", f"sha-{i}")

        self.assertEqual(guard.size(), 3)


if __name__ == "__main__":
    unittest.main()
