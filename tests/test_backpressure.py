"""Tests for ULPF Phase 6 backpressure controller."""

import unittest

from ulpf_runtime.backpressure import BackpressureController, BackpressurePolicy
from ulpf_runtime.errors import BufferFullError


class TestBackpressure(unittest.TestCase):
    def test_reject_policy(self) -> None:
        bp = BackpressureController(max_capacity=3, policy=BackpressurePolicy.REJECT)
        self.assertTrue(bp.acquire())
        self.assertTrue(bp.acquire())
        self.assertTrue(bp.acquire())

        # 4th acquisition triggers BufferFullError
        with self.assertRaises(BufferFullError):
            bp.acquire()

        # Release one slot
        bp.release()
        self.assertTrue(bp.acquire())

    def test_high_watermark_detection(self) -> None:
        bp = BackpressureController(max_capacity=10, high_watermark=0.8)
        for _ in range(7):
            bp.acquire()
        self.assertFalse(bp.is_high_watermark)

        bp.acquire()  # 8th acquisition -> hits 80% watermark
        self.assertTrue(bp.is_high_watermark)

    def test_dlq_policy_on_overflow(self) -> None:
        bp = BackpressureController(max_capacity=2, policy=BackpressurePolicy.DLQ)
        self.assertTrue(bp.acquire())
        self.assertTrue(bp.acquire())

        # 3rd acquisition returns False instead of raising exception
        self.assertFalse(bp.acquire())
        stats = bp.statistics
        self.assertEqual(stats["total_dlq_overflow"], 1)


if __name__ == "__main__":
    unittest.main()
