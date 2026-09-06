"""Tests for ULPF Phase 6 bounded retry policy."""

import unittest

from ulpf_runtime.errors import RetryExhaustedError
from ulpf_runtime.retry import BoundedRetryPolicy, RetryConfig


class TestBoundedRetry(unittest.TestCase):
    def test_successful_after_transient_failure(self) -> None:
        attempts = 0

        def flaky_op() -> str:
            nonlocal attempts
            attempts += 1
            if attempts < 3:
                raise ConnectionError("Transient network failure")
            return "SUCCESS"

        policy = BoundedRetryPolicy(
            RetryConfig(max_attempts=4, initial_delay_sec=0.01, max_delay_sec=0.05, jitter=False)
        )
        res = policy.execute(flaky_op, retryable_exceptions=(ConnectionError,))
        self.assertEqual(res, "SUCCESS")
        self.assertEqual(attempts, 3)

    def test_exhausted_retries_raises_exception(self) -> None:
        attempts = 0

        def failing_op() -> None:
            nonlocal attempts
            attempts += 1
            raise ValueError("Permanent defect")

        policy = BoundedRetryPolicy(
            RetryConfig(max_attempts=3, initial_delay_sec=0.01, max_delay_sec=0.02, jitter=False)
        )
        with self.assertRaises(RetryExhaustedError):
            policy.execute(failing_op, retryable_exceptions=(ValueError,))

        self.assertEqual(attempts, 3)


if __name__ == "__main__":
    unittest.main()
