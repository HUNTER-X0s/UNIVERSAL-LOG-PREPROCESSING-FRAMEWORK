"""Bounded retry policy with exponential backoff and jitter for ULPF Phase 6.

Enforces:
- Rule 21: No unbounded retry loops
- Rule 22: Controlled retry termination with failure propagation
"""

import random
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeVar

from ulpf_runtime.errors import RetryExhaustedError

T = TypeVar("T")


@dataclass(frozen=True)
class RetryConfig:
    """Configuration for bounded retries."""

    max_attempts: int = 3
    initial_delay_sec: float = 0.05
    max_delay_sec: float = 2.0
    backoff_factor: float = 2.0
    jitter: bool = True


class BoundedRetryPolicy:
    """Executes callables with bounded exponential retries."""

    def __init__(self, config: RetryConfig | None = None) -> None:
        self.config = config or RetryConfig()
        if self.config.max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")

    def execute(
        self,
        operation: Callable[[], T],
        retryable_exceptions: tuple[type[Exception], ...] = (Exception,),
        on_retry: Callable[[int, Exception, float], None] | None = None,
    ) -> T:
        """Execute an operation with bounded retry attempts.

        Raises RetryExhaustedError if max attempts are exceeded.
        """
        last_exception: Exception | None = None
        delay = self.config.initial_delay_sec

        for attempt in range(1, self.config.max_attempts + 1):
            try:
                return operation()
            except retryable_exceptions as ex:
                last_exception = ex
                if attempt >= self.config.max_attempts:
                    break

                sleep_time = min(delay, self.config.max_delay_sec)
                if self.config.jitter:
                    sleep_time = random.uniform(0.5 * sleep_time, 1.5 * sleep_time)  # noqa: S311

                if on_retry:
                    on_retry(attempt, ex, sleep_time)

                time.sleep(sleep_time)
                delay *= self.config.backoff_factor

        raise RetryExhaustedError(
            f"Operation failed after {self.config.max_attempts} attempts: {last_exception}",
            details={"max_attempts": self.config.max_attempts, "last_error": str(last_exception)},
        ) from last_exception
