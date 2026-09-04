"""Graceful, dependency-free worker process shell for later composition."""

import asyncio
import signal

from ulpf_platform.config import get_settings
from ulpf_platform.logging import configure_logging, get_logger


class WorkerRuntime:
    """Own lifecycle state only; task execution is intentionally deferred."""

    def __init__(self) -> None:
        self._stop_requested = asyncio.Event()
        self._logger = get_logger("worker.lifecycle")

    def request_stop(self) -> None:
        """Request bounded shutdown without claiming future queue draining."""
        self._stop_requested.set()

    async def run(self) -> None:
        """Remain ready for a future registered task interface."""
        self._logger.info("worker_started", extra={"component": "worker"})
        await self._stop_requested.wait()
        self._logger.info("worker_stopped", extra={"component": "worker"})


def main() -> None:
    """Start the worker shell and handle supported local shutdown signals."""
    configure_logging(get_settings())
    runtime = WorkerRuntime()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    for signal_name in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(signal_name, runtime.request_stop)
        except NotImplementedError:
            signal.signal(signal_name, lambda *_: runtime.request_stop())
    try:
        loop.run_until_complete(runtime.run())
    finally:
        loop.close()


if __name__ == "__main__":
    main()
