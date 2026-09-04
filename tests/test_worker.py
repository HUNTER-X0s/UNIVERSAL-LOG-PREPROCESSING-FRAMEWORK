"""Worker shell lifecycle tests."""

import asyncio
import unittest

from ulpf_worker.main import WorkerRuntime


class WorkerRuntimeTests(unittest.TestCase):
    """Prove the worker shell can stop without future queue semantics."""

    def test_stop_request_completes_run_loop(self) -> None:
        runtime = WorkerRuntime()
        runtime.request_stop()
        asyncio.run(runtime.run())
