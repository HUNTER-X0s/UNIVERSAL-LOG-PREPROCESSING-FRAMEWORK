"""Tests for ULPF Phase 6 worker lifecycle and graceful shutdown."""

import time
import unittest

from ulpf_runtime.pipeline import RuntimePipeline
from ulpf_runtime.worker import WorkerHost, WorkerStatus
from ulpf_storage.memory import (
    MemoryRawEvidenceRepository,
    MemorySemanticEventRepository,
    MemoryUCERepository,
)
from ulpf_streaming.memory import MemoryEventStream


class TestWorkerShutdown(unittest.TestCase):
    def test_worker_lifecycle_and_drain(self) -> None:
        stream = MemoryEventStream(num_partitions=1)
        raw_store = MemoryRawEvidenceRepository()
        uce_store = MemoryUCERepository()
        sem_store = MemorySemanticEventRepository()
        pipeline = RuntimePipeline(
            raw_store=raw_store,
            uce_store=uce_store,
            semantic_store=sem_store,
        )

        worker = WorkerHost(
            stream=stream,
            pipeline=pipeline,
            worker_id="test-worker",
            poll_timeout_sec=0.05,
        )

        # 1. Publish messages before start
        for i in range(5):
            stream.publish(
                topic="test",
                key=f"k-{i}",
                payload=f"event-{i}".encode(),
                headers={"source_id": "test-src"},
            )

        # 2. Start worker
        worker.start()
        self.assertEqual(worker.status, WorkerStatus.RUNNING)

        # Wait for messages to be processed
        time.sleep(0.3)
        stats = worker.statistics
        self.assertGreaterEqual(stats["processed_count"], 1)

        # 3. Pause & Resume
        worker.pause()
        self.assertEqual(worker.status, WorkerStatus.PAUSED)
        worker.resume()
        self.assertEqual(worker.status, WorkerStatus.RUNNING)

        # 4. Graceful drain and stop
        worker.drain_and_stop(timeout_sec=2.0)
        self.assertEqual(worker.status, WorkerStatus.STOPPED)

        stream.close()


if __name__ == "__main__":
    unittest.main()
