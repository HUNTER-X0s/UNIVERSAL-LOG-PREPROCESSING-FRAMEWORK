"""Worker host and execution lifecycle for ULPF Phase 6.

Enforces:
- Rule 22: Non-blocking or interruptible polling with cancellation
- Rule 23: Graceful shutdown: stop intake, drain safe work, acknowledge only completed work
- Rule 24: All external data untrusted; poison event resilience
"""

import threading
import time
from enum import Enum
from typing import Any

from ulpf_streaming.interfaces import EventStream, StreamMessage

from ulpf_runtime.pipeline import PipelineResult, RuntimePipeline


class WorkerStatus(str, Enum):
    """Lifecycle states of the worker host."""

    INITIALIZING = "INITIALIZING"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    DRAINING = "DRAINING"
    STOPPED = "STOPPED"


class WorkerHost:
    """Consumes from EventStream, routes to RuntimePipeline, and manages acks."""

    def __init__(
        self,
        stream: EventStream,
        pipeline: RuntimePipeline,
        worker_id: str = "worker-1",
        poll_timeout_sec: float = 0.2,
        batch_size: int = 25,
    ) -> None:
        self.stream = stream
        self.pipeline = pipeline
        self.worker_id = worker_id
        self.poll_timeout_sec = poll_timeout_sec
        self.batch_size = batch_size

        self._status = WorkerStatus.INITIALIZING
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._processed_count = 0
        self._error_count = 0
        self._lock = threading.Lock()

    @property
    def status(self) -> WorkerStatus:
        with self._lock:
            return self._status

    @property
    def statistics(self) -> dict[str, Any]:
        with self._lock:
            return {
                "worker_id": self.worker_id,
                "status": self._status.value,
                "processed_count": self._processed_count,
                "error_count": self._error_count,
            }

    def start(self) -> None:
        """Start the background worker thread."""
        with self._lock:
            if self._status == WorkerStatus.RUNNING:
                return
            self._status = WorkerStatus.RUNNING
            self._stop_event.clear()
            self._pause_event.clear()
            self._thread = threading.Thread(
                target=self._run_loop, name=f"WorkerHost-{self.worker_id}", daemon=True
            )
            self._thread.start()

    def pause(self) -> None:
        """Pause message polling."""
        with self._lock:
            if self._status == WorkerStatus.RUNNING:
                self._status = WorkerStatus.PAUSED
                self._pause_event.set()

    def resume(self) -> None:
        """Resume message polling."""
        with self._lock:
            if self._status == WorkerStatus.PAUSED:
                self._status = WorkerStatus.RUNNING
                self._pause_event.clear()

    def drain_and_stop(self, timeout_sec: float = 5.0) -> None:
        """Gracefully drain in-flight messages and stop worker."""
        with self._lock:
            if self._status in (WorkerStatus.DRAINING, WorkerStatus.STOPPED):
                return
            self._status = WorkerStatus.DRAINING
            self._stop_event.set()

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout_sec)

        with self._lock:
            self._status = WorkerStatus.STOPPED

    def _process_message(self, msg: StreamMessage) -> PipelineResult:
        """Process a single stream message safely."""
        source_id = msg.headers.get("source_id", "default-source")
        format_str = msg.headers.get("format", "syslog")
        cid = msg.headers.get("correlation_id")
        mapping_ver = msg.headers.get("mapping_version")

        res = self.pipeline.process_event(
            raw_payload=msg.payload,
            source_id=source_id,
            format_str=format_str,
            correlation_id=cid,
            mapping_version=mapping_ver,
        )
        return res

    def _run_loop(self) -> None:
        """Continuous execution loop."""
        while not self._stop_event.is_set():
            if self._pause_event.is_set():
                time.sleep(0.1)
                continue

            try:
                records = self.stream.poll(
                    timeout_sec=self.poll_timeout_sec, max_records=self.batch_size
                )
                if not records:
                    continue

                for msg in records:
                    if self._stop_event.is_set():
                        # Unprocessed messages remain unacknowledged for next run
                        self.stream.nack(msg, requeue=True)
                        continue

                    try:
                        res = self._process_message(msg)
                        if res.error and res.dlq_id:
                            # Poison event routed to DLQ -> ack message to prevent stalling
                            self.stream.ack(msg)
                            with self._lock:
                                self._error_count += 1
                        else:
                            self.stream.ack(msg)
                            with self._lock:
                                self._processed_count += 1
                    except Exception:
                        self.stream.nack(msg, requeue=True)
                        with self._lock:
                            self._error_count += 1

            except Exception:
                time.sleep(0.1)

        with self._lock:
            self._status = WorkerStatus.STOPPED
