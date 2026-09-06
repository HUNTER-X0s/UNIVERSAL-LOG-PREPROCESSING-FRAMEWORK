"""In-memory bounded, partitioned event stream implementation for ULPF Phase 6.

Enforces:
- Rule 15/16: Offline/air-gapped local development & testing
- Rule 17: Deterministic partitioning
- Rule 19: Bounded queue capacity per partition
- Rule 22: Non-blocking or bounded polling with shutdown handling
"""

import hashlib
import threading
import time

from ulpf_runtime.errors import BufferFullError

from ulpf_streaming.interfaces import EventStream, StreamMessage


class MemoryEventStream(EventStream):
    """In-memory bounded stream supporting partitioned pub/sub, ack/nack, and offset tracking."""

    def __init__(self, num_partitions: int = 4, max_partition_capacity: int = 10_000) -> None:
        if num_partitions <= 0 or max_partition_capacity <= 0:
            raise ValueError("num_partitions and max_partition_capacity must be positive")
        self.num_partitions = num_partitions
        self.max_partition_capacity = max_partition_capacity

        # Partitions: partition_idx -> list of StreamMessage (append-only log)
        self._logs: dict[int, list[StreamMessage]] = {p: [] for p in range(num_partitions)}
        # Consumer committed offsets: partition_idx -> int
        self._consumer_offsets: dict[int, int] = {p: 0 for p in range(num_partitions)}
        # Unacknowledged in-flight: message_id -> StreamMessage
        self._inflight: dict[str, StreamMessage] = {}
        # Message ID sequence
        self._seq = 0
        self._lock = threading.Lock()
        self._not_empty = threading.Condition(self._lock)
        self._closed = False

    def _determine_partition(self, key: str) -> int:
        """Compute deterministic partition index via SHA-256."""
        h = int(hashlib.sha256(key.encode("utf-8")).hexdigest(), 16)
        return h % self.num_partitions

    def publish(
        self, topic: str, key: str, payload: bytes, headers: dict[str, str] | None = None
    ) -> StreamMessage:
        with self._lock:
            if self._closed:
                raise RuntimeError("Stream is closed")

            partition = self._determine_partition(key)
            log = self._logs[partition]

            # Bounded capacity check
            active_depth = len(log) - self._consumer_offsets[partition]
            if active_depth >= self.max_partition_capacity:
                raise BufferFullError(
                    f"Partition {partition} exceeded capacity {self.max_partition_capacity}",
                    details={
                        "partition": partition,
                        "capacity": self.max_partition_capacity,
                        "lag": active_depth,
                    },
                )

            self._seq += 1
            offset = len(log)
            msg_id = f"msg-{self._seq}-{partition}-{offset}"
            msg = StreamMessage(
                message_id=msg_id,
                partition=partition,
                offset=offset,
                key=key,
                payload=payload,
                headers=headers or {},
            )
            log.append(msg)
            self._not_empty.notify_all()
            return msg

    def poll(self, timeout_sec: float = 0.5, max_records: int = 100) -> list[StreamMessage]:
        deadline = time.time() + timeout_sec
        results: list[StreamMessage] = []

        with self._lock:
            while not self._closed and len(results) < max_records:
                found_any = False
                for p in range(self.num_partitions):
                    log = self._logs[p]
                    while self._consumer_offsets[p] < len(log) and len(results) < max_records:
                        offset = self._consumer_offsets[p]
                        msg = log[offset]
                        self._consumer_offsets[p] = offset + 1
                        self._inflight[msg.message_id] = msg
                        results.append(msg)
                        found_any = True

                if len(results) >= max_records or self._closed:
                    break

                if not found_any:
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        break
                    self._not_empty.wait(timeout=min(remaining, 0.1))
                else:
                    break

        return results

    def ack(self, message: StreamMessage) -> None:
        with self._lock:
            self._inflight.pop(message.message_id, None)

    def nack(self, message: StreamMessage, requeue: bool = True) -> None:
        with self._lock:
            self._inflight.pop(message.message_id, None)
            if requeue and not self._closed:
                # Reset consumer offset back to message offset if it was the last read
                p = message.partition
                if self._consumer_offsets[p] > message.offset:
                    self._consumer_offsets[p] = message.offset
                    self._not_empty.notify_all()

    def seek(self, partition: int, offset: int) -> None:
        with self._lock:
            if partition not in self._logs:
                raise IndexError(f"Partition {partition} does not exist")
            log = self._logs[partition]
            bounded_offset = max(0, min(offset, len(log)))
            self._consumer_offsets[partition] = bounded_offset
            self._not_empty.notify_all()

    def get_lag(self, partition: int) -> int:
        with self._lock:
            if partition not in self._logs:
                return 0
            return max(0, len(self._logs[partition]) - self._consumer_offsets[partition])

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._not_empty.notify_all()
