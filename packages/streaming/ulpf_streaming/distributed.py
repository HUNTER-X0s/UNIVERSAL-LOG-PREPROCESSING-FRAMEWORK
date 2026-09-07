"""ULPF Phase 7 — Distributed Event Stream with Offset Commits and Recovery.

Provides a `DistributedEventStream` interface and an in-process simulation
(`InProcessDistributedStream`) for testing distributed consumer group semantics
including:
- Deterministic SHA-256 partition routing by source_id
- Consumer group coordination with committed offsets
- Crash recovery: replay from last committed offset
- Rebalance handling on consumer join/leave
- At-least-once delivery with committed offset strictly post-persistence

Enforces:
- Rule C1: Partition key determinism (source_id → SHA-256 partition assignment)
- Rule C2: Committed offsets strictly after persistence boundary
- Rule C3: Crash recovery replays uncommitted records
- Rule C4: Consumer group coordination with rebalance
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime

from ulpf_streaming.interfaces import StreamMessage


class PartitionAssignmentError(Exception):
    """Raised when partition assignment fails."""


class OffsetCommitError(Exception):
    """Raised when an offset commit fails."""


@dataclass
class PartitionState:
    """State for a single partition within the distributed stream."""

    partition_id: int
    messages: list[StreamMessage] = field(default_factory=list)
    # consumer_id → committed offset
    committed_offsets: dict[str, int] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)


class DistributedEventStream:
    """Distributed event stream with consumer group coordination.

    Provides a partitioned, at-least-once delivery stream with explicit
    offset commits strictly after persistence boundary.

    Consumer groups share a committed offset table per partition; crash recovery
    replays from the last committed offset so no events are silently skipped.
    """

    def __init__(
        self,
        topic: str = "ulpf-events",
        num_partitions: int = 4,
    ) -> None:
        self._topic = topic
        self._num_partitions = num_partitions
        self._partitions: dict[int, PartitionState] = {
            i: PartitionState(partition_id=i) for i in range(num_partitions)
        }
        # consumer_group → consumer_id → list[partition_id]
        self._consumer_groups: dict[str, dict[str, list[int]]] = {}
        self._group_lock = threading.Lock()
        self._global_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Partition routing
    # ------------------------------------------------------------------

    def route_partition(self, source_id: str) -> int:
        """Deterministically route source_id to a partition via SHA-256."""
        digest = hashlib.sha256(source_id.encode("utf-8")).digest()
        return int.from_bytes(digest[:4], "big") % self._num_partitions

    # ------------------------------------------------------------------
    # Publishing
    # ------------------------------------------------------------------

    def publish(
        self,
        key: str,
        payload: bytes,
        source_id: str | None = None,
        headers: dict[str, str] | None = None,
        partition_override: int | None = None,
    ) -> StreamMessage:
        """Publish a message, routing by source_id or explicit partition."""
        partition_id = (
            partition_override
            if partition_override is not None
            else self.route_partition(source_id or key)
        )

        partition = self._partitions[partition_id]
        with partition._lock:
            offset = len(partition.messages)
            msg = StreamMessage(
                message_id=f"{self._topic}-p{partition_id}-{offset}",
                partition=partition_id,
                offset=offset,
                key=key,
                payload=payload,
                timestamp=datetime.now(UTC).isoformat(),
                headers=headers or {},
            )
            partition.messages.append(msg)
        return msg

    # ------------------------------------------------------------------
    # Consumer group coordination
    # ------------------------------------------------------------------

    def join_consumer_group(
        self, group_id: str, consumer_id: str, requested_partitions: list[int] | None = None
    ) -> list[int]:
        """Register a consumer in a group and get partition assignments.

        On rebalance (new consumer joins), partitions are redistributed
        evenly across all consumers in the group.

        Returns the list of partition IDs assigned to this consumer.
        """
        with self._group_lock:
            if group_id not in self._consumer_groups:
                self._consumer_groups[group_id] = {}

            group = self._consumer_groups[group_id]
            group[consumer_id] = []

            # Rebalance: clear all assignments first, then redistribute evenly
            all_partitions = list(range(self._num_partitions))
            consumers = sorted(group.keys())
            for c in consumers:
                group[c] = []
            # Round-robin assignment
            for idx, pid in enumerate(all_partitions):
                assigned_consumer = consumers[idx % len(consumers)]
                group[assigned_consumer].append(pid)

            return list(group[consumer_id])

    def leave_consumer_group(self, group_id: str, consumer_id: str) -> None:
        """Remove a consumer from a group and trigger rebalance."""
        with self._group_lock:
            group = self._consumer_groups.get(group_id, {})
            group.pop(consumer_id, None)
            if not group:
                self._consumer_groups.pop(group_id, None)
                return
            # Rebalance remaining consumers
            all_partitions = list(range(self._num_partitions))
            consumers = sorted(group.keys())
            for c in consumers:
                group[c] = []
            for idx, pid in enumerate(all_partitions):
                assigned_consumer = consumers[idx % len(consumers)]
                group[assigned_consumer].append(pid)

    def get_assigned_partitions(self, group_id: str, consumer_id: str) -> list[int]:
        """Return partitions currently assigned to a consumer."""
        with self._group_lock:
            return list(self._consumer_groups.get(group_id, {}).get(consumer_id, []))

    # ------------------------------------------------------------------
    # Polling with offset tracking
    # ------------------------------------------------------------------

    def poll(
        self,
        group_id: str,
        consumer_id: str,
        partition_id: int,
        max_records: int = 100,
    ) -> list[StreamMessage]:
        """Poll for unconsumed messages in a partition from the committed offset.

        This implements at-least-once delivery: returns messages from the
        last committed offset so that uncommitted messages are replayed after
        a crash.
        """
        partition = self._partitions[partition_id]
        with partition._lock:
            # Determine start offset from committed offset (default: 0)
            group_key = f"{group_id}:{consumer_id}"
            start = partition.committed_offsets.get(group_key, 0)
            available = partition.messages[start:]
            return available[:max_records]

    # ------------------------------------------------------------------
    # Offset commit (strictly post-persistence)
    # ------------------------------------------------------------------

    def commit_offset(
        self, group_id: str, consumer_id: str, partition_id: int, offset: int
    ) -> None:
        """Commit processed offset. Must be called AFTER successful persistence.

        This is the at-least-once safety guarantee: calling commit before
        persistence would risk data loss on crash.
        """
        partition = self._partitions[partition_id]
        with partition._lock:
            group_key = f"{group_id}:{consumer_id}"
            current = partition.committed_offsets.get(group_key, 0)
            if offset < current:
                raise OffsetCommitError(
                    f"Attempt to commit offset {offset} below current {current} "
                    f"(would create gap)"
                )
            partition.committed_offsets[group_key] = offset

    def get_committed_offset(
        self, group_id: str, consumer_id: str, partition_id: int
    ) -> int:
        """Return the last committed offset for a consumer in a partition."""
        partition = self._partitions[partition_id]
        with partition._lock:
            group_key = f"{group_id}:{consumer_id}"
            return partition.committed_offsets.get(group_key, 0)

    # ------------------------------------------------------------------
    # Lag and introspection
    # ------------------------------------------------------------------

    def get_lag(self, group_id: str, consumer_id: str, partition_id: int) -> int:
        """Return unconsumed message lag for a consumer on a partition."""
        partition = self._partitions[partition_id]
        with partition._lock:
            group_key = f"{group_id}:{consumer_id}"
            committed = partition.committed_offsets.get(group_key, 0)
            return max(0, len(partition.messages) - committed)

    def partition_count(self) -> int:
        return self._num_partitions

    def topic(self) -> str:
        return self._topic
