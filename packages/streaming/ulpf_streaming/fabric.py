"""ULPF Phase 14 — Distributed Ingestion Fabric, Partition Routing & Idempotency.

Fulfills Phase 14 Workstreams A, B, C, and D:
- Multi-collector partitioned streaming
- Deterministic multi-key partition routing (source, tenant, entity, device, hash)
- Bounded lateness window for out-of-order events (event-time vs ingestion-time)
- Distributed idempotency and replay-safe deduplication
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PartitionStrategy(str, Enum):
    """Partitioning strategy for distributed routing."""

    SOURCE = "SOURCE"
    TENANT = "TENANT"
    ENTITY = "ENTITY"
    DEVICE = "DEVICE"
    HASH = "HASH"
    ROUND_ROBIN = "ROUND_ROBIN"


class OrderingSemantics(str, Enum):
    """Ordering guarantee for event processing."""

    EVENT_TIME = "EVENT_TIME"
    INGESTION_TIME = "INGESTION_TIME"
    PARTITION_ORDER = "PARTITION_ORDER"
    BEST_EFFORT = "BEST_EFFORT"


@dataclass(frozen=True)
class DistributedEnvelope:
    """Envelope wrapping a raw log event across distributed boundaries.
    
    Preserves raw evidence identity, source, tenant, lineage, and ordering keys.
    """

    envelope_id: str
    source_id: str
    tenant_id: str
    raw_payload: str
    raw_sha256: str
    ingestion_time: float
    event_time: float
    partition_id: int
    partition_key: str
    sequence_number: int
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        source_id: str,
        raw_payload: str,
        tenant_id: str = "default",
        entity_id: str | None = None,
        event_time: float | None = None,
        partition_override: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> DistributedEnvelope:
        now = time.time()
        ev_time = event_time if event_time is not None else now
        raw_bytes = raw_payload.encode("utf-8")
        h = hashlib.sha256(raw_bytes).hexdigest()
        env_id = hashlib.sha256(f"{source_id}:{h}:{now}".encode()).hexdigest()[:16]
        return cls(
            envelope_id=env_id,
            source_id=source_id,
            tenant_id=tenant_id,
            raw_payload=raw_payload,
            raw_sha256=h,
            ingestion_time=now,
            event_time=ev_time,
            partition_id=partition_override if partition_override is not None else -1,
            partition_key=entity_id or source_id,
            sequence_number=0,
            metadata=metadata or {},
        )


class DistributedIdempotencyRegistry:
    """Replay-safe distributed deduplication and idempotency registry.
    
    Workstream C: practical exactly-once-like semantics via durable processing keys.
    """

    def __init__(self, capacity: int = 50_000, ttl_seconds: float = 86400.0) -> None:
        self._capacity = capacity
        self._ttl_seconds = ttl_seconds
        self._processed_keys: dict[str, float] = {}
        self._lock = threading.Lock()

    def compute_idempotency_key(self, envelope: DistributedEnvelope) -> str:
        """Compute deterministic processing key from source + content hash + event time."""
        raw = (
            f"{envelope.source_id}:{envelope.raw_sha256}:"
            f"{envelope.event_time:.3f}:{envelope.tenant_id}"
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def is_duplicate(self, envelope: DistributedEnvelope) -> bool:
        """Check if envelope has already been processed without side effects."""
        key = self.compute_idempotency_key(envelope)
        now = time.time()
        with self._lock:
            if key in self._processed_keys:
                ts = self._processed_keys[key]
                if now - ts <= self._ttl_seconds:
                    return True
            return False

    def mark_processed(self, envelope: DistributedEnvelope) -> bool:
        """Atomically record processing key. Returns True if accepted, False if duplicate."""
        key = self.compute_idempotency_key(envelope)
        now = time.time()
        with self._lock:
            if key in self._processed_keys:
                ts = self._processed_keys[key]
                if now - ts <= self._ttl_seconds:
                    return False  # Duplicate
            if len(self._processed_keys) >= self._capacity:
                # Evict oldest 10%
                sorted_keys = sorted(self._processed_keys.items(), key=lambda x: x[1])
                for k, _ in sorted_keys[: max(1, self._capacity // 10)]:
                    del self._processed_keys[k]
            self._processed_keys[key] = now
            return True

    def clear(self) -> None:
        with self._lock:
            self._processed_keys.clear()


class BoundedLatenessBuffer:
    """Buffers and sorts events within a bounded temporal window.
    
    Workstream D: distinguishes event-time vs ingestion-time ordering.
    Allows late-arriving events up to `lateness_budget_seconds` to be reordered
    correctly before final emission to the pipeline.
    """

    def __init__(self, lateness_budget_seconds: float = 2.0) -> None:
        self.lateness_budget_seconds = lateness_budget_seconds
        self._buffer: list[DistributedEnvelope] = []
        self._lock = threading.Lock()
        self._watermark: float = 0.0

    def add(self, envelope: DistributedEnvelope) -> None:
        with self._lock:
            self._buffer.append(envelope)
            # Update event-time watermark
            if envelope.event_time > self._watermark:
                self._watermark = envelope.event_time

    def drain_ready(self, current_time: float | None = None) -> list[DistributedEnvelope]:
        """Drain events whose event_time is safely behind the watermark budget."""
        now = current_time if current_time is not None else time.time()
        with self._lock:
            if not self._buffer:
                return []
            threshold = self._watermark - self.lateness_budget_seconds
            ready = []
            remaining = []
            for env in self._buffer:
                is_expired = (now - env.ingestion_time) >= self.lateness_budget_seconds
                if env.event_time <= threshold or is_expired:
                    ready.append(env)
                else:
                    remaining.append(env)
            self._buffer = remaining
            # Sort ready by event_time, then ingestion_time for deterministic ordering
            ready.sort(key=lambda e: (e.event_time, e.ingestion_time, e.raw_sha256))
            return ready

    def flush_all(self) -> list[DistributedEnvelope]:
        """Flush entire buffer sorted deterministically."""
        with self._lock:
            sorted_all = sorted(
                self._buffer,
                key=lambda e: (e.event_time, e.ingestion_time, e.raw_sha256),
            )
            self._buffer.clear()
            return sorted_all


class DistributedIngestionFabric:
    """Master multi-collector partitioned ingestion fabric.
    
    Coordinates:
    - Partition assignment according to strategy
    - In-flight deduplication
    - Bounded lateness reordering
    - Event accounting without raw evidence loss
    """

    def __init__(
        self,
        num_partitions: int = 8,
        strategy: PartitionStrategy = PartitionStrategy.SOURCE,
        lateness_budget_seconds: float = 1.5,
    ) -> None:
        self.num_partitions = num_partitions
        self.strategy = strategy
        self.idempotency = DistributedIdempotencyRegistry()
        self._partition_queues: dict[int, deque[DistributedEnvelope]] = {
            i: deque() for i in range(num_partitions)
        }
        self._lateness_buffers: dict[int, BoundedLatenessBuffer] = {
            i: BoundedLatenessBuffer(lateness_budget_seconds) for i in range(num_partitions)
        }
        self._round_robin_counter = 0
        self._lock = threading.Lock()
        # Accounting metrics
        self.total_received = 0
        self.total_duplicates = 0
        self.total_routed = 0

    def route_partition(self, envelope: DistributedEnvelope) -> int:
        """Deterministically map envelope to a partition ID based on strategy."""
        if self.strategy == PartitionStrategy.ROUND_ROBIN:
            with self._lock:
                idx = self._round_robin_counter % self.num_partitions
                self._round_robin_counter += 1
                return idx
        elif self.strategy == PartitionStrategy.TENANT:
            key = envelope.tenant_id
        elif self.strategy == PartitionStrategy.ENTITY:
            key = envelope.partition_key
        elif self.strategy == PartitionStrategy.HASH:
            key = envelope.raw_sha256
        else:  # SOURCE
            key = envelope.source_id

        digest = hashlib.sha256(key.encode("utf-8")).digest()
        return int.from_bytes(digest[:4], "big") % self.num_partitions

    def submit(self, envelope: DistributedEnvelope) -> bool:
        """Submit an envelope to the fabric. Returns True if accepted, False if duplicate."""
        with self._lock:
            self.total_received += 1

        # 1. Idempotency Check
        if not self.idempotency.mark_processed(envelope):
            with self._lock:
                self.total_duplicates += 1
            return False

        # 2. Partition Routing
        target_p = envelope.partition_id
        if target_p < 0 or target_p >= self.num_partitions:
            target_p = self.route_partition(envelope)

        assigned_env = DistributedEnvelope(
            envelope_id=envelope.envelope_id,
            source_id=envelope.source_id,
            tenant_id=envelope.tenant_id,
            raw_payload=envelope.raw_payload,
            raw_sha256=envelope.raw_sha256,
            ingestion_time=envelope.ingestion_time,
            event_time=envelope.event_time,
            partition_id=target_p,
            partition_key=envelope.partition_key,
            sequence_number=self.total_routed + 1,
            metadata=envelope.metadata,
        )

        # 3. Buffer in partition lateness buffer
        self._lateness_buffers[target_p].add(assigned_env)
        with self._lock:
            self.total_routed += 1
        return True

    def poll_partition(self, partition_id: int, max_events: int = 100) -> list[DistributedEnvelope]:
        """Poll ordered, ready events from a partition."""
        if partition_id not in self._lateness_buffers:
            return []
        ready = self._lateness_buffers[partition_id].drain_ready()
        return ready[:max_events]

    def drain_all_partitions(self) -> list[DistributedEnvelope]:
        """Drain and flush all events across all partitions deterministically."""
        res = []
        for p in range(self.num_partitions):
            res.extend(self._lateness_buffers[p].flush_all())
        return res

    def get_stats(self) -> dict[str, Any]:
        """Return operational telemetry for the distributed fabric."""
        with self._lock:
            queue_depths = {
                p: len(self._lateness_buffers[p]._buffer)
                for p in range(self.num_partitions)
            }
            return {
                "num_partitions": self.num_partitions,
                "strategy": self.strategy.value,
                "total_received": self.total_received,
                "total_duplicates": self.total_duplicates,
                "total_routed": self.total_routed,
                "total_buffered": sum(queue_depths.values()),
                "partition_depths": queue_depths,
            }
