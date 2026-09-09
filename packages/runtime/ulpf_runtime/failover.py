"""ULPF Phase 7 & Phase 14 — Failover, Degraded Mode & Cluster Coordinator.

Models graceful failover behavior in the face of:
- Search subsystem failure → canonical processing continues (degraded mode)
- Database subsystem failure → ingest REJECTED with fail-closed semantics
- Authentication subsystem failure → all requests rejected (fail-closed)
- Delivery sink failure → routed to DLQ (fail-open for delivery)

Phase 14 Additions:
- High Availability & Worker Failover Coordinator (Workstream G)
- Dynamic partition lease rebalancing on worker crash or join
- Rebalance handling: no event loss or duplicate execution
- Uncommitted offset recovery upon reassignment
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum, auto
from typing import Any

logger = logging.getLogger(__name__)


class SubsystemStatus(Enum):
    """Health status of a platform subsystem."""
    HEALTHY = auto()
    DEGRADED = auto()
    FAILED = auto()


class FailoverBehavior(Enum):
    """How to respond when a subsystem is unavailable."""
    FAIL_CLOSED = auto()   # Reject operation entirely
    FAIL_OPEN = auto()     # Continue with degraded service
    ROUTE_DLQ = auto()     # Accept but route to dead-letter queue


@dataclass
class SubsystemConfig:
    """Configuration for a subsystem's failover behavior."""
    name: str
    failure_behavior: FailoverBehavior
    description: str


# Platform subsystem failover configuration
SUBSYSTEM_CONFIGS: dict[str, SubsystemConfig] = {
    "database": SubsystemConfig(
        name="database",
        failure_behavior=FailoverBehavior.FAIL_CLOSED,
        description="Database failure: ingest rejected, no false ACK",
    ),
    "auth": SubsystemConfig(
        name="auth",
        failure_behavior=FailoverBehavior.FAIL_CLOSED,
        description="Auth failure: all requests rejected, no anonymous access",
    ),
    "search": SubsystemConfig(
        name="search",
        failure_behavior=FailoverBehavior.FAIL_OPEN,
        description="Search failure: canonical processing continues in degraded mode",
    ),
    "delivery": SubsystemConfig(
        name="delivery",
        failure_behavior=FailoverBehavior.ROUTE_DLQ,
        description="Delivery failure: route to DLQ, no silent drop",
    ),
    "stream": SubsystemConfig(
        name="stream",
        failure_behavior=FailoverBehavior.FAIL_CLOSED,
        description="Stream failure: ingest paused, backpressure active",
    ),
}


class FailoverDecision:
    """The result of a failover evaluation."""

    __slots__ = ("subsystem", "behavior", "allowed", "reason", "decided_at")

    def __init__(
        self,
        subsystem: str,
        behavior: FailoverBehavior,
        allowed: bool,
        reason: str,
    ) -> None:
        self.subsystem = subsystem
        self.behavior = behavior
        self.allowed = allowed
        self.reason = reason
        self.decided_at = datetime.now(UTC).isoformat()


class DegradedModeController:
    """Tracks subsystem health and evaluates failover decisions.

    The controller models fail-closed (database, auth, stream) and
    fail-open (search) behaviors according to the ULPF security policy.
    """

    def __init__(self) -> None:
        self._status: dict[str, SubsystemStatus] = {
            name: SubsystemStatus.HEALTHY for name in SUBSYSTEM_CONFIGS
        }
        self._incident_log: list[dict[str, Any]] = []

    def mark_failed(self, subsystem: str, reason: str = "") -> None:
        """Mark a subsystem as failed and log the incident."""
        if subsystem not in SUBSYSTEM_CONFIGS:
            raise ValueError(f"Unknown subsystem: {subsystem}")
        self._status[subsystem] = SubsystemStatus.FAILED
        self._incident_log.append({
            "subsystem": subsystem,
            "transition": "HEALTHY→FAILED",
            "reason": reason,
            "at": datetime.now(UTC).isoformat(),
        })
        logger.warning("Subsystem '%s' marked FAILED: %s", subsystem, reason)

    def mark_degraded(self, subsystem: str, reason: str = "") -> None:
        """Mark a subsystem as degraded (reduced performance)."""
        if subsystem not in SUBSYSTEM_CONFIGS:
            raise ValueError(f"Unknown subsystem: {subsystem}")
        self._status[subsystem] = SubsystemStatus.DEGRADED
        self._incident_log.append({
            "subsystem": subsystem,
            "transition": "→DEGRADED",
            "reason": reason,
            "at": datetime.now(UTC).isoformat(),
        })
        logger.warning("Subsystem '%s' marked DEGRADED: %s", subsystem, reason)

    def mark_recovered(self, subsystem: str) -> None:
        """Mark a subsystem as recovered."""
        if subsystem not in SUBSYSTEM_CONFIGS:
            raise ValueError(f"Unknown subsystem: {subsystem}")
        prev = self._status.get(subsystem, SubsystemStatus.HEALTHY)
        self._status[subsystem] = SubsystemStatus.HEALTHY
        self._incident_log.append({
            "subsystem": subsystem,
            "transition": f"{prev.name}→HEALTHY",
            "at": datetime.now(UTC).isoformat(),
        })
        logger.info("Subsystem '%s' recovered", subsystem)

    def evaluate(self, subsystem: str, operation: str = "") -> FailoverDecision:
        """Evaluate whether an operation should proceed given subsystem health."""
        config = SUBSYSTEM_CONFIGS.get(subsystem)
        if config is None:
            # Unknown subsystem: fail closed by default
            return FailoverDecision(
                subsystem=subsystem,
                behavior=FailoverBehavior.FAIL_CLOSED,
                allowed=False,
                reason=f"Unknown subsystem '{subsystem}': fail closed",
            )

        status = self._status.get(subsystem, SubsystemStatus.HEALTHY)

        if status == SubsystemStatus.HEALTHY:
            return FailoverDecision(
                subsystem=subsystem,
                behavior=config.failure_behavior,
                allowed=True,
                reason="Subsystem healthy",
            )

        # Subsystem DEGRADED or FAILED
        if config.failure_behavior == FailoverBehavior.FAIL_CLOSED:
            return FailoverDecision(
                subsystem=subsystem,
                behavior=config.failure_behavior,
                allowed=False,
                reason=f"{config.description} [status={status.name}]",
            )
        elif config.failure_behavior == FailoverBehavior.FAIL_OPEN:
            return FailoverDecision(
                subsystem=subsystem,
                behavior=config.failure_behavior,
                allowed=True,
                reason=f"Degraded mode: {config.description} [status={status.name}]",
            )
        else:  # ROUTE_DLQ
            return FailoverDecision(
                subsystem=subsystem,
                behavior=config.failure_behavior,
                allowed=True,  # Allowed but will be routed to DLQ by caller
                reason=f"DLQ routing: {config.description} [status={status.name}]",
            )

    def get_status(self) -> dict[str, str]:
        return {name: status.name for name, status in self._status.items()}

    def incident_log(self) -> list[dict[str, Any]]:
        return list(self._incident_log)

    def is_healthy(self) -> bool:
        return all(s == SubsystemStatus.HEALTHY for s in self._status.values())


# ==============================================================================
# Phase 14 Workstream G: Worker Failover & Cluster Lease Rebalancing
# ==============================================================================

@dataclass
class WorkerDescriptor:
    """Registered worker node in the distributed cluster."""

    worker_id: str
    host: str
    assigned_partitions: set[int] = field(default_factory=set)
    last_heartbeat: float = 0.0
    is_active: bool = True


class FailoverCoordinator:
    """Coordinates worker leases, detects node failures, and rebalances partitions."""

    def __init__(
        self,
        num_partitions: int = 8,
        heartbeat_timeout_seconds: float = 3.0,
    ) -> None:
        self.num_partitions = num_partitions
        self.heartbeat_timeout_seconds = heartbeat_timeout_seconds
        self._workers: dict[str, WorkerDescriptor] = {}
        self._partition_assignments: dict[int, str | None] = {
            i: None for i in range(num_partitions)
        }
        self._committed_offsets: dict[int, int] = {i: 0 for i in range(num_partitions)}
        self._rebalance_events: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def register_worker(self, worker_id: str, host: str = "127.0.0.1") -> bool:
        """Register a worker and trigger rebalancing."""
        with self._lock:
            self._workers[worker_id] = WorkerDescriptor(
                worker_id=worker_id,
                host=host,
                last_heartbeat=time.time(),
                is_active=True,
            )
            self._rebalance_locked()
            return True

    def heartbeat(self, worker_id: str) -> bool:
        """Update worker heartbeat timestamp."""
        with self._lock:
            if worker_id in self._workers:
                self._workers[worker_id].last_heartbeat = time.time()
                self._workers[worker_id].is_active = True
                return True
            return False

    def commit_offset(self, partition_id: int, offset: int) -> None:
        """Record strictly committed offset for a partition."""
        with self._lock:
            if partition_id in self._committed_offsets:
                if offset > self._committed_offsets[partition_id]:
                    self._committed_offsets[partition_id] = offset

    def get_committed_offset(self, partition_id: int) -> int:
        with self._lock:
            return self._committed_offsets.get(partition_id, 0)

    def check_failures_and_rebalance(self, now: float | None = None) -> list[str]:
        """Detect timed-out workers, mark inactive, and reassign orphaned partitions."""
        current_time = now if now is not None else time.time()
        failed_workers = []
        with self._lock:
            for w_id, w in self._workers.items():
                if w.is_active and (current_time - w.last_heartbeat) > self.heartbeat_timeout_seconds:
                    w.is_active = False
                    failed_workers.append(w_id)

            if failed_workers:
                self._rebalance_locked(trigger_reason=f"Workers failed: {failed_workers}")
        return failed_workers

    def _rebalance_locked(self, trigger_reason: str = "cluster change") -> None:
        """Evenly distribute partitions across active workers."""
        active = [w for w in self._workers.values() if w.is_active]
        if not active:
            for p in self._partition_assignments:
                self._partition_assignments[p] = None
            return

        # Clear assignments
        for w in self._workers.values():
            w.assigned_partitions.clear()

        # Deterministic round-robin partition assignment
        active_sorted = sorted(active, key=lambda w: w.worker_id)
        for p in range(self.num_partitions):
            target_worker = active_sorted[p % len(active_sorted)]
            target_worker.assigned_partitions.add(p)
            self._partition_assignments[p] = target_worker.worker_id

        self._rebalance_events.append({
            "timestamp": time.time(),
            "reason": trigger_reason,
            "active_workers": [w.worker_id for w in active_sorted],
            "assignments": {p: self._partition_assignments[p] for p in range(self.num_partitions)},
        })

    def get_worker_partitions(self, worker_id: str) -> set[int]:
        with self._lock:
            w = self._workers.get(worker_id)
            return set(w.assigned_partitions) if w and w.is_active else set()

    def get_cluster_status(self) -> dict[str, Any]:
        with self._lock:
            active = sum(1 for w in self._workers.values() if w.is_active)
            return {
                "total_workers": len(self._workers),
                "active_workers": active,
                "num_partitions": self.num_partitions,
                "assignments": dict(self._partition_assignments),
                "committed_offsets": dict(self._committed_offsets),
                "rebalance_count": len(self._rebalance_events),
            }
