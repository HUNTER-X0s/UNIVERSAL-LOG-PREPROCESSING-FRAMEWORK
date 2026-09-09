"""Tests for ULPF Phase 14 Milestone B — Distributed Platform.

Verifies:
- Workstream A: Distributed ingestion fabric & envelope creation
- Workstream B: Multi-key partition routing (source, tenant, entity, hash)
- Workstream C: Distributed idempotency registry & deduplication
- Workstream D: Bounded lateness ordering (event-time vs ingestion-time)
- Workstream E: Mission-scale backpressure & lossless DLQ integrity
- Workstream F: Autoscaling signals
- Workstream G: Worker failover, heartbeat tracking, and partition reassignment
"""

import time
import pytest
from ulpf_streaming.fabric import (
    BoundedLatenessBuffer,
    DistributedEnvelope,
    DistributedIdempotencyRegistry,
    DistributedIngestionFabric,
    PartitionStrategy,
)
from ulpf_runtime.mission_backpressure import (
    BackpressureState,
    LosslessDeadLetterQueue,
    MissionBackpressureController,
)
from ulpf_runtime.failover import FailoverCoordinator


def test_distributed_envelope_immutability_and_hash():
    env = DistributedEnvelope.create(
        source_id="palo_alto_firewall",
        raw_payload="1,2026/09/09,001234,TRAFFIC,drop,1,2026/09/09,10.0.0.1,192.168.1.1",
        tenant_id="tenant-alpha",
        entity_id="host-101",
        event_time=1725880000.0,
    )
    assert env.source_id == "palo_alto_firewall"
    assert env.tenant_id == "tenant-alpha"
    assert len(env.raw_sha256) == 64
    assert env.event_time == 1725880000.0
    with pytest.raises(Exception):
        env.source_id = "mutated"  # Frozen dataclass


def test_multi_key_partition_routing_determinism():
    fabric_source = DistributedIngestionFabric(num_partitions=8, strategy=PartitionStrategy.SOURCE)
    fabric_tenant = DistributedIngestionFabric(num_partitions=8, strategy=PartitionStrategy.TENANT)

    env1 = DistributedEnvelope.create("firewall-1", "msg1", tenant_id="tenant-a")
    env2 = DistributedEnvelope.create("firewall-1", "msg2", tenant_id="tenant-b")

    # Under SOURCE strategy, same source routes to same partition regardless of payload/tenant
    p1_s = fabric_source.route_partition(env1)
    p2_s = fabric_source.route_partition(env2)
    assert p1_s == p2_s

    # Under TENANT strategy, different tenants route according to tenant hash
    p1_t = fabric_tenant.route_partition(env1)
    p2_t = fabric_tenant.route_partition(env2)
    assert 0 <= p1_t < 8
    assert 0 <= p2_t < 8


def test_distributed_idempotency_and_deduplication():
    registry = DistributedIdempotencyRegistry(capacity=1000, ttl_seconds=60.0)
    env = DistributedEnvelope.create("auth_service", "Failed login for root", event_time=100.0)

    # First attempt: accepted
    assert registry.mark_processed(env) is True
    assert registry.is_duplicate(env) is True

    # Immediate duplicate: rejected
    assert registry.mark_processed(env) is False

    # Different event time or content: accepted
    env_diff = DistributedEnvelope.create("auth_service", "Failed login for root", event_time=101.0)
    assert registry.mark_processed(env_diff) is True


def test_bounded_lateness_reordering():
    buf = BoundedLatenessBuffer(lateness_budget_seconds=1.0)
    base_t = 1000.0

    # Event 3 arrives first (t=1005)
    e3 = DistributedEnvelope.create("src", "ev3", event_time=base_t + 5)
    # Event 1 arrives second (out-of-order, t=1001)
    e1 = DistributedEnvelope.create("src", "ev1", event_time=base_t + 1)
    # Event 2 arrives third (out-of-order, t=1003)
    e2 = DistributedEnvelope.create("src", "ev2", event_time=base_t + 3)

    buf.add(e3)
    buf.add(e1)
    buf.add(e2)

    # Watermark is now 1005. Threshold is 1005 - 1.0 = 1004.
    # Events e1 (1001) and e2 (1003) are <= 1004 and should drain in correct order!
    drained = buf.drain_ready(current_time=time.time())
    assert len(drained) == 2
    assert drained[0].event_time == base_t + 1
    assert drained[1].event_time == base_t + 3

    # Flush remaining
    remaining = buf.flush_all()
    assert len(remaining) == 1
    assert remaining[0].event_time == base_t + 5


def test_mission_backpressure_and_lossless_dlq():
    ctrl = MissionBackpressureController(max_queue_depth=100)

    # Normal load
    assert ctrl.evaluate_state(current_queue_depth=20) == BackpressureState.NORMAL
    # Degraded load
    assert ctrl.evaluate_state(current_queue_depth=65) == BackpressureState.DEGRADED
    # Overload
    assert ctrl.evaluate_state(current_queue_depth=85) == BackpressureState.OVERLOAD
    # Critical overload
    assert ctrl.evaluate_state(current_queue_depth=98) == BackpressureState.CRITICAL_OVERLOAD

    # Test Lossless DLQ Spilling under Critical Overload
    admitted, dlq_rec = ctrl.process_envelope_admission(
        source_id="overloaded_stream",
        raw_payload="critical audit event",
        current_queue_depth=100,  # Maxed out
    )
    assert admitted is False
    assert dlq_rec is not None
    assert dlq_rec.original_source_id == "overloaded_stream"
    assert ctrl.dlq.get_count() == 1

    # Invariant check: DLQ record integrity
    integrity = ctrl.dlq.verify_integrity()
    assert integrity["integrity_intact"] is True
    assert integrity["valid"] == 1


def test_autoscaling_signal_generation():
    ctrl = MissionBackpressureController(max_queue_depth=100)

    # Idle load recommends scale down
    sig_down = ctrl.generate_autoscale_signal(current_queue_depth=5, current_workers=4)
    assert sig_down.scale_direction == "DOWN"
    assert sig_down.recommended_worker_count == 3

    # Critical overload recommends scale up and throttle
    sig_up = ctrl.generate_autoscale_signal(current_queue_depth=98, current_workers=4, consumer_lag=6000)
    assert sig_up.scale_direction == "UP"
    assert sig_up.recommended_worker_count >= 8
    assert sig_up.throttle_rate_percent > 0


def test_failover_coordinator_heartbeat_and_rebalance():
    coord = FailoverCoordinator(num_partitions=6, heartbeat_timeout_seconds=0.5)

    # Register 2 workers
    coord.register_worker("worker-1")
    coord.register_worker("worker-2")

    status = coord.get_cluster_status()
    assert status["active_workers"] == 2
    w1_parts = coord.get_worker_partitions("worker-1")
    w2_parts = coord.get_worker_partitions("worker-2")
    assert len(w1_parts) == 3
    assert len(w2_parts) == 3
    assert w1_parts.union(w2_parts) == {0, 1, 2, 3, 4, 5}

    # Commit offset on partition 0
    coord.commit_offset(partition_id=0, offset=150)
    assert coord.get_committed_offset(partition_id=0) == 150

    # Simulate worker-2 crash (worker-1 stays alive with continuous heartbeat)
    time.sleep(0.3)
    coord.heartbeat("worker-1")
    time.sleep(0.3)
    coord.heartbeat("worker-1")
    failed = coord.check_failures_and_rebalance()
    assert "worker-2" in failed
    assert "worker-1" not in failed

    # All 6 partitions should now be assigned to worker-1 with 0 loss of committed offset
    new_w1_parts = coord.get_worker_partitions("worker-1")
    assert len(new_w1_parts) == 6
    assert coord.get_committed_offset(partition_id=0) == 150
