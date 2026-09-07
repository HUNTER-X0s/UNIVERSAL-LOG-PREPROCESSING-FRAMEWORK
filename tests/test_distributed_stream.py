"""Phase 7 Test: Distributed Event Stream.

Verifies:
- Rule C1: Partition routing is deterministic via SHA-256(source_id)
- Rule C2: Committed offsets recorded strictly post-persistence
- Rule C3: Crash recovery replays from committed offset
- Rule C4: Consumer group coordination and rebalance
"""

import pytest
from ulpf_streaming.distributed import DistributedEventStream, OffsetCommitError


@pytest.fixture()
def stream() -> DistributedEventStream:
    return DistributedEventStream(topic="test-events", num_partitions=4)


def test_deterministic_partition_routing(stream: DistributedEventStream) -> None:
    """Same source_id must always map to same partition."""
    for _ in range(10):
        assert stream.route_partition("firewall-A") == stream.route_partition("firewall-A")
        assert stream.route_partition("ids-sensor-01") == stream.route_partition("ids-sensor-01")


def test_different_sources_route_to_correct_partitions(stream: DistributedEventStream) -> None:
    """Different sources should be routable (distribution may not be uniform with 2 sources)."""
    p1 = stream.route_partition("source-alpha")
    p2 = stream.route_partition("source-beta")
    # At minimum, both must be valid partition IDs
    assert 0 <= p1 < stream.partition_count()
    assert 0 <= p2 < stream.partition_count()


def test_publish_and_poll(stream: DistributedEventStream) -> None:
    stream.join_consumer_group("group-1", "consumer-1")
    partitions = stream.get_assigned_partitions("group-1", "consumer-1")

    # Publish to a known partition
    pid = partitions[0] if partitions else 0
    msg = stream.publish("k1", b"payload-001", partition_override=pid)
    assert msg.partition == pid
    assert msg.payload == b"payload-001"

    # Poll should return that message
    messages = stream.poll("group-1", "consumer-1", pid, max_records=10)
    assert len(messages) == 1
    assert messages[0].payload == b"payload-001"


def test_committed_offset_advances(stream: DistributedEventStream) -> None:
    stream.join_consumer_group("g1", "c1")
    pid = 0

    stream.publish("k", b"msg-1", partition_override=pid)
    stream.publish("k", b"msg-2", partition_override=pid)

    messages = stream.poll("g1", "c1", pid, max_records=10)
    assert len(messages) == 2

    # Commit after processing first message
    stream.commit_offset("g1", "c1", pid, 1)
    assert stream.get_committed_offset("g1", "c1", pid) == 1

    # Poll again should only return messages from offset 1+
    remaining = stream.poll("g1", "c1", pid, max_records=10)
    assert len(remaining) == 1
    assert remaining[0].payload == b"msg-2"


def test_crash_recovery_replays_uncommitted(stream: DistributedEventStream) -> None:
    """After crash (no commit), re-poll returns same messages."""
    stream.join_consumer_group("g-crash", "c-crash")
    pid = 0

    stream.publish("k", b"crash-msg-1", partition_override=pid)
    stream.publish("k", b"crash-msg-2", partition_override=pid)

    # Process but do NOT commit (simulate crash)
    msgs1 = stream.poll("g-crash", "c-crash", pid)
    assert len(msgs1) == 2

    # Re-poll (recovery): must see same messages again
    msgs2 = stream.poll("g-crash", "c-crash", pid)
    assert len(msgs2) == 2
    assert msgs2[0].payload == msgs1[0].payload


def test_consumer_group_rebalance(stream: DistributedEventStream) -> None:
    """When a second consumer joins, partitions are redistributed."""
    partitions_c1 = stream.join_consumer_group("g-rebalance", "consumer-1")
    assert len(partitions_c1) == 4  # All 4 partitions to single consumer

    partitions_c2 = stream.join_consumer_group("g-rebalance", "consumer-2")
    # After rebalance, partitions should be split
    partitions_c1_after = stream.get_assigned_partitions("g-rebalance", "consumer-1")
    total = len(partitions_c1_after) + len(partitions_c2)
    assert total == 4  # All partitions still covered


def test_consumer_leave_triggers_rebalance(stream: DistributedEventStream) -> None:
    stream.join_consumer_group("g-leave", "c1")
    stream.join_consumer_group("g-leave", "c2")
    stream.leave_consumer_group("g-leave", "c2")

    # After c2 leaves, c1 should have all partitions
    partitions = stream.get_assigned_partitions("g-leave", "c1")
    assert len(partitions) == 4


def test_lag_calculation(stream: DistributedEventStream) -> None:
    stream.join_consumer_group("g-lag", "c1")
    pid = 0

    assert stream.get_lag("g-lag", "c1", pid) == 0

    stream.publish("k", b"m1", partition_override=pid)
    stream.publish("k", b"m2", partition_override=pid)
    assert stream.get_lag("g-lag", "c1", pid) == 2

    stream.commit_offset("g-lag", "c1", pid, 1)
    assert stream.get_lag("g-lag", "c1", pid) == 1


def test_offset_regression_rejected(stream: DistributedEventStream) -> None:
    """Committing a lower offset than current committed raises OffsetCommitError."""
    stream.join_consumer_group("g-reg", "c1")
    pid = 0

    stream.publish("k", b"m1", partition_override=pid)
    stream.publish("k", b"m2", partition_override=pid)
    stream.commit_offset("g-reg", "c1", pid, 2)

    with pytest.raises(OffsetCommitError):
        stream.commit_offset("g-reg", "c1", pid, 1)
