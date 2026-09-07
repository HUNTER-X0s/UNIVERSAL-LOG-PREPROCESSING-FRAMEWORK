"""Phase 7 Test: Committed Offsets — strict post-persistence semantics.

Verifies:
- Rule C2: Offset must be committed strictly AFTER persistence boundary
- Rule C2: Uncommitted offsets are replayed after restart
- Rule C2: Offset commit below current raises OffsetCommitError
"""

import pytest
from ulpf_streaming.distributed import DistributedEventStream, OffsetCommitError


@pytest.fixture()
def stream() -> DistributedEventStream:
    return DistributedEventStream(num_partitions=2)


def test_offset_not_committed_until_after_persistence(stream: DistributedEventStream) -> None:
    """Demonstrates at-least-once: if we don't commit, we replay."""
    stream.join_consumer_group("g1", "c1")
    pid = 0
    for i in range(5):
        stream.publish(f"k{i}", f"msg-{i}".encode(), partition_override=pid)

    # Consume but don't commit (simulate crash before persistence)
    batch1 = stream.poll("g1", "c1", pid, max_records=5)
    assert len(batch1) == 5

    # Recovery: same batch replayed
    batch2 = stream.poll("g1", "c1", pid, max_records=5)
    assert len(batch2) == 5

    # NOW commit (simulating successful persistence)
    stream.commit_offset("g1", "c1", pid, 5)

    # No more lag
    assert stream.get_lag("g1", "c1", pid) == 0


def test_commit_all_then_no_more_messages(stream: DistributedEventStream) -> None:
    stream.join_consumer_group("g2", "c2")
    pid = 1
    stream.publish("k", b"only-msg", partition_override=pid)

    messages = stream.poll("g2", "c2", pid)
    assert len(messages) == 1
    stream.commit_offset("g2", "c2", pid, 1)

    # No more unconsumed
    empty = stream.poll("g2", "c2", pid)
    assert len(empty) == 0


def test_commit_below_current_raises(stream: DistributedEventStream) -> None:
    stream.join_consumer_group("g3", "c3")
    pid = 0
    stream.publish("k", b"m", partition_override=pid)
    stream.commit_offset("g3", "c3", pid, 1)

    with pytest.raises(OffsetCommitError):
        stream.commit_offset("g3", "c3", pid, 0)


def test_initial_offset_is_zero(stream: DistributedEventStream) -> None:
    stream.join_consumer_group("g4", "c4")
    assert stream.get_committed_offset("g4", "c4", 0) == 0


def test_per_consumer_independent_offsets(stream: DistributedEventStream) -> None:
    """Two consumers in different groups have independent offsets."""
    stream.join_consumer_group("groupA", "cA")
    stream.join_consumer_group("groupB", "cB")
    pid = 0

    stream.publish("k", b"shared-msg", partition_override=pid)

    # Consumer A commits, consumer B does not
    stream.commit_offset("groupA", "cA", pid, 1)
    assert stream.get_committed_offset("groupA", "cA", pid) == 1
    assert stream.get_committed_offset("groupB", "cB", pid) == 0

    # Group B still has lag
    assert stream.get_lag("groupB", "cB", pid) == 1
    assert stream.get_lag("groupA", "cA", pid) == 0
