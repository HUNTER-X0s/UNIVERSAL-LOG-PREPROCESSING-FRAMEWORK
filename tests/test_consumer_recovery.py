"""Phase 7 Test: Consumer Crash Recovery.

Verifies:
- Rule C3: Consumer restart replays from last committed offset
- Rule C3: No messages are silently skipped after crash
- Rule C4: Rebalance after consumer crash reassigns partitions
"""

import pytest
from ulpf_streaming.distributed import DistributedEventStream


@pytest.fixture()
def stream() -> DistributedEventStream:
    return DistributedEventStream(num_partitions=4)


def test_consumer_replays_from_committed_offset_after_crash(
    stream: DistributedEventStream,
) -> None:
    """After crash (no commit for some messages), recovery must see them again."""
    stream.join_consumer_group("g1", "c1")
    pid = 0

    # Publish 10 messages
    for i in range(10):
        stream.publish(f"k{i}", f"msg-{i}".encode(), partition_override=pid)

    # Process and commit only first 5
    batch = stream.poll("g1", "c1", pid, max_records=10)
    assert len(batch) == 10
    stream.commit_offset("g1", "c1", pid, 5)

    # Simulate crash: new consumer instance in same group picks up
    # Re-poll from committed offset (5), should get remaining 5
    remaining = stream.poll("g1", "c1", pid, max_records=10)
    assert len(remaining) == 5
    assert remaining[0].offset == 5


def test_no_messages_lost_after_consumer_crash(stream: DistributedEventStream) -> None:
    """Every published message is eventually polled after consumer crash recovery."""
    stream.join_consumer_group("g2", "c2")
    pid = 1

    published_payloads = set()
    for i in range(5):
        payload = f"crash-safe-{i}".encode()
        stream.publish(f"k{i}", payload, partition_override=pid)
        published_payloads.add(payload)

    # Crash simulation: poll without commit
    _ = stream.poll("g2", "c2", pid, max_records=3)

    # Recovery: all messages still visible
    recovered = stream.poll("g2", "c2", pid, max_records=10)
    recovered_payloads = {m.payload for m in recovered}
    assert published_payloads == recovered_payloads


def test_consumer_crash_and_rejoin_gets_reassigned(stream: DistributedEventStream) -> None:
    """Consumer that crashes and rejoins should get partition assignments."""
    stream.join_consumer_group("g3", "original-c")
    orig_partitions = stream.get_assigned_partitions("g3", "original-c")
    assert len(orig_partitions) > 0

    # Simulate crash: leave group
    stream.leave_consumer_group("g3", "original-c")

    # New consumer instance joins (recovery)
    new_partitions = stream.join_consumer_group("g3", "recovered-c")
    assert len(new_partitions) == 4  # All partitions reassigned to recovered consumer


def test_partial_commit_replay(stream: DistributedEventStream) -> None:
    """Only uncommitted messages are replayed; committed ones are not."""
    stream.join_consumer_group("g4", "c4")
    pid = 2

    for i in range(6):
        stream.publish(f"k{i}", f"m{i}".encode(), partition_override=pid)

    # Commit up to offset 3
    stream.commit_offset("g4", "c4", pid, 3)

    # Poll: should only get messages 3, 4, 5
    msgs = stream.poll("g4", "c4", pid, max_records=10)
    assert len(msgs) == 3
    assert all(m.offset >= 3 for m in msgs)
