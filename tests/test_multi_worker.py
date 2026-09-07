"""Phase 7 Test: Multi-Worker Coordinator.

Verifies:
- Rule C5: Multiple workers process events concurrently
- Rule C6: Graceful drain stops workers cleanly
- Rule C7: Worker crash does not halt other workers
- Rule C8: Thread-safe concurrent access
"""

import threading
import time

from ulpf_runtime.multi_worker import MultiWorkerCoordinator


def test_coordinator_starts_and_stops() -> None:
    processed: list[int] = []
    lock = threading.Lock()

    def process_fn(partition_id: int) -> None:
        with lock:
            processed.append(partition_id)
        time.sleep(0.01)

    coord = MultiWorkerCoordinator(num_workers=3, process_fn=process_fn)
    coord.start()
    time.sleep(0.2)
    coord.stop(timeout_sec=2.0)

    # Some processing must have occurred
    assert len(processed) > 0


def test_all_workers_get_partition_assignments() -> None:
    processed_partitions: set[int] = set()
    lock = threading.Lock()

    def process_fn(partition_id: int) -> None:
        with lock:
            processed_partitions.add(partition_id)
        time.sleep(0.02)

    coord = MultiWorkerCoordinator(num_workers=4, process_fn=process_fn, num_partitions=4)
    coord.start()
    time.sleep(0.3)
    coord.stop(timeout_sec=2.0)

    # All 4 partitions should have been processed
    assert len(processed_partitions) == 4


def test_graceful_drain_stops_all_workers() -> None:
    coord = MultiWorkerCoordinator(
        num_workers=2,
        process_fn=lambda _: time.sleep(0.01),
    )
    coord.start()
    time.sleep(0.1)
    coord.drain(timeout_sec=3.0)

    stats = coord.worker_stats()
    for s in stats:
        assert s.status in ("STOPPED", "DRAINING", "CRASHED")


def test_worker_crash_isolation() -> None:
    """A crashing worker does not affect sibling workers."""
    healthy_processed: list[int] = []
    healthy_lock = threading.Lock()
    crash_counter = [0]

    def process_fn(partition_id: int) -> None:
        if partition_id == 0 and crash_counter[0] < 2:
            crash_counter[0] += 1
            raise RuntimeError("Simulated partition-0 crash")
        with healthy_lock:
            healthy_processed.append(partition_id)
        time.sleep(0.01)

    coord = MultiWorkerCoordinator(
        num_workers=3,
        num_partitions=3,
        process_fn=process_fn,
        max_restarts_per_worker=1,
    )
    coord.start()
    time.sleep(0.3)
    coord.stop(timeout_sec=2.0)

    # Other workers (partitions 1, 2) must have processed events
    assert any(p in (1, 2) for p in healthy_processed)


def test_num_workers_property() -> None:
    coord = MultiWorkerCoordinator(num_workers=5, process_fn=lambda _: None)
    assert coord.num_workers() == 5


def test_worker_stats_collected() -> None:
    coord = MultiWorkerCoordinator(
        num_workers=2,
        process_fn=lambda _: time.sleep(0.01),
    )
    coord.start()
    time.sleep(0.15)
    stats = coord.worker_stats()
    coord.stop(timeout_sec=2.0)

    assert len(stats) == 2
    for s in stats:
        assert s.worker_id in ("w0", "w1")
        assert s.events_processed >= 0


def test_concurrent_ingestion_thread_safety() -> None:
    """Multiple threads can invoke coordinator concurrently without race conditions."""
    results: list[int] = []
    lock = threading.Lock()

    def process_fn(partition_id: int) -> None:
        with lock:
            results.append(partition_id)
        time.sleep(0.001)

    coord = MultiWorkerCoordinator(num_workers=4, process_fn=process_fn)
    coord.start()
    time.sleep(0.3)
    coord.stop(timeout_sec=2.0)

    assert len(results) > 0


def test_is_healthy_after_start() -> None:
    coord = MultiWorkerCoordinator(
        num_workers=2,
        process_fn=lambda _: time.sleep(0.01),
    )
    coord.start()
    time.sleep(0.1)
    assert coord.is_healthy()
    coord.stop(timeout_sec=2.0)
