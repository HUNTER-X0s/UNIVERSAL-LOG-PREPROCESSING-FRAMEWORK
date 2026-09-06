"""Tests for ULPF Phase 6 streaming abstraction."""

import unittest

from ulpf_runtime.errors import BufferFullError
from ulpf_streaming.memory import MemoryEventStream


class TestStreamAdapter(unittest.TestCase):
    def test_partitioning_and_publish_poll(self) -> None:
        stream = MemoryEventStream(num_partitions=4, max_partition_capacity=50)

        # Publish 10 messages with distinct keys
        published = []
        for i in range(10):
            msg = stream.publish(
                topic="telemetry",
                key=f"device-{i}",
                payload=f"log-{i}".encode(),
                headers={"source_id": f"device-{i}"},
            )
            published.append(msg)
            self.assertGreaterEqual(msg.partition, 0)
            self.assertLess(msg.partition, 4)

        # Poll messages
        polled = stream.poll(timeout_sec=0.2, max_records=20)
        self.assertEqual(len(polled), 10)

        # Ack messages
        for msg in polled:
            stream.ack(msg)

        stream.close()

    def test_nack_and_requeue(self) -> None:
        stream = MemoryEventStream(num_partitions=1, max_partition_capacity=10)
        stream.publish("test", key="k1", payload=b"payload-1")

        records = stream.poll(timeout_sec=0.2, max_records=1)
        self.assertEqual(len(records), 1)

        # Nack with requeue
        stream.nack(records[0], requeue=True)

        # Re-poll should receive the message again
        records_again = stream.poll(timeout_sec=0.2, max_records=1)
        self.assertEqual(len(records_again), 1)
        self.assertEqual(records_again[0].message_id, records[0].message_id)

        stream.ack(records_again[0])
        stream.close()

    def test_partition_capacity_backpressure(self) -> None:
        stream = MemoryEventStream(num_partitions=1, max_partition_capacity=2)
        stream.publish("test", key="k1", payload=b"1")
        stream.publish("test", key="k1", payload=b"2")

        # 3rd message exceeds capacity of partition 0
        with self.assertRaises(BufferFullError):
            stream.publish("test", key="k1", payload=b"3")

        stream.close()

    def test_seek_and_replay(self) -> None:
        stream = MemoryEventStream(num_partitions=1, max_partition_capacity=10)
        for i in range(5):
            stream.publish("test", key="k1", payload=f"item-{i}".encode())

        polled = stream.poll(timeout_sec=0.2, max_records=5)
        self.assertEqual(len(polled), 5)

        # Seek back to offset 0
        stream.seek(partition=0, offset=0)
        re_polled = stream.poll(timeout_sec=0.2, max_records=5)
        self.assertEqual(len(re_polled), 5)
        self.assertEqual(re_polled[0].payload, b"item-0")

        stream.close()


if __name__ == "__main__":
    unittest.main()
