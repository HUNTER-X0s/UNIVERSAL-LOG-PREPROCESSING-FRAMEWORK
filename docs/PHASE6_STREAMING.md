# ULPF Phase 6 Streaming & Buffering

## 1. Streaming Port & Abstraction
The streaming layer is decoupled from concrete message brokers via `EventStream`, `EventPublisher`, and `EventConsumer` interfaces.

## 2. Partitioning & Ordering Guarantees
- **Partition Key**: Computed deterministically via SHA-256 hash of `source_id` or `key`.
- **Per-Partition Ordering**: Guaranteed sequential ordering within each partition; global ordering across partitions is intentionally not claimed.
- **Bounded Buffering**: Partitions enforce `max_partition_capacity`. When capacity is reached, backpressure is exerted via `REJECT` (`BufferFullError`), `BLOCK` with bounded timeout, or `DLQ` routing.
