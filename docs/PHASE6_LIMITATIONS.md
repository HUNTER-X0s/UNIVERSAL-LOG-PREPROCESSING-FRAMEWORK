# ULPF Phase 6 Known Limitations & Non-Blocking Gaps

1. **Adapter Implementations**: Phase 6 provides production-grade local in-memory and filesystem storage/streaming adapters; distributed Kafka and PostgreSQL adapters follow established interface boundaries.
2. **Replay Limit**: Single historical replay jobs are bounded to 1,000 events to prevent operational denial of service.
3. **Parquet Export**: File export currently produces partitioned NDJSON/JSONL; Parquet conversion can be run as an offline batch transformation.
