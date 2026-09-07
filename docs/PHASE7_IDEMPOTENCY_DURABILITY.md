# Phase 7 Durable Idempotency Specification

## Deduplication Invariant
- Key generated from `(source_id, raw_sha256)`.
- Unique database constraints prevent duplicate insertions across worker restarts.
