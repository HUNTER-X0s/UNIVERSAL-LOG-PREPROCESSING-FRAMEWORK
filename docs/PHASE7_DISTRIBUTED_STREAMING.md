# Phase 7 Distributed Streaming Specification

## Partitioning & Offset Management
- Deterministic partition routing using SHA-256 hash of `source_id`.
- Consumer groups share persistent committed offset tables.
- Offsets committed strictly AFTER downstream persistence boundary.
