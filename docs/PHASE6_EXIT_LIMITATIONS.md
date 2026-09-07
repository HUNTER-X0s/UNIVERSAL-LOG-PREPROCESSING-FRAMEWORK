# ULPF Phase 6 Exit Limitations

**Date:** 2026-09-06T20:58:53.020333+00:00  
**Status:** Explicitly Documented Operational Boundaries

1. **Storage Durability Mode:** Local development and testing utilizes in-memory repositories for UCE, Semantic events, and Outbox intents. Only raw evidence is written to disk via `FilesystemRawEvidenceRepository`. For multi-node durable production, persistent database adapters (PostgreSQL, ClickHouse) must be configured.
2. **API Authentication Boundary:** The REST API authorization model is implemented for reference/development environments and expects an upstream API gateway or reverse proxy to terminate authentication and pass verified `X-Role` headers.
3. **Single-Node Execution Scope:** Phase 6 provides verified thread-safe single-node execution. Multi-node distributed consensus and cluster partition rebalancing are architecture targets for Phase 7.
4. **Historical Replay Batch Bounds:** Replay jobs are default-bounded to 1,000 events per invocation to prevent resource exhaustion on single-node runtimes.
