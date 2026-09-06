# ULPF Phase 6 Test Strategy

## Test Matrix
- **Unit & Contract Tests**: Pipeline, Stream, Backpressure, Retry, DLQ, Idempotency, Storage, Search, Delivery, Outbox, Replay, Health, Observability.
- **Integration Tests**: End-to-end pipeline, REST API contracts, role security.
- **Chaos & Failure Injection Tests**: Storage failure, downstream sink failure, poison events.
- **Regression Tests**: All 271 Phase 0–5 tests pass intact (319 tests total, 100% pass).
