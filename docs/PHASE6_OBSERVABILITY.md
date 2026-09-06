# ULPF Phase 6 Observability & Telemetry

## 1. Structured Metrics
Counters, gauges, and latency histograms track end-to-end performance:
- `events_total`, `events_normalized`, `events_semantic_success`, `events_persisted`, `events_dlq`, `events_rejected`.
- Quantiles: p50, p95, p99 latency tracking for pipeline stages.
- Bounded label dimensions prevent metric cardinality explosion.

## 2. Log & Secret Redaction
- `StructuredJsonFormatter` outputs structured JSON logs with correlation IDs.
- Passwords, bearer tokens, API keys, and credentials are automatically redacted before emitting log lines.
