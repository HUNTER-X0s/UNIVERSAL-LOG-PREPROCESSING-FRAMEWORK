# ULPF Phase 6 Downstream Delivery & Outbox

## 1. Isolated Delivery Sinks
Supports downstream telemetry fan-out:
- **OCSF Sink**: Dispatches OCSF v1.1.0 JSON payloads.
- **OTel Sink**: Dispatches OpenTelemetry LogRecord batches.
- **SIEM Sink**: Dispatches normalized security telemetry to external SIEM collectors.
- **Data Lake Sink**: Exports NDJSON/JSONL partitioned files.

## 2. Outbox Pattern
Delivery intents are persisted alongside canonical records. The `OutboxDispatcher` attempts delivery with bounded exponential backoff. Downstream sink failure does not abort canonical persistence or impact other sinks.
