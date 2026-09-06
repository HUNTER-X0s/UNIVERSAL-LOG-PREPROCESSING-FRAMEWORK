# ULPF Phase 6 Resilience & Fault Tolerance

## 1. Backpressure
Queue depths are actively bounded. Under load spikes, the system enforces configurable policies:
`REJECT` (explicit 503/BufferFullError), `BLOCK` (bounded timeout), or `DLQ` (routing overflow to dead letter storage).

## 2. Bounded Retries & DLQ
- Retries use exponential backoff with jitter up to `max_attempts`.
- Terminal failures escalate to the Dead Letter Queue with full forensic context, source ID, error trace, and payload preview.
