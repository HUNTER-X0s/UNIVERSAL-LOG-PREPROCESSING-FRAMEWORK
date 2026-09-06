# ULPF Phase 6 Runtime Processing Model

## 1. Lifecycle State Machine
Every telemetry event progresses through an explicit, auditable lifecycle:
`RECEIVED -> CAPTURED -> BUFFERED -> PROCESSING -> NORMALIZED -> SEMANTIC_READY -> PERSISTED -> DELIVERED -> ACKNOWLEDGED`
Failure paths transition to `FAILED` and escalate to `DLQ`. Historical replays enter at `REPLAYED`.

## 2. Durability & Acknowledgment Semantics
- **No False Acknowledgment**: An event is never marked `ACKNOWLEDGED` until raw evidence and canonical UCE are durably persisted.
- **Poison Event Isolation**: Malformed payloads terminate into the Dead Letter Queue without stalling consumer streams.
- **Worker Host**: Supports `STARTING`, `RUNNING`, `PAUSED`, `DRAINING`, `STOPPED` with signal handling for graceful teardown.
