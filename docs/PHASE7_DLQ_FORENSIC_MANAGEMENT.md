# Phase 7 Durable DLQ & Forensic Management

## Poison-Pill Isolation
- Unparseable or corrupt events routed to durable DLQ without stalling stream.
- Retains original error message, stack trace, and raw evidence reference.
