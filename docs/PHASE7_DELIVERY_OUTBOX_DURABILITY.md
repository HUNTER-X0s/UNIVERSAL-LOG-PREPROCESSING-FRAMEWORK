# Phase 7 Delivery Outbox Durability Specification

## Transactional Outbox Pattern
- Delivery intents persisted in the same transaction as event processing.
- Outbox dispatcher retries with exponential backoff on sink failure.
