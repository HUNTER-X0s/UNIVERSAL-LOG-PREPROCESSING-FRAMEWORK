# Phase 7 Durable Storage Architecture

## Relational Persistence Engine
- Replaces ephemeral in-memory storage with durable relational persistence (SQLite WAL / PostgreSQL).
- Canonical UCE records are strictly write-once with unique constraints on event ID.
- Outbox intents stored transactionally alongside event updates.
