# ADR-005: Immutable Raw-event Storage

**Status:** Accepted for Phase 0

## Context

Losslessness and forensic traceability require raw content to outlive parsing, indexing, projection, and replay failures.

## Decision

Persist raw bytes/text and receipt metadata first in S3-compatible object storage, with stable ID, SHA-256, byte length, encoding, retention class, and immutable reference. PostgreSQL stores governance metadata; search is a rebuildable projection.

## Alternatives considered

- Store raw payload only in a search index or relational blob column.
- Retain only parsed/normalized data.
- Use local filesystem as the long-term evidence store.

## Pros

Independent lifecycle, scalable evidence retention, reproducible replay, and portability for air-gapped deployment.

## Cons

Object-store access/backup/retention policies need careful operational management.

## Security implications

Separate evidence permissions, encryption where deployed, audit retrieval/export, integrity checks, and no UI-side mutation.

## Operational implications

Do not acknowledge a durable accepted event before evidence policy is satisfied; restore tests are mandatory.

## Consequences

No normalized record or search index is treated as the authoritative original event.
