# ADR-008: Storage by Data Purpose

**Status:** Accepted for Phase 0

## Context

Evidence, governance, search, and analytics impose different consistency, query, retention, and scale requirements.

## Decision

Use PostgreSQL for governance metadata and audit indexes; MinIO/S3-compatible storage for raw evidence; OpenSearch for operational search projections; partitioned Parquet with an Iceberg-compatible strategy for the data lake; and Kafka for transport rather than durable evidence.

## Alternatives considered

- One relational database for all data.
- Search engine as system of record.
- Object store only.

## Pros

Each store serves its workload; projections can be rebuilt from evidence and versioned processing.

## Cons

More operational components and consistency boundaries require deliberate reconciliation/runbooks.

## Security implications

Per-store least privilege, encryption/access policy, retention, backup, and audit are required; sensitive evidence is not broadly indexed.

## Operational implications

Destination failures use retries/outbox/DLQ behavior; backups/restores cover each store and evidence integrity.

## Consequences

No component is assumed to be globally transactional; lineage and idempotency make state reconciliation explicit.
