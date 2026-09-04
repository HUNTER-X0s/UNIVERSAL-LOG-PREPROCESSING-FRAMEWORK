# ADR-007: Durable Streaming Architecture

**Status:** Accepted for Phase 0

## Context

ULPF needs decoupled ingestion, retry, partitioning, backpressure, replay, and a path to horizontal scale without claiming a laptop can handle billion-event volume.

## Decision

Plan a Kafka-compatible durable transport in KRaft mode, partitioned by stable source/device semantics where useful, with stateless consumer groups and idempotent destination handling. Use a small local profile for MVP.

## Alternatives considered

- Direct synchronous API-to-parser processing.
- NATS/JetStream or Redpanda.
- Managed cloud queue.

## Pros

Replayable retained transport, consumer scaling, backpressure, mature tooling, and air-gap deployability.

## Cons

Kafka has a non-trivial operational footprint for a small demo.

## Security implications

Broker authentication/authorization, encrypted transport where deployed, topic ACLs, quota, and sensitive payload handling are required.

## Operational implications

Topics, partitions, retention, lag, consumer health, and recovery must be monitored; object evidence remains authoritative.

## Consequences

The MVP can be single-node, but code/contracts must avoid coupling correctness to single-node ordering or memory queues.
