# ULPF Versioned Contracts

These JSON Schema contracts are the implementation boundary for ULPF Phase 0. They describe payload shape, not a deployed API. Future phases must evolve them semantically, retain compatible readers where practical, and record breaking changes through an ADR.

The `raw-event`, `parsed-event`, and `normalized-event` contracts deliberately separate evidence from observations, inferences, enrichments, and derived values. Raw event content is held by an immutable object reference rather than duplicated by every downstream payload.

## Contract set

| Contract | Purpose |
| --- | --- |
| `raw-event.v1.schema.json` | Immutable ingress evidence and capture metadata |
| `parsed-event.v1.schema.json` | Source-specific extraction with field provenance |
| `normalized-event.v1.schema.json` | ULPF Universal Canonical Event (UCE) and output-ready data |
| `source.v1.schema.json` | Source and source-profile registration |
| `parser.v1.schema.json` | Versioned parser-pack manifest |
| `mapping.v1.schema.json` | Versioned semantic mapping manifest |
| `schema.v1.schema.json` | Registered schema and compatibility policy |
| `replay-job.v1.schema.json` | Immutable replay request and result record |
| `dlq-event.v1.schema.json` | Explicit failed-event routing record |
| `lineage.v1.schema.json` | Event and field transformation lineage |
| `audit-event.v1.schema.json` | Security-sensitive, append-only audit record |

All identifiers are opaque strings so deployment-specific UUID, ULID, or content-addressable implementations can be selected without changing the contract. Timestamps use RFC 3339 UTC values at runtime.

## Cross-contract invariants

- RawEvent is the immutable evidence receipt and carries source identity,
  payload reference, raw SHA-256, and ingestion metadata.
- ParsedEvent carries the same source/raw-event identity plus source resolution
  and a versioned parser reference.
- NormalizedEvent is the ULPF Universal Canonical Event (UCE). It requires
  source/evidence identity, processing run ID, source-profile/parser/mapping/
  schema versions, field provenance, and a lineage reference.
- DLQEvent requires source/evidence/failure context, failed timestamp, replay
  eligibility, and explicit parser-selection state. A parser version is
  recorded when selected; pre-parser failure is represented explicitly instead
  of fabricated.
- Lineage requires source/evidence identity, the normalized result, pinned
  source-profile/parser/mapping/schema versions, operation and input/output
  stage records, and field-mapping evidence. The evidence raw-event ID must
  agree with the top-level raw-event ID in records that carry both.
- OCSF, OpenTelemetry Logs, ECS, JSON/NDJSON, REST/HTTP, Kafka, and Parquet are
  UCE output projections. None is an internal replacement for UCE or RawEvent.
