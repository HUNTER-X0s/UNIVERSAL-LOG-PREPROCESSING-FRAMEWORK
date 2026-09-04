# ULPF Logical Data Model and Storage Strategy

**Status:** Phase 0 logical design. Store names below describe responsibilities;
the concrete technology selection remains a planned deployment decision.

## 1. Storage principles

1. Keep raw evidence, operational metadata, search projections, and analytical
   datasets separate because they have different integrity, access, retention,
   and query requirements.
2. Treat indexes and exports as rebuildable projections. Raw evidence plus
   versioned processing artifacts are the forensic source of truth.
3. Write idempotently and record delivery/retry state; do not assume a
   distributed “exactly once” guarantee without a measured, implemented design.
4. Partition by tenant/scope, source, and time where applicable, while
   preserving source sequence/event-time metadata separately.
5. Retention durations, legal holds, backups, and encryption settings must be
   policy-controlled and not invented in Phase 0.

## 2. Planned data-store responsibilities

| Logical store | Baseline candidate(s) to evaluate | Data and access pattern | Integrity / recovery model |
|---|---|---|---|
| Governance metadata | PostgreSQL or another transactional relational store | Sources, parser/mapping/schema versions, jobs, approvals, policies, audit metadata; transactional reads/writes | Referential integrity, migrations, point-in-time backup, restore validation |
| Raw evidence store | MinIO or other S3-compatible object storage | Immutable raw payloads, receipt manifests, export evidence; write-once/read-by-ID or investigation query | Object versioning/immutability where available, content digest, manifest verification, replication/backup |
| Durable transport | Kafka or equivalent durable broker | References to accepted evidence and processing state; ordered per key, consumer-group work distribution | At-least-once delivery, idempotent consumers, retention aligned to recovery/replay needs |
| Operational search | OpenSearch or equivalent | Searchable UCE projections, filters, aggregations, dashboards, alert investigation | Rebuild from canonical results/evidence; index lifecycle and snapshots |
| Analytical lake | Parquet with Iceberg-compatible tables or equivalent | High-volume normalized/export data, batch analysis, ML feature preparation | Partitioned immutable files, manifests, schema evolution, catalog/table snapshots |
| Audit/lineage projection | Relational tables plus append-only manifests; optional search projection | Trace graph traversal, admin audit, evidence verification | Append-only records, correlated identifiers, backup and hash checks |
| Local registry artifact store | Signed local filesystem/object repository | Parser packs, schema packs, mapping packs, model/enrichment packs, SBOMs | Digest/signature verification and retained published versions |

The listed candidates are an evaluation baseline, not a claim they are installed
or selected in this repository.

## 3. Metadata relational model

| Table / collection | Primary key | Principal relationships and indexes | Expected use |
|---|---|---|---|
| sources | source_id | tenant/scope, status, product/vendor hints; index on active scope/name | Resolve source identity and access scope |
| source_profiles | source_profile_id, version | source_id; compatibility/parser references; unique active profile constraint | Controlled source matching/activation |
| raw_event_receipts | raw_event_id | source_id, evidence_id, receipt_time, content_hash, idempotency/fingerprint indexes | Receipt lookup, duplicate relationships, evidence link |
| evidence_records | evidence_id | raw_event_id unique; storage_key/version, digest, retention/legal-hold indexes | Authorized evidence retrieval and verification |
| parsers / parser_versions | parser_id; parser_id + version | package digest, state, signature, compatibility indexes | Resolve approved runtime parser |
| mappings / mapping_versions | mapping_id; mapping_id + version | input/output schema versions, source/profile scope, state | Map extraction to canonical meaning |
| schemas / schema_versions | schema_id; schema_id + version | family, compatibility range, publish state | Validate UCE and adapters |
| processing_jobs | processing_job_id | raw_event_id, artifact-set digest, state, idempotency key, created_time indexes | Track stages, retries, and worker outcomes |
| normalized_event_catalog | normalized_event_id | raw_event_id, schema version, processing_job_id, quality/status, event_time indexes | Link canonical result to a search/lake projection |
| lineage_records | lineage_id | subject ID/type, parent ID/type, operation, run ID, timestamp indexes | Traverse provenance at event or field granularity |
| dlq_events | dlq_event_id | raw_event_id, stage/reason/state, last_attempt_time | Operator recovery queue |
| replay_jobs | replay_job_id | selection, pinned artifacts, requester, status, output namespace | Reproducible historical reprocessing |
| export_deliveries | delivery_id | normalized_event_id/export target/version/status, idempotency key | Decouple canonical success from target delivery |
| audit_events | audit_event_id | actor, action, object, outcome, timestamp, correlation ID | Security and governance audit |

All foreign-key-like references must be preserved in exported/rebuilt
projections even if an implementation uses a non-relational technology for
particular tables.

## 4. Raw evidence layout and retrieval

A planned evidence object key is conceptually:

    raw-events/{scope}/{YYYY}/{MM}/{DD}/{source_id}/{raw_event_id}

A corresponding EvidenceRecord holds the object version, byte length, encoding,
SHA-256 digest, receipt timestamp, source ID, retention state, and a manifest
reference. The payload is never silently redacted, reformatted, or overwritten.
If sensitive data must be hidden from a view, masking happens at read/export
time under policy; the original evidence remains protected rather than changed.

Retrieval flow: authorized user or worker → RawEvent/EvidenceRecord lookup →
policy decision and audit event → object-version read → digest verification →
content returned or referenced. A failed digest verification creates an
integrity incident, not an automatic substitution.

## 5. Stream/topic model

| Logical topic / stream | Key | Payload | Consumer intent |
|---|---|---|---|
| raw.received.v1 | source_id + receipt partition | RawEvent reference, not a lossy field subset | Detection and processing |
| processing.requested.v1 | raw_event_id + artifact-set selector | Job reference and idempotency key | Parser workers |
| processing.completed.v1 | normalized_event_id | Result reference, quality/status, lineage root | Indexing, lake/export routing |
| processing.dlq.v1 | raw_event_id | DLQEvent reference and reason | Operators, alerting, recovery |
| registry.published.v1 | artifact family/id | Approved immutable version reference | Runtime cache invalidation/controlled rollout |
| export.requested.v1 | delivery id | UCE/output reference and destination policy | Export adapters |
| audit.appended.v1 | audit event id | Audit reference | Security monitoring projection |

Partitioning must provide stable ordering where it matters, normally per source
or source-session, without claiming global event-time ordering. The event
payload includes original timestamp, receipt time, and processing time so late
or clock-skewed records remain analyzable.

## 6. Search and lake projections

| Projection | Partition/index idea | Query pattern | Source-of-truth rule |
|---|---|---|---|
| UCE operational index | Canonical major version + event-time period + scope | Event details, filtering, aggregations, source/quality/DLQ investigations | Rebuildable from canonical result catalog/evidence and artifact references |
| Field-lineage index | scope + subject ID/type | “Why does this field have this value?” | Derived from append-only lineage records |
| Evidence metadata index | source + receipt time + digest | Locate evidence after authorization | Evidence object and receipt manifest remain authoritative |
| Normalized lake table | schema family/version + event date + source/category | Batch analytics, ML preparation, cross-period analysis | Immutable table snapshots/manifests identify exact output version |
| Export manifest | target + delivery time/status | Delivery audit, retry and reconciliation | Delivery records are separate from UCE truth |

An implementation must never make an indexed document the only link to raw
evidence. Search index loss must be recoverable by re-indexing retained records.

## 7. Consistency, idempotency, and deduplication

1. **Receipt boundary:** persist evidence/object reference and receipt metadata
   before publishing a processing reference. Use an outbox or equivalent
   durable handoff so a crash cannot create invisible accepted evidence.
2. **Processing boundary:** a job uses a stable idempotency key made from raw
   event ID plus pinned parser/mapping/schema/enrichment versions. Repeated
   delivery must yield a detectable repeat, not an overwrite.
3. **Duplicate relationship:** a similarity or fingerprint match can link events
   as suspected/confirmed duplicates. It cannot delete the later raw receipt.
4. **Replay boundary:** replay results use a distinct job/result namespace and
   preserve their artifact set; consumers choose which version is active.
5. **Output boundary:** target delivery status is independent from successful
   normalization. Failed exports retry or quarantine without corrupting UCE.

## 8. Retention, backup, and recovery

Future policy must define retention classes for raw evidence, normalized
projections, DLQ, parser artifacts, audit/lineage, and analytical data.
Retention changes require authorization and audit. Planned recovery exercises
include metadata restore, object/evidence manifest verification, replay from
evidence, search re-indexing, lake table recovery, registry package recovery,
and a documented air-gap restore procedure.

## 9. Data-model acceptance tests

- Raw payload hash, object version, and receipt manifest match after storage
  and restoration.
- A canonical event resolves through its result catalog to RawEvent,
  EvidenceRecord, ProcessingJob, parser/mapping/schema versions, and lineage.
- Search loss can be recovered without loss of raw evidence or governance
  history.
- Duplicate-looking records remain individually retrievable.
- A replay with a new parser/mapping version produces a distinct result and
  preserves both histories.

