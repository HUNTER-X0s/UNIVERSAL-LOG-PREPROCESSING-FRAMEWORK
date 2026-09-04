# ULPF Domain Model

**Status:** Phase 0 domain specification. Entity names and relationships are
contracts for future design work, not database classes or implemented APIs.

## 1. Ubiquitous language

| Term | Meaning |
|---|---|
| Source | A registered logical origin of events, such as a particular firewall feed or collector endpoint. |
| Source Profile | Versioned description of how a source is identified, authenticated, sampled, and associated with a parser/mapping. |
| RawEvent | Immutable accepted event content plus receipt metadata and evidence reference. |
| ParsedEvent | Typed extraction result from a particular RawEvent and parser version; it never replaces the raw event. |
| ULPF Universal Canonical Event (UCE) | Normalized, versioned security/operational representation carrying evidence and lineage references. |
| Parser Pack | Governed bundle containing a reusable format parser, source profiles, mappings, transforms, metadata, fixtures, and compatibility assertions. |
| Mapping | Declarative relationship between extracted vendor fields and canonical semantics. |
| Schema | Versioned contract and vocabulary for a UCE or output form. |
| Evidence | Raw content, hash, receipt manifest, access/audit history, and any verifiable chain-of-custody material. |
| Lineage | Directed record of the artifacts and steps that produced a field, event, export, or replay result. |
| Replay | Controlled reprocessing of immutable raw evidence with explicitly chosen artifact versions. |
| Quarantine | A recoverable state for accepted evidence that cannot yet take a valid downstream path. |

## 2. Bounded contexts and ownership

| Context | Owns | Primary responsibility |
|---|---|---|
| Intake and Evidence | Source receipt, RawEvent, EvidenceRecord, content hash, evidence manifest | Accept once, preserve before interpretation, and expose controlled retrieval |
| Parsing and Normalization | ParsedEvent, NormalizedEvent/UCE, ProcessingJob, quality/warnings | Deterministically interpret evidence using pinned artifact versions |
| Governance | SourceProfile, Parser/ParserVersion/Test, Mapping/MappingVersion, Schema/SchemaVersion, policy | Review, version, approve, publish, rollback, and audit configuration |
| Recovery and Provenance | DLQEvent, ReplayJob, LineageRecord, integrity verification | Explain outcomes and enable controlled repair/reprocessing |
| Enrichment and Analytics | Enrichment, Asset, ThreatIndicator, Correlation, Finding | Add clearly labelled optional context downstream of evidence interpretation |
| Identity and Audit | User, Role, Permission, Policy, AuditEvent | Enforce least privilege and create non-repudiable operational history |
| Interoperability | ExportTarget, delivery manifest, adapter version | Deliver approved forms without coupling ULPF core to a vendor |

## 3. Core entity relationships

~~~mermaid
erDiagram
  SOURCE ||--o{ SOURCE_PROFILE : has
  SOURCE ||--o{ RAW_EVENT : emits
  RAW_EVENT ||--|| EVIDENCE_RECORD : recorded_as
  RAW_EVENT ||--o{ PARSED_EVENT : produces
  PARSER ||--o{ PARSER_VERSION : has
  PARSER_VERSION ||--o{ PARSER_TEST : verified_by
  PARSER_VERSION ||--o{ PARSED_EVENT : processes
  PARSED_EVENT ||--o{ NORMALIZED_EVENT : maps_to
  MAPPING ||--o{ MAPPING_VERSION : has
  MAPPING_VERSION ||--o{ NORMALIZED_EVENT : applied_to
  SCHEMA ||--o{ SCHEMA_VERSION : has
  SCHEMA_VERSION ||--o{ NORMALIZED_EVENT : validates
  NORMALIZED_EVENT ||--o{ LINEAGE_RECORD : explained_by
  EVIDENCE_RECORD ||--o{ LINEAGE_RECORD : anchors
  RAW_EVENT ||--o{ DLQ_EVENT : may_create
  REPLAY_JOB ||--o{ PROCESSING_JOB : schedules
  PROCESSING_JOB ||--o{ NORMALIZED_EVENT : produces
  USER ||--o{ AUDIT_EVENT : performs
  POLICY ||--o{ AUDIT_EVENT : governs
~~~

The diagram intentionally models a one-to-many path from a raw event to
processed outputs. A replay or upgraded mapping can produce an additional,
version-distinct UCE record without overwriting prior processing history.

## 4. Entity catalogue

### Intake, evidence, and processing

| Entity | Stable identifier and essential attributes | Lifecycle / owner |
|---|---|---|
| Source | source_id; tenant/scope; display name; device/vendor/product hints; transport; status | Created and activated by authorized administration; owned by Governance |
| SourceProfile | source_profile_id + version; matching rules; expected format; profile state; compatibility | Draft → tested → approved → active/retired; owned by Governance |
| RawEvent | raw_event_id; source_id; receipt time; original-time candidate; payload reference; content hash; byte length; encoding; receipt state | Created only after durable acceptance; immutable; owned by Intake and Evidence |
| EvidenceRecord | evidence_id; raw_event_id; storage locator/version; hash algorithm/value; manifest; retention/legal-hold state | Append-only evidence metadata; owned by Intake and Evidence |
| ParsedEvent | parsed_event_id; raw_event_id; parser version; extracted field set; extraction warnings; parse status | Produced by a ProcessingJob; historical and versioned; owned by Parsing |
| ProcessingJob | processing_job_id; input/raw reference; artifact-version set; run state; timings; worker identity; idempotency key | Requested → running → succeeded/failed/quarantined; owned by Processing |
| NormalizedEvent | normalized_event_id; raw_event_id; canonical schema version; selected assertions; quality; lineage root; output status | Immutable result of a specific run; superseded only by reference; owned by Processing |
| DLQEvent | dlq_event_id; raw_event_id; job/run; stage; reason code; retry count; operator disposition | Open → retried/resolved/accepted-risk; never deletes evidence; owned by Recovery |
| ReplayJob | replay_job_id; evidence selection; pinned versions; requested-by; purpose; compare target; status | Draft → approved → running → completed/failed; owned by Recovery |

### Governance, schema, and parser assets

| Entity | Stable identifier and essential attributes | Lifecycle / owner |
|---|---|---|
| Parser | parser_id; name; supported formats; maintainer; trust tier | Long-lived logical product; owned by Governance |
| ParserVersion | parser_id + semantic version; package digest; format capability; resource limits; signature; compatibility statement | Draft → test → approved → published → deprecated/revoked; immutable once published |
| ParserTest | parser_test_id; fixture corpus digest; expected result contract; result; runtime profile | Tied to a parser/mapping/schema version; append-only result history |
| Mapping | mapping_id; source/format scope; canonical target family; owner | Logical mapping family; owned by Governance |
| MappingVersion | mapping_id + semantic version; rules/transform set; input/output schemas; digest; approval | Immutable published version; rollback selects an older approved version |
| Schema | schema_id; domain; owner; compatibility policy | Logical contract family; owned by Schema Governance |
| SchemaVersion | schema_id + version; field definitions; vocabulary; validation rules; deprecation policy; digest | Draft → reviewed → published → deprecated; immutable after publish |
| Enrichment | enrichment_id + version; provider/pack; inputs; outputs; freshness; status | Optional, fail-open enrichment rule; owned by Analytics/Enrichment |

### Investigation, analytics, and identity

| Entity | Stable identifier and essential attributes | Lifecycle / owner |
|---|---|---|
| LineageRecord | lineage_id; subject type/id; parent artifact; operation; actor/run; timestamp; evidence locators | Append-only transformation edge; owned by Recovery and Provenance |
| AuditEvent | audit_event_id; actor; action; object; authorization decision; time; request correlation; outcome | Append-only operational/security record; owned by Identity and Audit |
| Asset | asset_id; identifiers; network zones; criticality; source and freshness | Enrichment data with provenance; never rewrites observation |
| ThreatIndicator | indicator_id; type/value; local feed/version; confidence; validity window | Optional enrichment reference; controlled import and expiry |
| Correlation | correlation_id; query/rule version; input event refs; result status | Downstream analytic product, not an alteration of UCE |
| Finding | finding_id; correlation/source refs; severity; disposition | Analytic outcome owned by downstream cyber-analytics scope |
| User / Role / Permission / Policy | stable principal/authorization IDs; scope; effect; expiry; version | Identity administration, least privilege, audited changes |

## 5. Aggregate boundaries

- **Evidence aggregate:** RawEvent and EvidenceRecord are created together
  conceptually and are never updated to change raw content. Operational status
  is additive metadata.
- **Processing aggregate:** ProcessingJob references immutable input and
  artifact versions, then produces ParsedEvent, NormalizedEvent, and/or
  DLQEvent records. It cannot alter the Evidence aggregate.
- **Parser-pack aggregate:** ParserVersion, compatible SourceProfiles,
  MappingVersions, SchemaVersions, fixtures, and approval report travel as a
  compatible release set.
- **Replay aggregate:** ReplayJob identifies selection, version set, outcome,
  comparison results, and audit events. It creates new results rather than
  modifying old results.
- **Access aggregate:** Policy decisions govern operations; the resulting
  AuditEvent is retained even if the requested operation is denied.

## 6. Important lifecycle rules

~~~mermaid
stateDiagram-v2
  [*] --> Draft
  Draft --> Tested
  Tested --> Approved
  Tested --> Rejected
  Approved --> Published
  Published --> Deprecated
  Published --> Revoked
  Deprecated --> Retired
  Rejected --> Draft
~~~

The state diagram applies to publishable governance artifacts such as
ParserVersion, MappingVersion, and SchemaVersion. A revoked parser is blocked
for future activation, but records that already cite it remain explainable and
replayable under explicit authorization.

## 7. Cross-domain rules

1. Identity, schema, parser, mapping, and source version references must be
   resolvable for every completed processing run.
2. A RawEvent can have many ParsedEvents or NormalizedEvents, but an individual
   result has one declared input raw-event ID and one pinned artifact set.
3. An enrichment, inference, correlation, or finding is an additional relation,
   never a replacement for raw or observed values.
4. Deletion/retention actions are governed and audited; data retention is a
   policy decision, not an error-handling mechanism.
5. An entity identifier must remain stable across exports. Derived output IDs
   must retain the originating UCE and RawEvent references.
