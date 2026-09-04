# ULPF System Architecture

**Status:** Planned logical architecture for Phase 0. This document describes
responsibilities and interfaces, not deployed services.

## 1. System context

~~~mermaid
flowchart TB
  Dev[Perimeter devices and collectors] -->|events| ULPF
  Admin[Administrator / parser author] -->|governed configuration| ULPF
  Analyst[Security analyst / auditor] -->|search, trace, replay requests| ULPF
  ULPF[ULPF]
  ULPF -->|normalized, versioned records| SIEM[SIEM or security platform]
  ULPF -->|columnar datasets and manifests| Lake[Data lake]
  ULPF -->|searchable operational events| Search[Investigation/search]
  ULPF -->|canonical data| ML[Analytics and ML]
  Bundle[Verified offline update bundle] -->|controlled import| ULPF
~~~

ULPF owns preprocessing, evidence preservation, normalization governance, and
export. Downstream systems own detection response, long-term analytics, or
visualization beyond the ULPF operational views.

## 2. Logical components

| Area | Planned responsibilities | Does not own |
|---|---|---|
| Edge collection and intake | Receive supported transports/files, assign source context, apply size/rate protections, acknowledge durable acceptance | Semantic interpretation |
| Raw evidence service | Persist raw content, receipt metadata, content hash, and stable raw-event identifier | Search-oriented reshaping of evidence |
| Durable transport | Decouple producers and workers; retain delivery state, retries, partition key, and backpressure | Immutable evidence source of truth |
| Format/source identification | Identify format, source profile candidates, and uncertainty | Unapproved parser changes |
| Parser and extraction | Convert raw representation into typed extracted fields and preserve extraction errors | External schema lock-in |
| Mapping and normalization | Map fields and vocabularies into UCE, capture unmapped data and assertion origin | Altering raw evidence |
| Validation and quality | Check contract, types, required conditions, semantic consistency, and quality signals | Silent rejection of evidence |
| Lineage/integrity | Record transformation graph, artifacts, hashes, actor/run identifiers, and audit links | Business analytics |
| Registry/control plane | Govern source profiles, parser packs, mapping/schema versions, fixtures, approvals, and rollback state | Per-event mutable behavior |
| DLQ/quarantine and replay | Preserve failures, classify reasons, schedule repair or controlled reprocessing | Deleting original event history |
| Output adapters | Deliver versioned UCE/OCSF/OTel/ECS-compatible forms to approved targets | Vendor-specific logic in core processing |
| Operational API/UI | Present source, parser, event, lineage, quality, replay, and audit workflows | Direct database access or bypass of authorization |

## 3. Detailed processing pipeline

~~~mermaid
flowchart LR
  A[Receive event] --> B[Validate transport envelope and limits]
  B --> C[Persist RawEvent and SHA-256 digest]
  C --> D[Publish durable processing reference]
  D --> E[Detect format and identify source profile]
  E --> F[Choose approved parser pack version]
  F --> G[Parse and extract typed fields]
  G --> H[Map semantics to UCE]
  H --> I[Validate UCE and score quality]
  I --> J[Attach lineage, integrity, and processing metadata]
  J --> K[Persist/query-route normalized representation]
  K --> L[Export through explicit adapter]

  B -->|cannot accept| R[Reject with receipt-level audit; sender retry policy]
  E -->|unknown/ambiguous| Q[Quarantine or reduced-confidence route]
  F -->|parse failure| Q
  H -->|mapping failure| Q
  I -->|validation failure| Q
  Q --> M[Reason code, alert, review, repair, replay]
  C -. raw reference retained .-> Q
~~~

An event becomes a processing failure only after its raw evidence is accepted
and retained. A transport-level rejection is separately audited because ULPF
cannot claim preservation of content it never successfully received.

## 4. Known, unknown, and failed event paths

| Condition | Planned behavior | Evidence and audit result |
|---|---|---|
| Known source and compatible parser | Process with pinned source/profile/parser/mapping/schema versions | UCE references RawEvent and a complete processing run |
| Known format, unknown source | Preserve, assign an uncertainty state, and make it available to the onboarding workflow | Candidate profile and analysis never replace raw content |
| Unsupported or malformed syntax | Preserve raw event; create a DLQ/quarantine record with stage and reason | Repair/replay remains possible |
| Schema or mapping validation warning | Emit UCE with explicit warning and quality score if the contract allows it | Warning is queryable and traceable |
| Irrecoverable processing failure | Stop downstream routing, retain raw evidence and failure metadata | Operator can inspect, fix configuration, and replay |
| Duplicate-looking event | Preserve raw receipt; link fingerprint/duplicate relationship rather than erase it | Deduplication affects downstream views, not evidence retention |

## 5. Control-plane lifecycle

~~~mermaid
sequenceDiagram
  participant Author as Parser author
  participant Registry as Local registry
  participant Test as Fixture/contract validation
  participant Approver as Authorized reviewer
  participant Runtime as Processing runtime

  Author->>Registry: Submit versioned parser pack and metadata
  Registry->>Test: Run fixtures, compatibility and safety checks
  Test-->>Registry: Results and immutable report
  Registry->>Approver: Request review
  Approver->>Registry: Approve, reject, or request change
  Registry->>Runtime: Publish approved immutable version reference
  Runtime->>Runtime: Pin version for each processing run
~~~

No runtime worker should load mutable, unreviewed configuration from a user
workspace. Rollback is a governed selection of a previously approved version,
not a rewrite of historical records.

## 6. Trust and failure boundaries

1. **Untrusted input boundary:** Logs, uploads, collectors, and sample files
   are treated as data. Size limits, parser timeouts, safe parsing, content
   handling, and least-privilege workers are required.
2. **Evidence boundary:** Raw evidence write/read permissions are stricter than
   ordinary normalized-event search. Hashes prove later retrieval matches the
   accepted content.
3. **Control boundary:** Only authorized roles can publish/activate source,
   parser, mapping, schema, or bundle versions.
4. **Output boundary:** An export adapter can fail without corrupting the
   canonical record. Delivery status is tracked independently.
5. **Air-gap boundary:** Internet access is not required by the runtime.
   Updates arrive as verified local bundles and remain auditable.

## 7. Operational properties to implement later

| Property | Planned mechanism |
|---|---|
| Idempotency | Stable receipt/event identifiers, fingerprints, delivery state, and explicit duplicate relationships |
| Ordering | Preserve source sequence and event time where available; use processing time separately; do not rewrite late events |
| Backpressure | Bounded intake, durable queueing, quotas, worker scaling, and sender-visible overload behavior |
| Recovery | Restart from durable references; retry idempotent work; quarantine exhausted failures; replay from evidence |
| Observability | Correlated event/run identifiers across metrics, logs, traces, quality counters, DLQ rate, and downstream health |
| Privacy/security | RBAC, field/evidence access controls, encrypted channels/storage where deployed, and audited exports |

## 8. Definition of architectural completion for a component

A future component is ready to implement only when it has a named owner, a
versioned contract, a data owner/store, authorization boundary, failure mode,
observable signals, test plan, and deployment assumptions. This avoids
building a visually complete pipeline whose evidence, error, and governance
paths are undefined.

