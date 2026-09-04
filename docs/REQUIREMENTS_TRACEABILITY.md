# NTRO Requirements Traceability Matrix

**Status:** Phase 0 planned traceability matrix. “Planned proof” identifies
future test/demo evidence; it is not a claim that a capability exists today.

## Traceability rule

Every requirement below has an architectural home, an implementation phase,
verification work, and a demo-proof concept. Any future change must preserve
the complete chain:

~~~mermaid
flowchart LR
  R[NTRO requirement] --> A[Architecture and ADR]
  A --> P[Implementation phase and contract]
  P --> T[Test and measurement]
  T --> D[Demo evidence]
  D --> R
~~~

## Mandatory requirements matrix

| ID | Exact requirement | Interpretation and architectural response | Responsible components / data / interface | Security implication | Phase | Planned test and demo evidence | Acceptance criterion |
|---|---|---|---|---|---|---|---|
| ULPF-REQ-001 | Preserve complete raw event data without information loss. | Persist raw content before processing with a stable ID, digest, ingest metadata, and immutable reference; no normalizer may replace it. | Intake, Raw Evidence, Lineage; RawEvent; RawEvent and evidence retrieval contracts. | Tamper detection, least-privilege evidence access, audit retrieval/export. | 2, 8, 9, 10 | Integrity/round-trip test; demo opens raw text and verifies linked digest. | Every accepted event has retrievable raw evidence whose hash matches its receipt record. |
| ULPF-REQ-002 | Extract and parse source-specific attributes. | Separate format parsers from source profiles, mappings, and tests so extraction is source-aware without hardcoding the core. | Identifier, Parser Engine, Parser Registry; ParsedEvent; parser/source contracts. | Sandboxed/resource-limited parsing; signed/approved packs. | 3, 10, 15 | Fixture tests across disclosed formats; demo shows extracted source fields. | An approved parser emits typed extraction results and preserves unparsed content/errors. |
| ULPF-REQ-003 | Normalize fields into a common event taxonomy. | Map extracted semantics into UCE with versioned schemas, controlled vocabularies, validators, and external adapters. | Mapping/Normalization, Schema Registry; NormalizedEvent/UCE; mapping and schema contracts. | Prevent semantic spoofing; clearly label assertion origin. | 4, 15 | Cross-format equivalence and schema-contract tests; demo shows a unified event view. | Equivalent disclosed security concepts occupy documented canonical fields with mapping provenance. |
| ULPF-REQ-004 | Maintain traceability between normalized and original events. | Record event and field-level lineage from RawEvent through parser, mapping, validation, enrichment, output, and run identifiers. | Lineage/Integrity; LineageRecord; trace and event-detail contracts. | Chain of custody, auditability, access control. | 9, 10, 15 | Lineage traversal and tamper-detection tests; demo traces one field to raw evidence. | A normalized event and asserted field resolve to raw reference and versioned transformations. |
| ULPF-REQ-005 | Provide plug-and-play onboarding of new log sources. | Govern configuration-driven source profiles, parser packs, mappings, fixtures, approval, publication, rollback, and drift signals. | Source/Parser/Mapping registries; SourceProfile, ParserVersion, MappingVersion; onboarding contracts. | Only authorized, verified artifacts can activate; AI suggestions cannot publish. | 3, 4, 6, 10 | Onboarding fixture/rollback tests; demo reviews a new source configuration. | A new declared source can be onboarded by approved configuration when its format parser already exists. |
| ULPF-REQ-006 | Provide unified visibility across enterprise environments. | Publish searchable UCE records with source, quality, warning, and lineage context while retaining tenant/environment boundaries. | Operational Search/API/UI; NormalizedEvent, Source, Quality, AuditEvent; query contracts. | RBAC, raw-evidence permissions, field/data-scope controls. | 8, 11, 12 | Authorization and cross-source query tests; demo filters several source types in one view. | Authorized users can query normalized records across configured sources with provenance context. |
| ULPF-REQ-007 | Provide efficient SIEM and Data Lake integration. | Use decoupled versioned output adapters for OCSF/NDJSON/HTTP/streaming and columnar lake delivery; do not embed a vendor product in core. | Output adapters, routing, lake exporter; export manifest and delivery contracts. | Authenticated destinations, export authorization, delivery audit. | 8, 14, 15 | Contract/export conformance tests; demo shows one normalized event in two output forms. | An adapter can emit documented versioned records without changing core parser/normalizer logic. |
| ULPF-REQ-008 | Produce AI/ML-ready security and operational analytics data. | Provide typed, timestamped, quality-scored, provenance-aware canonical records plus explicit missing/unknown states. | Normalization, Quality, Lineage, Lake outputs; UCE and quality contracts. | Prevent inference/enrichment from masquerading as observation; protect sensitive fields. | 4, 8, 13, 15 | Schema completeness/type tests; demo exposes quality and assertion origin. | Consumers can distinguish observed, inferred, enriched, and derived values in a versioned record. |
| ULPF-REQ-009 | Reduce parser development effort. | Reuse format parsers and express vendor variation through profiles, declarative mappings, transformations, fixtures, and registry workflow. | Parser/Mapping registries; parser-pack contract. | Validate and authorize configuration; protect against regex/transform abuse. | 3, 4, 6, 15 | Regression suite reuse test; demo shows mapping-driven onboarding. | A compatible new vendor source requires no core-engine code change. |
| ULPF-REQ-010 | Be deployable in an air-gapped network. | Require local runtime dependencies, local registries/storage/identity, offline administration, and verified import bundles. | Deployment, registry, bundle importer, local model/enrichment optional components. | Signed manifests, offline verification, supply-chain inventory, no SaaS control-plane dependency. | 1, 10, 16 | Network-denied runtime and bundle-verification tests; demo explains local artifact path. | Core intake-to-output path functions without Internet connectivity. |
| ULPF-REQ-011 | May be packaged in a container for platform independence. | Package planned components with reproducible images/configuration; separate state from containers and document offline image transfer. | Deployment packaging; configuration and image manifests. | Pinned dependencies, image scanning/signing, secrets external to images. | 1, 10, 16 | Build/run and offline-import checks; demo starts planned stack from approved artifacts. | A documented container deployment can run the supported MVP topology without platform-specific code. |
| ULPF-REQ-012 | Convert perimeter logs regardless of source, format, vendor, or technology. | Scope the framework to perimeter telemetry while designing a format/source abstraction for Syslog, JSON, XML, CSV, CEF, LEEF, key=value, and extensible formats. | Intake, identifier, parser packs, source profiles; RawEvent/ParsedEvent contracts. | Treat every input as hostile/untrusted; enforce boundaries before parsing. | 2, 3, 4 | Multi-format corpus test; demo submits several disclosed log representations. | Supported formats are declared, test-backed, and extensible without vendor dependency in core. |
| ULPF-REQ-013 | Be scalable, extensible, vendor-agnostic, Big Data suitable, and intended for billions of events/day. | Design horizontally scalable partitions, stateless workers, durable backpressure, tiered storage, versioned contracts, and pluggable infrastructure. | Transport, workers, stores, registries, deployment contracts. | Tenant/source quotas, resource isolation, auditability under load. | 7, 8, 10, 15, 16 | Load/failure plan using measured hardware only; demo reports no invented throughput. | Architecture documents partitioning, recovery, and scale assumptions; measured limits are separately reported. |
| ULPF-REQ-014 | Ingest, parse, normalize, and standardize logs/events. | Establish the end-to-end pipeline with explicit gates, state transitions, and failure/replay paths. | Intake through output routing; RawEvent, ParsedEvent, NormalizedEvent, DLQEvent. | Authentication, input validation, explicit failure records. | 2, 3, 4, 7, 15 | End-to-end fixture test; demo walks a single event across stages. | An accepted event either reaches a valid target state or has a traceable failure/quarantine record. |
| ULPF-REQ-015 | Enable consistent analytics, correlation, visualization, threat hunting, anomaly detection, and machine learning. | Make normalized, queryable, quality-scored outputs available to downstream capabilities; do not imply ULPF is a full SIEM. | Search/API/export adapters; UCE/OCSF/OTel/ECS output contracts. | Authorization, minimization, audit of queries/exports. | 12, 13, 14, 15 | Query/export contract tests; demo shows unified investigation-ready records. | Downstream tools receive documented canonical/output representations with context required for analysis. |

## Coverage check

| Check | Phase 0 result |
|---|---|
| Mandatory expected-solution requirements A–K mapped | Yes: ULPF-REQ-001 through ULPF-REQ-011 |
| Current perimeter-source scope mapped | Yes: ULPF-REQ-012 and ULPF-REQ-014 |
| Scale and analytics intent mapped | Yes: ULPF-REQ-013 and ULPF-REQ-015 |
| Requirement without architecture, phase, test, or demo evidence | None in this planned matrix |
| Completion claim | Not yet; Phase 0 defines the proof obligations for future work |

## Change-control rule

A pull request, parser-pack publication, schema change, or architecture change
is incomplete if it changes a requirement's response without updating this
matrix, its linked contract/ADR, planned verification, and demo proof.

## Final-audit requirement chain

This crosswalk makes the required chain explicit: NTRO requirement to
architectural component to data contract to implementation phase to test to
demo evidence. It supplements, rather than replaces, the detailed matrix
above.

| Requirement | Architectural component | Data contract(s) | Phase(s) | Planned test | Planned demo evidence |
| --- | --- | --- | --- | --- | --- |
| REQ-001 raw preservation/losslessness | Evidence Architecture, intake, immutable object store | RawEvent, NormalizedEvent evidence, Lineage | 2, 8, 9, 10 | byte round-trip, hash/manifest, restore/tamper test | raw evidence plus digest/manifest verification |
| REQ-002 parsing and source-specific extraction | format detector, trusted parser adapter, parser registry | RawEvent, ParsedEvent, Parser | 3, 10, 15 | multi-format fixture, parser regression, fuzz/limit tests | parsed source fields beside raw event |
| REQ-003 common taxonomy and normalization | mapping engine, UCE schema, validation | Mapping, Schema, NormalizedEvent/UCE | 4, 15 | cross-format equivalence and schema contract tests | unified UCE event view |
| REQ-004 traceability | lineage service, evidence manifest, trace API/UI | Lineage, NormalizedEvent/UCE, AuditEvent | 9, 10, 15 | backward field trace and tamper detection | raw-to-field trace with versions |
| REQ-005 plug-and-play onboarding | source profile, parser/mapping registry, approval workflow | Source, Parser, Mapping, Schema | 3, 4, 6, 10 | onboarding, approval, rollback fixture test | sample-to-approved source configuration |
| REQ-006 unified visibility | operational search, API, console | NormalizedEvent/UCE, Source, AuditEvent | 8, 11, 12 | authorization and cross-source search test | one filtered view across source types |
| REQ-007 SIEM/data-lake integration | versioned output adapters and lake writer | NormalizedEvent/UCE projection metadata, Lineage, AuditEvent | 8, 14, 15 | adapter conformance and delivery retry test | one event shown in UCE and OCSF/Parquet form |
| REQ-008 AI/ML-ready data | typed UCE, quality, provenance, lake projection | NormalizedEvent/UCE, Lineage, Schema | 4, 8, 13, 15 | type/completeness/origin tests | quality and origin visible for an event |
| REQ-009 reduced parser effort | reusable format adapters plus declarative packs/mappings | Parser, Mapping, Source | 3, 4, 6, 15 | compatible-source onboarding without core code change | mapping-driven new source |
| REQ-010 air-gapped deployment | local runtime, registries, signed bundle importer | Parser, Mapping, Schema, AuditEvent | 1, 10, 16 | network-denied core run and invalid-bundle test | offline bundle/status view |
| REQ-011 container/platform independence | OCI packaging and deployment profiles | deployment/bundle manifests plus contract inventory | 1, 10, 16 | clean-host build/run and offline import test | local containerized topology |
| REQ-012 universal perimeter scope | source/format/parser/profile separation | RawEvent, ParsedEvent, Source, Parser | 2, 3, 4 | declared multi-format corpus test | heterogeneous perimeter samples |
| REQ-013 scale/extensibility/vendor neutrality/big-data path | partitions, workers, backpressure, tiered stores, adapter boundaries | RawEvent references, NormalizedEvent/UCE, DLQEvent, ReplayJob | 7, 8, 10, 15, 16 | measured load/failure/recovery plan | measured scope only; no laptop-scale claim |
| REQ-014 ingest/parse/normalize/standardize lifecycle | end-to-end processing and explicit failure routing | RawEvent, ParsedEvent, NormalizedEvent/UCE, DLQEvent | 2, 3, 4, 7, 15 | end-to-end fixture including failure branch | single event through each lifecycle stage |
| REQ-015 analytics/hunting/visualization/ML enablement | search, focused UI, output adapters, quality/lineage overlays | NormalizedEvent/UCE, Lineage, output projection metadata | 12, 13, 14, 15 | query/export contract test | investigation-ready unified event |

### Audit conclusion

All mandatory NTRO capabilities listed in the final architecture audit are
covered by at least one row above. The architecture distinguishes planned
proof from completed implementation; future phases must not convert this
traceability into an unsupported deployment, vendor-support, or benchmark
claim.

## Phase 1 foundation evidence update

Phase 1 adds repository and validation evidence only. It does not complete a product requirement whose planned phase is later.

| Requirement | Phase 1 evidence | Status after Phase 1 |
| --- | --- | --- |
| ULPF-REQ-010 air-gapped deployment | runtime shell has no mandatory cloud API or startup fetch; local configuration, dependency classification, and offline-capable container foundation are documented | FOUNDATION READY; end-to-end offline proof pending |
| ULPF-REQ-011 container packaging | OCI API Dockerfile, non-root/read-only Compose foundation, reproducible build task, and Python 3.12 CI definition exist | FOUNDATION READY; container build/run proof pending |
| ULPF-REQ-013 scalability/extensibility | contract/domain/application boundaries, worker shell, dependency-direction checks, and no speculative microservices are implemented | FOUNDATION READY; scale validation pending |
| All other ULPF requirements | frozen contracts, ADRs, architecture, and contract validation are preserved | ARCHITECTED or PLANNED; no completion claim |

No Phase 1 evidence changes the planned implementation phase of parsing, normalization, evidence retention, streaming, data stores, interoperability, analytics, AI, onboarding, replay, or frontend workflows.
