# Phase 0 Final Architecture Audit

**Project:** ULPF - Universal Log Pre-processing Framework  
**Problem statement:** SIH26156 / NTRO  
**Audit date:** 2026-09-04  
**Audit outcome:** PASS WITH DOCUMENTED RISKS  
**Freeze state:** ARCHITECTURE AUDITED AND FROZEN

## Audit boundary

This audit reviewed the complete Phase 0 documentation set, ADR inventory, and
JSON Schema contract inventory. It did not implement, deploy, benchmark, or
certify a product. Claims in this audit are architecture and documentation
claims only.

## Corrections made during the final audit

1. Resolved the ADR-016 number collision. The legacy redirect file was removed;
   ADR-016 No Blockchain for Evidence Integrity is the only ADR-016, and all
   documentation now references it.
2. Defined UCE unambiguously as ULPF Universal Canonical Event, the sole
   internal canonical representation. RawEvent remains immutable evidence;
   ParsedEvent remains source-specific; OCSF, OpenTelemetry Logs, ECS,
   JSON/NDJSON, REST/HTTP, Kafka, and Parquet are output projections.
3. Strengthened the machine-readable contracts. NormalizedEvent/UCE now
   requires explicit source and evidence context plus processing run,
   source-profile, parser, mapping, and schema versions. Lineage now requires
   the same root references and structured field mapping proof. DLQEvent now
   requires source/evidence/failure context, failed time, replay eligibility,
   and an explicit parser-selection state.
4. Added an explicit air-gap dependency classification: mandatory offline,
   optional offline, online only, and not required.
5. Distinguished demo, prototype, production, enterprise, and
   billion-events-per-day architectural scale without claiming laptop capacity.
6. Added a final explicit NTRO chain crosswalk: requirement to component to
   contract to phase to test to demo evidence.
7. Clarified that Silver lake data stores UCE and OCSF is a separate projection,
   avoiding two competing canonical-schema labels.
8. Added a six-member delivery cut that preserves all mandatory invariants
   while deferring advanced implementation work.

## NTRO traceability result

All requirements in the source problem statement have a documented chain in
[REQUIREMENTS_TRACEABILITY.md](REQUIREMENTS_TRACEABILITY.md):

| Capability group | Final audit result |
| --- | --- |
| ingestion, parsing, source-specific extraction | Covered by intake, parser architecture, RawEvent/ParsedEvent/Parser contracts, phases 2-3, fixture/security tests, and heterogeneous-log demo steps. |
| normalization, standardization, common taxonomy | Covered by UCE, mapping/schema architecture, Mapping/Schema/NormalizedEvent contracts, phase 4, equivalence tests, and unified-event demo. |
| raw preservation, losslessness, traceability | Covered by evidence, lineage, integrity, RawEvent/NormalizedEvent/Lineage contracts, phases 2/8/9/10, tamper/round-trip/restore tests, and raw-to-field trace demo. |
| plug-and-play, vendor-neutral onboarding, parser-effort reduction | Covered by source profile, format adapter, parser pack, mapping, review, publication, rollback, and replay architecture; Source/Parser/Mapping contracts; phases 3/4/6. |
| unified visibility, SIEM/data lake, AI/ML readiness | Covered by search/API/UI, UCE projections, lake architecture, quality/lineage, phases 8/11-15, authorization/adapter/schema tests, and investigation demo views. |
| scalability, extensibility, Big Data direction | Covered by durable partitioned transport, workers, backpressure, idempotency, storage partitioning, and scale profiles; phases 7/8/15/16; measured load/recovery evidence only. |
| air gap and containers | Covered by local services, signed bundles, local registries, OCI deployment, phases 1/10/16, no-egress and offline-import tests, and air-gap demo status. |
| perimeter device scope | Covered for firewall, router, VPN, IDS/IPS, WAF, proxy, security gateway, and extensible perimeter telemetry across declared structured, semi-structured, and proprietary formats. |

No mandatory requirement was found without an architectural home, data contract,
implementation phase, test obligation, and demo-proof concept.

## Confirmed architecture decisions

| Decision | Audit conclusion |
| --- | --- |
| Internal canonical representation | UCE is the sole internal canonical event representation. |
| External standards | OCSF is the primary cybersecurity projection; OpenTelemetry Logs and ECS are adapters, not internal competitors. |
| Universal onboarding | Source, format, parser adapter, source profile, extraction, mapping, transformation, schema, and output adapter remain separate. |
| Evidence integrity | Immutable raw payloads, SHA-256, append-only manifests, signed Merkle seals, access audit, and restore verification are selected. Blockchain is not required. |
| Parser lifecycle | Parser packs are declarative, signed, versioned, testable, approvable, publishable, monitorable, revocable, rollback-capable, and replay-compatible. |
| AI | Optional, offline-capable, advisory only; proposals require explanation, validation, approval, versioning, and audit. |
| Failure behavior | Accepted evidence is preserved; retries, DLQ, quarantine, and replay are explicit. |
| Storage | PostgreSQL holds governance metadata, object storage holds evidence, OpenSearch holds operational projections, Parquet/Iceberg-compatible storage holds analytical data, and Kafka-compatible transport carries durable work references. |
| Deployment | OCI containers and Docker Compose are the reference MVP profile; Kubernetes is a later option, not an MVP or air-gap prerequisite. |

## Contract audit result

| Contract | Audit conclusion |
| --- | --- |
| RawEvent | Identifies the source and receipt, preserves immutable payload reference, hash, ingestion time, transport data, and evidence-manifest linkage. |
| ParsedEvent | Retains raw/source identity, source-resolution state, parser version, field provenance, parse residue, warnings, and processing time. |
| NormalizedEvent/UCE | Requires raw/source/evidence identity, processing run, source profile, parser/mapping/schema versions, field provenance, quality, enrichment status, lineage, and output projection metadata. |
| Parser, Mapping, Schema, Source | Carry identifiers, semantic versions, lifecycle/status, compatibility, integrity or approval metadata, and governed references. |
| ReplayJob | Pins target parser/mapping/schema versions and records scope, requester, lifecycle, and result. |
| DLQEvent | Requires source/evidence/failure context, failed time, retry/replay state, and explicit parser-selection context. |
| Lineage | Requires raw/source/result identity, evidence verification identifiers, all governing artifact versions, stages, and field transformation proof. |
| AuditEvent | Records actor, action, target context, outcome, time, and audit-chain integrity. |

The contract inventory contains 12 JSON Schema files. Contract consistency is
architectural, not a runtime compatibility guarantee until Phase 1+ validation
and tests exist.

## Losslessness and lineage result

The design preserves raw bytes before asynchronous processing. Unknown fields,
malformed events, parser failures, normalization warnings, enrichments, AI
proposals, duplicate-looking receipts, and output failures cannot overwrite or
delete accepted evidence. Enrichment and AI values are distinct from observed
data. Every completed UCE has a raw reference, evidence hash/manifest,
source/profile/parser/mapping/schema versions, processing run, field
provenance, and lineage representation.

## AI, security, and air-gap result

AI is not in the production processing path and cannot change raw evidence,
execute log content, silently publish parser packs, or require Internet
access. The core reference deployment runs locally. Mandatory offline,
optional offline, online-only build activities, and unneeded cloud/SaaS
dependencies are explicitly classified in
[AIRGAP_ARCHITECTURE.md](AIRGAP_ARCHITECTURE.md).

The threat model covers hostile logs, parser injection, ReDoS, oversized and
malicious uploads, traversal, query injection, unauthorized evidence access,
tampering, credential/container/supply-chain compromise, denial of service,
data poisoning, AI prompt injection, and unsafe AI mappings. The architecture
still requires future implementation security tests before any production-like
claim.

## Parser, drift, replay, and DLQ result

The parser lifecycle is source to sample to detection to parser/mapping to test
to validation to approval to version to publish to activate to monitor to
rollback. Drift detects new/removed/renamed fields, type/structure/delimiter/
timestamp/vocabulary changes; remediation is analyze, test, review, version,
publish, and replay if necessary. Replay creates distinct results under pinned
versions. Failures use retry, DLQ, or quarantine with reason, time, source,
artifact context, and replay eligibility.

## UI, feasibility, and innovation result

The planned UI includes dashboard, sources, onboarding, parser and mapping
studio, event explorer/details, raw/parsed/UCE trace, lineage, quality, drift,
replay, DLQ, analytics, audit, health, settings, and air-gap status. It is
designed as an operational security console with access-aware evidence display.

The six-member cut keeps the first slice focused on disclosed perimeter
fixtures, raw evidence, deterministic normalization, traceability, controlled
onboarding, explicit failure handling, and a local demo profile. Advanced local
AI, broad adapter coverage, correlation, and cluster features remain optional
or later-phase work. Differentiation rests on governed onboarding, lossless
evidence, field lineage, drift, replay, air-gap operation, and trustworthy
normalization rather than AI hype.

## Documented implementation risks and manual work

Remaining risks are intentional implementation risks: parser complexity and
safety, lawful corpus acquisition, local hardware limits, air-gap bundle
operations, identity/key management, performance sizing, usability validation,
and optional local-AI usefulness. Their mitigations and owners are in
[RISK_REGISTER.md](RISK_REGISTER.md).

Human tasks remain limited to repository governance, authorized/lawful data,
real-device logs, data policy, credentials/certificates, infrastructure,
air-gap transfer custody, security review, measured benchmark execution, demo
recording, and SIH submission. See [MANUAL_TASKS.md](MANUAL_TASKS.md).

## Freeze declaration

Phase 0 is frozen as the single source of truth for future Codex work. Future
phases must follow [CODEX_EXECUTION_RULES.md](CODEX_EXECUTION_RULES.md),
[ARCHITECTURAL_GUARDRAILS.md](ARCHITECTURAL_GUARDRAILS.md), the requirement
matrix, contracts, and ADRs. Material changes require an ADR, contract
compatibility analysis, requirement-trace update, test plan, and documentation
update.

### Final validation evidence

The final non-destructive validation passed after corrections:

- 12 JSON Schema contracts parse successfully and all local schema references
  resolve.
- All checked relative Markdown links resolve.
- The ADR inventory contains exactly 16 unique numbers, ADR-001 through
  ADR-016, and each ADR contains the required decision-record sections.
- All 38 required Phase 0 documents are present.
- All 15 ULPF requirement IDs appear in the traceability matrix.
- The deprecated UCE phrase and duplicate ADR-016 filename/reference are absent.
- Markdown fence integrity passed across the documentation set; 32 documents
  contain maintainable Mermaid diagrams.
- Contract checks confirm required UCE, DLQ, and Lineage provenance fields.

These checks validate documentation and contract structure. They do not replace
future implementation, security, performance, recovery, or usability tests.

## Exact Phase 1 recommendation

Start **Phase 1 - Foundation only**: initialize version control and team
governance, preserve this freeze baseline, establish the planned monorepo
skeleton, add local development configuration, and add documentation/schema/
type/lint/test checks. Do not begin ingestion, parser, AI, UI, or production
deployment features until the Phase 1 scope is explicitly assigned.
