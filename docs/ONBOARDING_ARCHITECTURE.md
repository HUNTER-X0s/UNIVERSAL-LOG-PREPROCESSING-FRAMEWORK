# Source and No-Code Onboarding Architecture

**Phase:** 0 (architecture only)  
**Goal:** Onboard a perimeter-security log source through governed configuration rather than a core-engine rewrite.

## Product promise and boundary

Onboarding is a controlled lifecycle for a source profile and its parser pack. It covers firewall, router, VPN, IDS/IPS, WAF, proxy, security-gateway, and other perimeter telemetry in Syslog, JSON, XML, CSV, CEF, LEEF, key-value, structured, semi-structured, and unknown forms. It does not promise that every arbitrary enterprise data source can be fully automated in the MVP.

A successful onboarding creates a versioned, signed, test-backed configuration that deterministically converts future events into the ULPF Universal Canonical Event (UCE). It does not alter immutable raw evidence, silently erase an unknown field, or make AI a production dependency.

## Governing principles

- Configuration-driven first: format parser + source profile + field mapping + declarative transformations + validation + versioning.
- Evidence-first: samples are immutable raw records with access control and hashes before analysis begins.
- Human authority: AI or heuristics can suggest; authorized reviewers approve; a separate publisher signs/releases.
- Safe incompleteness: uncertain values remain unmapped and recoverable rather than guessed.
- Test before activation: representative, negative, malformed, and drift fixtures are required before a parser becomes active.
- Reversible change: activation is separate from publication, with retained prior versions and replay support.

## Core onboarding objects

| Object | Owner | Lifecycle responsibility |
| --- | --- | --- |
| Source | Source administrator | Identifies a device/feed, ownership, transport, sensitivity, and operational state. |
| Source profile | Parser author/reviewer | Captures vendor/product/version hints, format, expected structure, field vocabulary, and drift baseline. |
| Sample corpus | Evidence service | Holds immutable sample references, labels, expected outcomes, negative cases, and permissions. |
| Detection report | Detection service | Records format candidates, confidence, structural observations, and evidence references. |
| Mapping proposal | Author or AI advisory service | Carries candidate source fields, UCE/OCSF targets, transformations, origins, confidence, and rationale. |
| Mapping version | Mapping registry | Represents reviewed declarative mappings and validation rules. |
| Parser pack | Parser registry | Bundles parser adapter selection, profile, mapping, transforms, compatibility, tests, signatures, and version. |
| Parser test run | Test service | Persists corpus results, coverage, failures, performance observations, and environment version. |
| Publication/activation record | Governance service | Separates signed release from controlled production activation/rollback. |
| Drift baseline/alert | Drift service | Stores expected structure and detects changes after activation. |

These are conceptual objects. Their future machine-readable definitions belong in versioned contracts and schemas, not in this document.

## Lifecycle and state controls

~~~mermaid
stateDiagram-v2
  [*] --> DraftSource
  DraftSource --> SamplesCaptured: samples linked
  SamplesCaptured --> Analysed: detect and extract
  Analysed --> MappingDraft: author creates or accepts proposal
  MappingDraft --> CorpusTesting: reviewer submits candidate
  CorpusTesting --> MappingDraft: failures or edits
  CorpusTesting --> Reviewed: tests and validation pass
  Reviewed --> Published: authorized publisher signs pack
  Published --> Active: authorized activation
  Active --> DriftSuspected: profile variance observed
  DriftSuspected --> MappingDraft: investigate/change draft
  Active --> RolledBack: activation rollback
  Published --> Retired: superseded without activation
  RolledBack --> Active: prior approved version reactivated
  Active --> Retired: source decommissioned
~~~

Only **Active** packs process production events. Draft, Analysed, MappingDraft, and Reviewed states are not executable in production.

## Primary no-code flow

~~~mermaid
sequenceDiagram
  actor Admin as Source Administrator
  actor Reviewer as Mapping Reviewer
  actor Publisher as Parser Publisher
  participant UI as ULPF Console
  participant Evidence as Raw Evidence Service
  participant Detect as Detection and Suggestion Services
  participant Registry as Parser and Mapping Registry
  participant Test as Corpus Test Service

  Admin->>UI: Create source and add sample corpus
  UI->>Evidence: Store immutable samples and hashes
  UI->>Detect: Request deterministic format/structure analysis
  Detect-->>UI: Candidates, extracted fields, confidence, rationale
  Admin->>UI: Edit mappings and validation rules
  UI->>Registry: Save versioned mapping draft
  Reviewer->>UI: Review origins, semantics, unknown fields
  UI->>Test: Run corpus, malformed, and regression tests
  Test-->>UI: Results and coverage
  Reviewer->>UI: Approve reviewed candidate
  Publisher->>UI: Publish signed parser pack
  UI->>Registry: Store signed release
  Publisher->>UI: Activate release for source
  UI->>Registry: Record activation and audit trail
~~~

## Unknown-format branch

Unknown is a supported state, not a failure to hide. When no existing profile matches:

1. Preserve the sample and create an Unknown-format finding with source and integrity references.
2. Run deterministic structure analysis before advisory AI: framing, delimiters, record boundaries, key patterns, type candidates, timestamp candidates, and repeated vocabulary.
3. Offer dictionary/semantic suggestions only as a mapping proposal. Display alternatives and field-level confidence.
4. Require operator-defined extraction expressions within allowed declarative constructs; prohibit arbitrary code and unsafe regular expressions.
5. Use a small but diverse corpus to validate stable structure. A single happy-path sample is insufficient.
6. Create an explicit mapping for all desired canonical fields and retain all remaining source fields under recoverable unmapped attributes.
7. Publish only when parsing, validation, security policy, regression, and reviewer checks pass.

If structure remains ambiguous, the source stays in MappingDraft and future raw events route to controlled quarantine or raw-only retention according to source policy. They are never silently dropped.

## Required validation gates

| Gate | Required evidence | Blocks publication when |
| --- | --- | --- |
| Evidence integrity | Sample ID, raw hash, source identity, ingest metadata | Raw evidence is unavailable or integrity verification fails. |
| Structure | Format result, field paths/expressions, record boundaries | Extractors are ambiguous, unsafe, or unbounded. |
| Semantics | UCE targets, origin labels, transformation rationale | Inferred values masquerade as observed, or critical mappings lack review. |
| Completeness | Required canonical-field coverage and unmapped-field retention | Required mappings are absent without an accepted source-specific reason. |
| Corpus | Positive, negative, malformed, and drift-like fixtures | Candidate does not meet expected outputs or handles invalid input unsafely. |
| Security | Pack signature input, permissions, dependency/policy checks | Untrusted extension, prohibited transform, or unauthorized user is involved. |
| Operations | Compatibility, rollback target, alerting, capacity observation | No rollback/recovery plan or incompatible active dependency exists. |

## Roles and separation of duties

| Role | May do | Must not do by default |
| --- | --- | --- |
| Source administrator | Register source, capture samples, view allowed source health. | Publish parser packs or view restricted raw evidence. |
| Parser author | Build profiles/mappings and request tests. | Approve their own production release in high-assurance mode. |
| Mapping reviewer | Review semantics, confidence, origins, corpus results. | Sign releases without publisher permission. |
| Parser publisher | Sign/publish/activate approved packs and roll back. | Edit raw samples or bypass test gates. |
| Security analyst | Investigate events, lineage, quality, and drift. | Change parser configuration without authorization. |
| Auditor | Read audit and permitted evidence/lineage. | Modify source, mapping, or release state. |

MVP deployments may combine roles for a small team, but the audit log still records the acting identity and the combination must be documented.

## Activation, rollback, and replay

Activation binds a source profile to one parser-pack version and effective time. It must use optimistic concurrency so two administrators cannot silently overwrite each other. A rollback activates an already approved prior pack; it does not destroy the newer pack or its test/audit history.

Replay creates a distinct job that reads immutable raw-event references and produces a separately versioned normalized output. It must state the source selection, time range, parser/mapping/schema versions, target destination, deduplication policy, and operator. Default replay output does not overwrite historical normalized evidence.

## Drift handoff

The active source profile supplies expected-field, type, structure, and vocabulary baselines. Drift detection creates an alert with sample references and impact estimate. It never silently changes a mapping. Operators can branch from the active pack into a new onboarding draft, test it against both historical and new samples, publish a new version, then replay if warranted.

## MVP delivery slice

The hackathon implementation should prove one complete path: create a source, upload multi-format samples, detect a known format, define/review a mapping, run fixtures, publish/activate a versioned pack, inspect raw-to-normalized lineage, and roll back or reprocess. Unknown-format assistance, drift comparison, signed offline bundles, and local semantic suggestions should be designed now and introduced only if the core path is complete and measured.

## Acceptance criteria

- A source can be onboarded without changing the parser-engine core.
- Every sample, draft, test, publication, activation, rollback, and review action has a stable identifier and audit record.
- Raw samples and unmapped fields remain recoverable through all states.
- A pack cannot activate without a version, passing configured gates, authorization, and audit evidence.
- The same approved pack produces deterministic results over the same raw corpus and declared versions.
- Unknown, malformed, and drifted logs have explicit retention and recovery paths.
