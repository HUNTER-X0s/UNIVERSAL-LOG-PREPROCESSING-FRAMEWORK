# AI-Assisted Unknown-Log Architecture

**Phase:** 0 (architecture only)  
**Status:** Accepted design direction  
**Scope:** Assistance for onboarding and maintenance; never a mandatory dependency in the production event path.

## Decision in one sentence

ULPF uses deterministic detection, parsing, validation, and versioned parser packs for production processing. Optional local AI may propose field meanings and mappings for an unknown sample, but a qualified human must validate and approve the resulting configuration before it can be signed, published, and activated.

This preserves the core NTRO requirements of losslessness, traceability, vendor neutrality, air-gapped operation, and reduced parser effort without treating generated output as evidence or executable authority.

## Boundaries and invariants

| Concern | Design rule |
| --- | --- |
| Raw evidence | The sample bytes stay immutable in the raw-evidence store; AI receives a controlled copy or redacted projection. |
| Production lane | Does not call an AI service. A published parser pack is deterministic, signed, versioned, and tested. |
| Advisory lane | Produces proposals, confidence, evidence references, and explanations; it never mutates an event or publishes a pack. |
| Origin | Observed, inferred, derived, and enriched values remain separately labelled in the ULPF Universal Canonical Event (UCE). |
| Air gap | Core operations require no internet. A local model and offline knowledge packs are optional imported artifacts. |
| Safety | Log text is data, never instructions. No generated code is executed from a model response. |
| Accountability | Every proposal, review decision, model/version, prompt/template version, and publication transition is auditable. |

## Two-lane design

~~~mermaid
flowchart LR
  subgraph Production["Deterministic production lane"]
    R[Immutable raw event] --> D[Format/source detection]
    D --> P[Signed parser pack]
    P --> V[Mapping and schema validation]
    V --> U[UCE normalized event]
    U --> O[OCSF, OTel, ECS adapters]
  end
  subgraph Advisory["Optional advisory onboarding lane"]
    S[Unknown sample corpus] --> F[Feature and pattern extraction]
    F --> K[Local dictionaries and schema knowledge]
    K --> M[Optional local embedding model or LLM]
    M --> Q[Mapping proposal + confidence + rationale]
    Q --> H[Human review and edits]
    H --> T[Corpus tests and policy validation]
    T --> G[Signed versioned parser pack]
  end
  G -. approved configuration only .-> P
~~~

The arrow between lanes represents a governed publication artifact, not runtime AI inference.

## Unknown-log analysis workflow

1. The operator registers a source and uploads or captures a representative sample corpus. Each sample is stored as immutable raw evidence and linked to a source-profile draft.
2. The deterministic classifier first identifies container/transport and structure: Syslog framing, JSON, XML, CEF, LEEF, CSV, key-value, delimited, or unknown. It records competing classifications rather than hiding ambiguity.
3. Pattern extraction proposes stable tokens, key names, delimiters, type candidates, timestamp candidates, cardinality, and example values. This stage can run without a model.
4. Dictionaries and known schema vocabulary suggest semantic candidates for each extracted field. For example, a field with IP-shaped values can be proposed as source or destination only with contextual rationale; it is not silently assigned.
5. If configured, a local semantic model or local LLM receives the bounded feature summary, schema vocabulary, and redacted examples. It returns a structured mapping proposal, explanation, confidence per field, and uncertainty reasons.
6. The UI requires a reviewer to accept, reject, or edit every nontrivial mapping. Low-confidence or conflicting candidates are intentionally unresolved.
7. ULPF compiles the approved declarative format rule, source profile, mapping, transformations, validation rules, and test corpus references into a candidate parser pack.
8. The candidate runs corpus, negative, security, and regression tests. Only a passing pack may be signed and published by a user with parser-publisher authority.
9. Activation is a separate, auditable step. Earlier parser versions remain available for rollback and replay.

## AI inputs and outputs

### Permitted inputs

- Sample identifiers and selected raw samples, subject to the viewer permission.
- Deterministic structural features and token statistics.
- Approved source-profile metadata.
- Local schema and field dictionaries, including UCE and OCSF mapping vocabulary.
- Explicitly supplied historical mapping examples that have passed review.

### Prohibited inputs by default

- Broad raw-event archives.
- Secrets, credentials, private keys, or deployment configuration.
- Unredacted sensitive values when a redacted projection suffices.
- Instructions embedded in a log message, parser description, or user-controlled field.

### Required proposal contents

An onboarding proposal is a reviewable domain object, not a parser:

| Output | Requirement |
| --- | --- |
| Candidate source/format classification | Include alternatives and evidence. |
| Candidate extracted fields | Include path/token expression, type, examples, and extraction limitations. |
| Semantic mapping | UCE target, optional OCSF target, transformation suggestion, and field origin marked as inferred. |
| Confidence | Field-level score, calibration version, reason codes, and ambiguity. |
| Rationale | Human-readable evidence references; no opaque “model says so” approval. |
| Safety result | Flags for sensitive content, prompt-injection-like text, unsupported constructs, or policy conflicts. |
| Reproducibility metadata | Model bundle digest, model version, template version, dictionary version, and input sample IDs. |

The model cannot emit executable parser code. The only publication path is a constrained declarative parser-pack format validated by the parser registry.

## Confidence and approval policy

Confidence is evidence for prioritizing review, not an authorization mechanism. ULPF stores a score from 0 to 1, its calibration version, and reasons such as exact key match, value-shape match, contradictory context, or insufficient sample diversity.

| Band | Treatment |
| --- | --- |
| 0.90–1.00 | May be prefilled in the review UI; still requires human approval before publication. |
| 0.60–0.89 | Requires explicit field-by-field review and corpus expansion if semantics affect routing or security analysis. |
| Below 0.60 | Remains unmapped unless an operator supplies an approved mapping. |
| Any conflict or policy violation | Block publication irrespective of confidence. |

Human reviewers must verify semantic directionality (for example, source versus destination), timestamp semantics, security-critical fields, lossless retention of unmapped attributes, and output classification. Approval creates an audit event containing the reviewed proposal version and resulting pack version.

## Local model and air-gapped operation

The MVP must function with AI disabled. If the team demonstrates AI assistance, it should use a locally imported, documented model bundle only after hardware feasibility is measured. The model is a replaceable adapter behind an inference boundary.

| Mode | Capability | Operational requirement |
| --- | --- | --- |
| AI disabled | Deterministic detection, manual mapping, parser testing, publication, and production processing | Required baseline; works fully air-gapped. |
| Local lightweight semantic model | Candidate field similarity and schema suggestion | Signed offline model bundle; CPU/RAM suitability measured before inclusion. |
| Local LLM | Optional richer mapping rationale and transformation suggestions | Isolated inference service, resource quotas, template/version pinning, and an explicit operator opt-in. |
| Online service | Not part of the production design | May only be a separate development convenience after an explicit policy decision; never required for an air-gapped deployment. |

An air-gap update bundle can include a model artifact, license/provenance record, SBOM, signature, compatibility manifest, and rollback version. The administrator verifies the bundle before import. A missing or failed model degrades onboarding suggestions only; it never stops ingestion or deterministic parsing.

## Security controls

- Treat all logs and uploaded samples as hostile input; normalize encodings, bound sizes, and preserve bytes without executing content.
- Redact or tokenize sensitive values in the advisory projection when possible; preserve access-controlled raw evidence separately.
- Run feature extraction and optional inference in a sandboxed service with network egress disabled, CPU/memory/time limits, and no access to signing keys.
- Validate each model response against a strict proposal contract and allow-list of UCE field paths and declarative transformations.
- Defend against prompt injection by ignoring instructions found inside log content and using fixed system templates with bounded context.
- Require separate roles for source editor, reviewer, parser publisher, and raw-evidence viewer; production use should enforce separation of duties.
- Scan, sign, and version knowledge, model, parser, mapping, and schema bundles. Record their digests in audit history.
- Never use AI output to create shell commands, dynamic imports, SQL, regular expressions without safety checks, or arbitrary transformation code.

## Failure behavior and observability

| Condition | Behaviour | Observable signal |
| --- | --- | --- |
| Format cannot be identified | Store sample, mark unknown, offer manual/no-code onboarding; do not discard it. | Unknown-format count and source alert. |
| Model unavailable or times out | Continue with deterministic features and manual mapping. | Advisory availability and timeout metrics. |
| Invalid model response | Reject the proposal; preserve diagnostics without exposing protected data. | Proposal-validation failure audit event. |
| Low/conflicting confidence | Hold in review state; do not activate a parser. | Review queue and unresolved-field ratio. |
| Candidate pack fails tests | Block signing/publication; retain test report and candidate for repair. | Parser test failure and regression metric. |
| Drift later invalidates a pack | Keep raw events, alert operators, draft a new candidate, and support replay after approval. | Drift alert, parser-health degradation. |

Track proposal acceptance/rejection rate, confidence calibration error, human edit rate, onboarding time, time-to-published-parser, unsafe-output blocks, model latency, and model availability. These are quality metrics to measure later, not claimed benchmark results.

## Testing strategy

- Unit tests for deterministic feature extraction, type detection, redaction, confidence policy, and proposal validation.
- Corpus tests with known formats, unknown/proprietary-style synthetic formats, ambiguous fields, Unicode, malformed input, and adversarial prompt-like text.
- Contract tests for the proposal object and parser-pack compiler.
- Security tests for oversized samples, regex/resource limits, injection attempts, model-output constraint violations, and unauthorized publication.
- Offline tests proving all core onboarding and production paths work with no network and no model service.
- Human-review usability tests confirming ambiguity and field origin are visible before approval.

## MVP and roadmap

| Capability | Priority | Reason |
| --- | --- | --- |
| Deterministic format detection, manual mapping, declarative pack creation, test, sign, approve, activate | MVP | Directly reduces parser effort while remaining reliable and air-gap compatible. |
| Dictionary-based field suggestions, confidence display, and review rationale | MVP if feasible | Strong, explainable differentiation without model dependency. |
| Local semantic similarity/embedding adapter | Advanced MVP | Useful assistance after deterministic workflow is demonstrably correct. |
| Local LLM mapping explanation and feedback learning | Roadmap | Hardware, security review, calibration, and corpus maturity must justify it. |
| Automated publication or self-modifying parser behaviour | Never automatic | Violates governance and forensic trust requirements. |

## Acceptance criteria for a future implementation

- A new source can be onboarded manually with AI disabled, without changing core parser-engine code.
- An unknown sample remains retrievable as immutable evidence while a proposal is pending.
- Every model-generated suggestion is labelled inferred and records model/template/input provenance.
- No AI suggestion becomes an active parser without passing validation/tests, authorized review, signing, and activation.
- A disconnected deployment demonstrates deterministic ingestion and parser execution with the optional model absent.
- A failed or withdrawn parser version can be rolled back, and raw history can be replayed under a later approved version.
