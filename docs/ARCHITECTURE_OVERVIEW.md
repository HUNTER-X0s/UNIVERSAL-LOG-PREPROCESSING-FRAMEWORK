# ULPF Architecture Overview

**Status:** Phase 0 reference architecture; planned, not implemented  
**Authority:** SIH26156 / NTRO requirements take priority over all implementation choices.

## 1. Purpose

Universal Log Pre-processing Framework (ULPF) is designed as a vendor-agnostic
preprocessing and intelligence fabric for heterogeneous perimeter-security
telemetry. It is not a full SIEM, SOAR, packet-capture, or vulnerability
management product. Its responsibility is to receive evidence, preserve it,
interpret it deterministically where possible, normalize it into a trustworthy
canonical representation, and make it available to downstream systems.

The central architectural promise is:

> Every resulting event remains connected to its original evidence, the
> versioned logic that processed it, and any later enrichment or inference.

No performance, compatibility, vendor, or deployment claim in this document is
a measured result. All components below are planned architecture.

## 2. Product boundary

| In scope for the core | Out of scope for the core MVP |
|---|---|
| Firewall, router, VPN, IDS/IPS, WAF, proxy, security gateway, and comparable perimeter telemetry | Replacing a SIEM, SOAR, SOC, packet-capture, or vulnerability-management platform |
| Syslog, JSON, XML, CSV, CEF, LEEF, key=value, structured and semi-structured vendor formats | Arbitrary enterprise-domain integrations before the perimeter-security path is proven |
| Raw evidence preservation, parsing, normalization, lineage, replay, quality signals, and interoperable exports | Autonomous production parser publication or AI-driven enforcement decisions |

The data plane must be able to operate without Internet access. Optional
onboarding assistance, enrichment, and model updates must never become a
runtime dependency of deterministic processing.

## 3. Core before innovation

| Layer | Mandatory capability | Planned outcome |
|---|---|---|
| NTRO Core | Ingest, identify, parse, extract, normalize, validate, preserve, trace, store, and route perimeter logs | A lossless and explainable event path |
| NTRO Core | Plug-and-play source onboarding, SIEM/data-lake outputs, AI/ML-ready data, air-gap operation, container portability | A practical interoperability boundary |
| Differentiation | Unknown-format assistance, confidence scoring, parser regression, schema-drift detection, replay, field lineage, integrity verification | Trustworthy acceleration, never hidden automation |
| Roadmap | Local models, offline knowledge packs, advanced correlation, local threat intelligence, signed bundle management | Extensions after the core path is demonstrably correct |

## 4. Architectural principles and invariants

1. **Evidence first.** Raw bytes/text and ingest metadata are retained before
   parsing; downstream failure cannot erase accepted evidence.
2. **No silent mutation or loss.** Original content is immutable by reference,
   and unknown or unmapped fields remain recoverable.
3. **Traceable transformations.** Every normalized field records whether it is
   observed, inferred, enriched, or derived and links to the responsible step.
4. **Deterministic production path.** Approved, versioned parser packs and
   mappings are used in production; AI is advisory and review-gated.
5. **Configuration-driven onboarding.** New source support should primarily be
   expressed through format parsers, source profiles, mappings, and validation
   fixtures rather than changes to the core engine.
6. **Version everything that changes meaning.** Parsers, mappings, schemas,
   enrichment packs, contracts, and processing runs have stable identities and
   versions.
7. **Explicit failure paths.** Retries, DLQ/quarantine, reason codes, alerts,
   and replay replace silent drops.
8. **Air-gap by design.** Runtime uses local registries, artifacts, storage,
   identities, and optional local inference. Updates enter through verified
   offline bundles.
9. **Replaceable infrastructure.** Storage, transport, and export adapters are
   behind documented contracts so a small demo does not dictate enterprise
   deployment.
10. **Measured claims only.** Throughput, coverage, latency, and compatibility
    claims require a documented test corpus and reproducible measurement.

## 5. Reference logical architecture

~~~mermaid
flowchart LR
  subgraph Sources[Perimeter telemetry sources]
    FW[Firewall]
    VPN[VPN]
    IDS[IDS/IPS]
    WAF[WAF / proxy]
    UNK[New or unknown source]
  end

  subgraph ULPF[ULPF data and control planes]
    EC[Edge collection / intake]
    RE[Raw evidence service]
    Q[Durable transport]
    DET[Format and source identification]
    PE[Parser and extraction engine]
    NM[Semantic mapping and normalization]
    VQ[Validation and data quality]
    LN[Lineage and integrity]
    RT[Routing / replay / DLQ]
    REG[Parser, mapping, schema, source registries]
  end

  subgraph Consumers[Downstream consumers]
    SRCH[Search and investigation]
    SIEM[SIEM adapters]
    LAKE[Data-lake adapters]
    ML[Analytics / ML consumers]
  end

  FW & VPN & IDS & WAF & UNK --> EC --> RE --> Q --> DET --> PE --> NM --> VQ --> LN --> RT
  REG -. versioned control .-> DET
  REG -. versioned control .-> PE
  REG -. versioned control .-> NM
  RT --> SRCH & SIEM & LAKE & ML
  RE -. raw evidence reference .-> LN
~~~

The **data plane** handles events and raw evidence. The **control plane**
governs source profiles, parser packs, mappings, schemas, approvals,
configuration, and audit records. The two planes interact through immutable
version references rather than mutable runtime configuration.

## 6. Core design decisions

| Decision | Rationale | Boundary |
|---|---|---|
| ULPF Universal Canonical Event (UCE) is the internal contract | A product-owned, versioned intermediate model can preserve evidence and represent semantics not shared by every external standard | See ADR-001 and EVENT_MODEL.md |
| OCSF is the primary cybersecurity export target | It provides a security-oriented taxonomy; UCE prevents ULPF from being locked to it | See ADR-002 and SCHEMA_STRATEGY.md |
| OpenTelemetry Logs and ECS are adapter targets | They serve observability and ecosystem interoperability without imposing their limitations on raw evidence or UCE | See ADR-002 |
| Parser packs are configuration-driven and versioned | Separates reusable format parsing from source-specific mapping, cuts onboarding effort, and enables regression/replay | See ADR-003 and PARSER_ARCHITECTURE.md |
| Raw evidence is immutable and separately stored | Search indexes and normalized records can be regenerated without treating them as the evidentiary source | Detailed storage controls are specified in future storage/evidence documents |
| AI assists onboarding only | It can propose a mapping, but must expose confidence and evidence, pass validation, and receive human approval before publication | No AI decision may silently change a production parser |

## 7. MVP and scale path

| Concern | Hackathon-sized MVP | Scale-ready direction |
|---|---|---|
| Sources | A small, disclosed sample corpus across several formats | Distributed collectors and independently deployable source adapters |
| Processing | Single-node or small-container deployment with the same contracts | Partitioned durable transport, consumer groups, stateless workers, and backpressure |
| Storage | Local services suitable for a reproducible demo | Tiered object evidence, operational search, metadata store, and partitioned lake formats |
| Onboarding | Reviewed configuration packs and fixture tests | Signed, governed catalog with drift alerts, compatibility checks, and controlled rollout |
| AI | Optional local/offline suggestion workflow | Offline model/prompt packs with provenance and human approval |

The architecture is designed to scale horizontally; it does not assert that a
student laptop can process billions of events per day.

## 8. Navigation

- System structure and runtime flows: [SYSTEM_ARCHITECTURE.md](SYSTEM_ARCHITECTURE.md)
- Requirement-to-proof chain: [REQUIREMENTS_TRACEABILITY.md](REQUIREMENTS_TRACEABILITY.md)
- Business concepts: [DOMAIN_MODEL.md](DOMAIN_MODEL.md)
- Event, storage, schema, parser, and normalization contracts:
  [EVENT_MODEL.md](EVENT_MODEL.md), [DATA_MODEL.md](DATA_MODEL.md),
  [SCHEMA_STRATEGY.md](SCHEMA_STRATEGY.md),
  [PARSER_ARCHITECTURE.md](PARSER_ARCHITECTURE.md), and
  [NORMALIZATION_ARCHITECTURE.md](NORMALIZATION_ARCHITECTURE.md)

## 9. Open implementation decisions

The architecture intentionally does not claim a completed technology stack.
Future Phase 1 must choose concrete libraries and deployment products after
checking air-gap packaging, team skill, operational footprint, license,
security-maintenance, and benchmark evidence. Any material change to the
invariants or external contracts requires a new ADR.
