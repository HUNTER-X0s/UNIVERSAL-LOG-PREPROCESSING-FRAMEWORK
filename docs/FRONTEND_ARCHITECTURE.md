# Frontend Architecture

**Phase:** 0 (architecture only)  
**Product stance:** A security operations console that makes provenance, uncertainty, and operational state visible rather than a generic dashboard.

## Decision

The planned frontend is a modular React + TypeScript single-page application served with the ULPF deployment, with a versioned API client, route-level permission checks, server-state caching, and a small client-state layer for local interaction. This choice favors a six-member team’s delivery speed and typed UI contracts while keeping the backend replaceable.

The UI is an operator console, not the source of truth. All mutations go through versioned APIs, use audit-aware confirmation, and show the authoritative server state. It must work in an air-gapped browser environment with locally hosted assets and no required third-party analytics, fonts, CDNs, or remote identity widgets.

## Information architecture

~~~mermaid
flowchart TD
  U[Authenticated user] --> O[Overview]
  U --> S[Sources]
  S --> SO[Source onboarding]
  S --> PS[Parser Studio]
  PS --> MR[Mapping review]
  U --> R[Registries]
  R --> PR[Parser registry]
  R --> SR[Schema registry]
  U --> P[Processing]
  P --> PE[Pipeline health]
  P --> D[DLQ and quarantine]
  P --> RL[Replay Lab]
  U --> E[Explore]
  E --> EX[Event Explorer]
  EX --> ED[Event Details]
  ED --> T[Raw, parsed, normalized trace]
  T --> L[Lineage and integrity]
  U --> Q[Quality and drift]
  Q --> DQ[Data quality]
  Q --> SD[Schema drift]
  U --> A[Analytics]
  A --> CT[Correlation and timeline]
  A --> EN[Enrichment]
  U --> G[Governance]
  G --> AU[Audit]
  G --> ST[Settings and access]
  G --> AG[Air-gap status]
  U --> H[System health]
~~~

## Navigation model

The primary navigation groups work by operator intent:

| Group | Primary views | Main user question |
| --- | --- | --- |
| Observe | Overview, Sources, Pipeline, System Health | Is the platform receiving and processing telemetry safely? |
| Onboard | Source Onboarding, Parser Studio, Mapping Studio, Parser Registry | How do I make this new source deterministic and trusted? |
| Investigate | Event Explorer, Event Details, Raw/Parsed/Normalized Trace, Lineage | What happened, and can I prove where each value came from? |
| Recover | DLQ/Quarantine, Replay Lab, Drift | What failed or changed, and how do I repair it without losing evidence? |
| Govern | Schema Registry, Quality, Audit, Settings, Air-Gap Status | Is the system compliant, healthy, and controllable? |
| Analyze | Correlation/Timeline, Enrichment, downstream-output status | What downstream security value is the normalized data enabling? |

Routes must deep-link to stable resource identifiers and filter state so an auditor or teammate can return to the same source, event, parser version, or replay job. A location that exposes raw evidence must enforce permission checks both in the UI and server.

## View design requirements

| View | Primary content | Trust and safety behavior |
| --- | --- | --- |
| Overview | Ingestion, parser success, quality, DLQ, drift, system-health summaries. | Labels metrics as measured only when a time range and method are visible; no fabricated capacity claims. |
| Sources | Source status, active parser, last seen, quality/drift indicators. | Source-state changes require role checks and audit-aware confirmation. |
| Source Onboarding | Stepper for samples, detection, mappings, tests, review, publish, activation. | Shows draft versus active state, confidence, field origins, validation blocks, and raw-data permissions. |
| Parser/Mapping Studio | Declarative mapping editor, sample preview, test results, version comparison. | Never presents generated suggestions as approved; supports discard, save draft, and review handoff. |
| Event Explorer | High-density search, filters, time range, field columns, export awareness. | Displays data-classification badges and limits protected fields based on authorization. |
| Event Details / Trace | Side-by-side raw, parsed, UCE normalized, unmapped, enrichments, errors, and provenance. | Raw is read-only; clearly separates observed, inferred, derived, and enriched data. |
| Lineage / Integrity | Transformation graph, parser/schema/mapping versions, hashes, verification result. | Makes validation failure unmistakable and provides a non-destructive evidence retrieval path. |
| Quality / Drift | Source/pipeline scores, change alerts, impact estimate, sample links. | Drift opens a new draft workflow; it cannot auto-edit active parsers. |
| Replay / DLQ | Job configuration, dry-run comparison, records, failure reasons, recovery actions. | Defaults to non-overwriting output and requires a scoped, reviewed action. |
| Air-Gap / Health | Offline readiness, local service health, signed bundle and pack status. | Avoids reporting cloud reachability as a requirement; distinguishes degraded optional features. |

## Component architecture

~~~mermaid
flowchart LR
  App[App shell and route guard] --> Layout[Navigation, context, notifications]
  App --> Pages[Feature pages]
  Pages --> Features[Source / Parser / Event / Replay / Governance modules]
  Features --> UI[Shared accessible UI primitives]
  Features --> Query[Typed API client and server-state cache]
  Features --> Local[Local view state and form state]
  Query --> API[Versioned ULPF API]
  API --> Stream[Optional authenticated status stream]
~~~

Feature modules own their page composition, validation, and domain-specific widgets. Shared primitives own only reusable visual/interaction behavior. Backend business rules remain on the server; the client may pre-validate for usability but cannot authorize, sign, validate, or publish a parser independently.

## State and data communication

| State type | Owner | Design |
| --- | --- | --- |
| Server state | API/cache layer | Sources, events, registry versions, quality, replay jobs, audit data. Cache keys include API version, resource ID, filters, and permission-sensitive scope. |
| Local UI state | Feature module | Panel visibility, draft filter, selected trace node, unsaved form controls, table column preference. |
| URL state | Router | Resource IDs, time range, search/filter query, active tab, compare-version selection. |
| Form/draft state | Onboarding/Studio module | Explicit draft version with server-side optimistic concurrency token. Never treat local state as publication. |
| Live status | Authenticated stream or bounded polling | Pipeline health, job progress, quality/drift alerts. Reconnect with backoff and retain last-known timestamp. |

Mutations use idempotency keys where the API supports them, disable duplicate submission while pending, return actionable error detail, and refresh authoritative state on completion. For reversible operations such as a draft save, optimistic feedback is allowed with a visible pending state and rollback on server rejection. Publication, activation, evidence verification, and replay start remain confirmation-driven because their operational impact is material.

## Security-sensitive UX

- Show the active environment, air-gap status, user role, and last successful authorization refresh without exposing secrets.
- Redact or mask sensitive raw fields by default where policy requires; make any reveal action explicit, authorized, and auditable.
- Use stable version badges for parser, mapping, schema, model, and output adapters on every trace and review page.
- Make a proposed/inferred field visually distinct from an observed source field; never collapse them into one value.
- Require reason, scope preview, and role-aware confirmation for activation, rollback, replay, export, protected-evidence access, and destructive retention actions.
- Provide clear authorization failures rather than hiding critical controls silently; do not disclose protected data in an error message.
- Render untrusted log content as text, preserve escaping, and do not execute markup embedded in log samples.

## Error, loading, empty, and degraded states

Every operational page must specify four states:

| State | Expected behavior |
| --- | --- |
| Loading | Skeleton or bounded progress with the request scope; no misleading zero values. |
| Empty | Explain whether no data exists, filters exclude it, access is restricted, or a source has not sent data. |
| Error | State what failed, correlation/request ID if available, retry safety, and a route to health/audit information. |
| Degraded | Continue read-only investigation with last-known data when optional live updates, enrichment, or AI are unavailable; identify freshness. |

## Accessibility and responsive behavior

The console should target keyboard-first analyst workflows: semantic landmarks, focus management in steppers/dialogs, visible focus, accessible data-table labels, non-color-only status cues, screen-reader descriptions for lineage graphs, and contrast appropriate for a dark security-console theme. Dense tables may require horizontal scrolling on smaller screens, while destructive/governance actions remain usable on laptop-sized displays. Mobile is a secondary responsive experience for health and approval review, not the primary event-investigation target.

## Technology evaluation

| Area | Candidates | Selected direction | Justification / trade-off / fallback |
| --- | --- | --- | --- |
| UI framework | React, Vue, Angular | React + TypeScript | Broad ecosystem, typed components, and hackathon delivery speed. Trade-off: discipline is needed to avoid unstructured state. Fallback: a framework-agnostic API and design tokens preserve future migration options. |
| Styling/components | CSS modules, utility CSS, component library | Locally bundled accessible primitives plus design tokens | Prevents remote dependency and supports security-console density. Trade-off: more initial UI work. Fallback: adopt a vetted local component library later. |
| Server state | Query cache, Redux-like store, custom fetch | Typed query/cache layer | Fits API-backed resource screens and invalidation needs. Trade-off: cache policy must respect permissions. Fallback: direct typed fetch wrappers for small MVP surface. |
| Charts/graphs | Custom SVG, chart library | Locally bundled, accessible chart/graph adapter | Needed for quality/lineage but must not obscure data. Fallback: tables and textual timelines remain authoritative. |
| Realtime | WebSocket/SSE/polling | Bounded polling first; authenticated stream when justified | Simple, air-gap friendly MVP. Trade-off: less immediate updates. Fallback: manual refresh and timestamped last-known state. |

## Acceptance criteria

- An analyst can locate an event and visually distinguish raw evidence, parsed fields, UCE fields, unmapped values, inferred values, and enrichments.
- A reviewer can complete the onboarding flow without editing source code and sees every validation/publish boundary.
- Protected raw evidence and governance actions are permission-aware, auditable, and not exposed by client-side routing alone.
- The console has usable loading, empty, error, and degraded states for each primary operational route.
- No frontend view requires an internet-hosted asset or external AI service in an air-gapped deployment.
