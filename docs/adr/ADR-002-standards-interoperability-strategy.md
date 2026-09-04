# ADR-002: OCSF, OpenTelemetry, and ECS Interoperability Strategy

**Status:** Accepted for Phase 0

## Context

ULPF needs cybersecurity, observability, and ecosystem interoperability without locking internal evidence or semantics to one external standard.

## Decision

Use UCE internally; project to OCSF as the primary cybersecurity target, and support OpenTelemetry Logs and ECS through explicit versioned adapters.

## Alternatives considered

- OCSF-only internal model.
- ECS-only internal model.
- OpenTelemetry-only internal model.
- Direct per-vendor outputs.

## Pros

Security-oriented interoperability, broad downstream choice, and retained ULPF evidence/lineage semantics.

## Cons

Projection maintenance and imperfect one-to-one field coverage require mapping tests and documentation.

## Security implications

Adapters preserve origin and evidence references where target formats permit; exports remain authorized and audited.

## Operational implications

Each adapter needs target-version compatibility tests, delivery status, and failure isolation from canonical processing.

## Consequences

No external schema becomes a reason to discard raw/vendor fields or to bypass UCE validation.
