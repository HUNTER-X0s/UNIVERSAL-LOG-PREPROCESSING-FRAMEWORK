# ADR-003: Configuration-driven, Versioned Parser Packs

**Status:** Accepted for Phase 0

## Context

Vendor-specific hardcoded parser classes do not scale safely for broad perimeter telemetry onboarding. ULPF needs reusable format handling and controlled source-specific changes.

## Decision

Use trusted format adapters plus declarative, signed, versioned parser packs containing source profiles, extraction/mapping rules, tests, limits, and compatibility metadata.

## Alternatives considered

- Giant in-core vendor class hierarchy.
- Arbitrary user code plugins.
- Regex-only ungoverned configuration.

## Pros

Reduces core changes, improves reuse, permits fixture regression, approval, rollback, and replay.

## Cons

Requires registry tooling and cannot make every complex grammar no-code.

## Security implications

Packs are data, signed/authorized, bounded, and executed only by trusted isolated runtime components; no arbitrary code execution.

## Operational implications

Publication, revocation, compatibility, health, and drift monitoring become governed workflows.

## Consequences

New source onboarding normally creates/configures artifacts rather than modifies the core engine.
