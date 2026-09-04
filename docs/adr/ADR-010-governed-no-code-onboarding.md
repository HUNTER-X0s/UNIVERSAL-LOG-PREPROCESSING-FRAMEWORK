# ADR-010: Governed No-code Source Onboarding

**Status:** Accepted for Phase 0

## Context

ULPF must reduce parser development effort and provide plug-and-play onboarding without turning parser changes into unsafe, untested configuration.

## Decision

Provide a workflow for source creation, sample intake, format/structure analysis, candidate field mapping, confidence display, human editing, fixture/benchmark validation, approval, signed publication, activation, rollback, and audit.

## Alternatives considered

- Require core-code changes for every source.
- Auto-publish generated mappings.
- Allow unreviewed rule uploads directly to runtime.

## Pros

Speeds compatible-source onboarding while preserving versioning, safety, and ownership.

## Cons

Needs clear UX, validation infrastructure, and handling for formats beyond declarative packs.

## Security implications

Role separation, signed artifacts, sample sanitization, upload limits, and audit prevent unauthorized or unsafe activation.

## Operational implications

Onboarding maintains drafts and reports; activation is an explicit, observable state change with rollback.

## Consequences

No-code means configuration-driven where possible, not arbitrary untrusted code or bypassed testing.
