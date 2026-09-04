# ADR-015: Test and Benchmark Evidence Strategy

**Status:** Accepted for Phase 0

## Context

SIH/demo pressure can encourage unsupported performance, vendor, or security claims. ULPF needs reproducible correctness, safety, failure, and performance evidence.

## Decision

Use a fixture-first test pyramid with versioned corpus provenance, unit/contract/integration/e2e/security/fuzz/recovery/air-gap/load tests, and reproducible benchmark manifests that record corpus, hardware, configuration, command/run ID, and raw measurements.

## Alternatives considered

- Manual demonstrations only.
- Synthetic benchmark numbers without run artifacts.
- Test only happy-path parser output.

## Pros

Truthful claims, regression protection, safer parser packs, repeatable demo/scale reasoning.

## Cons

Requires corpus curation, CI time, hardware access, and disciplined reporting.

## Security implications

Fuzzing, authorization, integrity, supply-chain, and air-gap tests expose high-risk failures before release.

## Operational implications

Benchmark tests are isolated/bounded and never silently run against sensitive production evidence.

## Consequences

If a capability is unmeasured or untested, documentation must call it planned rather than claim it works at a stated scale.
