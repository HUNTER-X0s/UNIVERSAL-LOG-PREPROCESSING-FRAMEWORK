# ADR-001: ULPF Universal Canonical Event Model

**Status:** Accepted for Phase 0

## Context

ULPF must normalize heterogeneous perimeter telemetry while preserving raw evidence, source-native fields, field origin, and traceability. Directly making an external schema the internal model would leave evidence/provenance gaps.

## Decision

Adopt the versioned ULPF Universal Canonical Event (UCE) as the single internal canonical representation. It references immutable RawEvent evidence, retains unmapped fields, labels assertions as observed/inferred/enriched/derived, and pins parser/mapping/schema versions.

## Alternatives considered

- Direct OCSF, ECS, or OpenTelemetry as the internal representation.
- A vendor-specific object model per parser.
- Unstructured JSON after parsing.

## Pros

Lossless semantics, controlled evolution, replayability, field lineage, and adapter independence.

## Cons

UCE governance and adapters add schema/mapping work.

## Security implications

Evidence references, origin labels, and provenance reduce semantic spoofing and forensic ambiguity; raw evidence remains separately access-controlled.

## Operational implications

Readers, registries, tests, and outputs must declare schema versions and reject unsupported major versions explicitly.

## Consequences

Future implementation must treat UCE and its JSON Schema as the internal contract and use adapters for external standards.
