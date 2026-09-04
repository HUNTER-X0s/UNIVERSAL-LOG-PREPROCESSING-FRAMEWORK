# ADR-016: No Blockchain for Evidence Integrity

**Status:** Accepted for Phase 0

## Context

Forensic integrity requires tamper evidence and chain-of-custody. Blockchain is often proposed but may add operational overhead without meeting a unique ULPF need.

## Decision

Use immutable evidence references, SHA-256 hashes, append-only audit records, signed batch manifests/Merkle roots, least-privilege storage, and verified export manifests. Do not introduce blockchain.

## Alternatives considered

- Permissioned blockchain.
- Public blockchain anchoring.
- Hash-only records without signed manifests/audit.

## Pros

Air-gap compatible, simpler operation, no consensus network, lower latency/cost, and clear offline verification.

## Cons

Trust is rooted in protected signing keys and storage/audit controls rather than distributed consensus.

## Security implications

Key protection/rotation, append-only behavior, retention locks where available, and verification procedures are mandatory.

## Operational implications

Manifest cadence, verification jobs, restore checks, and incident response are required but simpler than blockchain node operation.

## Consequences

ULPF's innovation claim centers on verifiable field/evidence lineage and governed parser lifecycle, not hype technology.
