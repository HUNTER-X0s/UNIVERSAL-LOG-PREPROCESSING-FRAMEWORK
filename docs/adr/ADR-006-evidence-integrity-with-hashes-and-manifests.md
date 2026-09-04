# ADR-006: Evidence Integrity with SHA-256 and Signed Manifests

**Status:** Accepted for Phase 0

## Context

ULPF needs tamper-evident evidence and chain-of-custody without adding unjustified operational complexity.

## Decision

Hash raw content with SHA-256 at receipt; record append-only evidence/audit records; create signed batch manifests that may contain Merkle roots for efficient batch verification. Do not use blockchain.

## Alternatives considered

- Blockchain ledger.
- Per-event signatures only.
- Storage immutability without cryptographic digest.

## Pros

Simple verification, offline operation, batch scalability, clear provenance, and fewer distributed-consensus dependencies.

## Cons

Key custody, manifest retention, and verification tooling must be operated correctly.

## Security implications

Digest mismatch blocks a verified claim and creates a security event; signing keys are protected outside source control.

## Operational implications

Manifest generation/checkpoints and periodic verification are observable; restore includes integrity verification.

## Consequences

Blockchain is not an innovation target; evidence integrity is shown through verifiable hashes/manifests and audit records.
