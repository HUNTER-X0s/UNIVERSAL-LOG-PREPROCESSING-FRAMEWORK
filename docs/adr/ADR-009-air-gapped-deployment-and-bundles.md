# ADR-009: Air-gapped Deployment and Signed Offline Bundles

**Status:** Accepted for Phase 0

## Context

NTRO requires air-gapped deployability. Core processing cannot rely on public clouds, external SaaS, package registries, external AI APIs, or Internet availability.

## Decision

Operate local registries, identity, storage, broker, search, schema/parser/mapping catalogs, optional local models/enrichment, and offline administration. Import signed OCI/parser/schema/mapping/model/intelligence bundles via a controlled verify-before-activate flow.

## Alternatives considered

- Cloud-managed runtime with cached fallback.
- Unverified manual copy of artifacts.
- Air-gap support deferred after MVP.

## Pros

Meets the primary deployment constraint, reduces data exfiltration dependency, and supports reproducible update provenance.

## Cons

Offline artifact curation, key distribution, patch cadence, and capacity planning are more demanding.

## Security implications

Trusted signing keys, checksum/SBOM validation, malware scanning in a connected staging zone, and local policy enforcement are required.

## Operational implications

Bundle import/revocation, local registry health, dependency inventory, and transfer custody need runbooks and audit.

## Consequences

An online service may be optional for connected development but is not a dependency of the air-gapped runtime path.
