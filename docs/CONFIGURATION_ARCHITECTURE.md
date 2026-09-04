# Configuration, Identity, and Supply-chain Architecture

## Configuration ownership

Configuration is versioned data, never hidden business logic. Every effective configuration has an identifier, version, content hash, owner, approval state, activation time, and audit record.

| Layer | Examples | Stored with | Runtime rule |
| --- | --- | --- | --- |
| Application | service ports, limits, feature flags | `config/application/` | Typed validation at startup; safe defaults only |
| Source | listener, source profile, timezone, classification | PostgreSQL governance metadata | Source-specific and auditable |
| Parser | format grammar, extraction, limits, test references | signed parser pack | Data only; no arbitrary executable content |
| Mapping | canonical paths, transforms, vocabularies | signed mapping pack | Test and approval before activation |
| Schema | UCE/projection schemas, compatibility rules | schema registry/bundle | Versioned and integrity-checked |
| Enrichment | local feed/version, field access, TTL | governance metadata + local bundle | Optional and separable from evidence |
| Security | RBAC policies, TLS references, export policy | protected deployment configuration | Least privilege, dual review for privileged changes |
| Deployment | image digests, resource limits, retention profile | `deploy/` + signed bundle manifest | Environment-specific values are explicit |

## Secrets and identities

Secrets are neither committed nor embedded in parser packs, logs, screenshots, test fixtures, or client bundles. A local secrets manager or protected orchestrator secret store provides database credentials, signing keys, TLS private keys, and bootstrap credentials. Development uses non-production test secrets only. Rotation, break-glass access, export, and revocation create audit events.

Planned roles are Administrator, Parser Publisher, Security Analyst, Auditor, and Viewer. RBAC is the MVP authorization model; attribute-based constraints can later restrict tenant, source, classification, evidence, and export access. Raw evidence and parser publication require distinct permissions.

## Supply-chain controls

- Pin dependencies and record lock files; generate an SBOM for every release bundle.
- Scan dependencies and OCI images in the connected build environment; record results rather than claiming zero vulnerabilities.
- Build signed OCI images by digest. Sign parser, schema, mapping, model, and threat-intelligence bundles separately.
- Verify trusted signatures, manifest hashes, compatibility, and authorization before offline installation.
- Reject unknown registries, unsigned privileged artifacts, and incompatible schema/parser combinations.
- Retain release manifests and approval/audit records so an air-gapped deployment can identify exactly what ran.

```mermaid
flowchart LR
  C[Connected controlled build] --> S[Pin, scan, test, create SBOM]
  S --> G[Sign OCI and content bundles]
  G --> T[Controlled transfer]
  T --> V[Offline verification]
  V --> R[Local registry and pack registry]
  R --> A[Approved activation]
```
