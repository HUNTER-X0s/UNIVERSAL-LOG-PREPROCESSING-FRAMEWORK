# Air-Gap Runtime Checklist

## Phase 1 classification

| Dependency or activity | Classification | Phase 1 evidence |
| --- | --- | --- |
| API shell, worker shell, Python standard library, installed pinned Python packages | MANDATORY OFFLINE | no runtime network client or startup fetch is implemented |
| local OCI image and Compose profile | MANDATORY OFFLINE | uses only local image/build inputs once artifacts are supplied |
| OpenAPI document and structured logs | MANDATORY OFFLINE | generated locally from the application shell |
| local OIDC, Kafka, PostgreSQL, MinIO, OpenSearch, local model bundles | OPTIONAL OFFLINE | architecture-defined future local services; not started in Phase 1 |
| package installation, pip-audit advisory lookup, image scan, SBOM creation | BUILD/UPDATE ONLY | connected controlled build step; results/artifacts travel through approved offline process |
| cloud AI, SaaS telemetry, public runtime APIs | NOT REQUIRED | not present in source, startup, or configuration |

## Pre-flight checklist for a future offline run

- Verify all OCI images, wheels, contracts, and configuration artifacts from approved local media.
- Inject secrets through the local deployment mechanism; do not create a source-controlled .env.
- Run the local verification command without network access.
- Confirm no application setting names a cloud endpoint or enables telemetry export.
- Record signatures, hashes, SBOM, license/provenance evidence, and operator approval with the bundle.

Phase 1 proves the absence of mandatory network behavior in its own shell. It does not claim a complete network-denied end-to-end ULPF runtime, which requires later data-plane components and an actual offline drill.
