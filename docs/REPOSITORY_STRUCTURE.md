# Phase 1 Repository Structure and Boundaries

## Implemented structure

~~~text
apps/
  api/ulpf_api/              FastAPI composition root and foundation routes
  worker/ulpf_worker/        lifecycle shell only; no consumer implementation
  web/                       reserved React/TypeScript boundary, no UI implementation
packages/
  contracts/ulpf_contracts/  JSON Schema registry and API foundation models
  domain/ulpf_domain/        framework-independent identifiers and time primitives
  platform/ulpf_platform/    configuration, logs, correlation, errors, middleware
  parser-runtime/            reserved future boundary
  normalization/             reserved future boundary
  lineage/                   reserved future boundary
  integrations/              reserved future boundary
  observability/             reserved future boundary
contracts/jsonschema/        frozen Phase 0 source-of-truth contracts
config/                      tracked non-secret application configuration
deploy/                      API container and limited local Compose foundation
datasets/manifests/          provenance area; no external data downloaded
tests/                       unit and contract fixtures/tests
tools/                       cross-platform verification commands
docs/                        architecture and implementation records
~~~

## Module ownership and dependency direction

| Module | Responsibility and public interface | May depend on | Must not depend on | Future owner |
| --- | --- | --- | --- | --- |
| contracts | Load and validate frozen JSON Schemas; typed API envelopes | JSON Schema and Pydantic libraries | API, worker, data stores, frontend | schema/platform |
| domain | IDs, semantic versions, UTC primitives | Python standard library | web, persistence, FastAPI, Pydantic | core domain |
| platform | configuration, logging, correlation, errors, HTTP middleware | contracts and selected framework libraries | business/domain processing or data-plane clients | platform/security |
| api | application composition and versioned foundation routes | platform and contracts | frontend internals, parser/normalizer/evidence implementations | API/control plane |
| worker | process lifecycle and future task boundary | platform | queue consumer, parser, normalizer, storage client | worker/runtime |
| web | future contract-consuming UI | public HTTP/OpenAPI contracts only | backend package imports and direct stores | frontend |
| reserved packages | ownership boundary documentation only | none in Phase 1 | all runtime data-plane behavior | named future workstream |

Dependencies point inward: contracts and domain remain independent; applications compose platform and contracts; adapters and deployment are outer layers. A lightweight test prevents web/database framework imports in the domain package, and a static guard rejects selected data-plane libraries from Phase 1 code.

## Architectural-change process

If an implementation need conflicts with the frozen baseline: identify the conflict, read the affected ADR, propose and record an ADR or amendment, update contracts and linked documentation, then implement. No silent canonical-model, contract, or ownership change is permitted.
