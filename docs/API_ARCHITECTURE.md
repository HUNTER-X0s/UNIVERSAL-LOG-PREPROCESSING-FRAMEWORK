# API Architecture

**Status:** Phase 0 contract design. Endpoints are planned, versioned HTTP interfaces; none are implemented by this document.

## API rules

- Base path: `/api/v1`. A major version changes only for incompatible public behavior.
- JSON request/response bodies use the versioned contracts in [`contracts/jsonschema`](../contracts/jsonschema/). OpenAPI becomes a Phase 1+ generated/curated artifact.
- Every request is authenticated; authorization is enforced per action, source, data classification, and export scope.
- Mutating requests require an idempotency key where retries could create duplicate objects, plus an audit event.
- Cursor pagination, bounded filters, field selection, sorting allowlists, request-size limits, and timeouts protect read paths.
- Server-side identifiers are opaque; callers cannot choose storage paths, artifact digests, audit records, or authorization claims.
- API errors use a stable envelope: `code`, `message`, `correlation_id`, `details` (safe), `retryable`, and an optional remediation hint. Raw evidence is never included in an error by default.

## Logical endpoint catalogue

| Resource | Method and path | Purpose | Authorization / idempotency / rate policy |
|---|---|---|---|
| Sources | `POST /sources`, `GET /sources`, `GET/PATCH /sources/{id}`, `POST /sources/{id}/activate` | Manage source profile/lifecycle | Parser Publisher/Admin; mutation idempotency; bounded admin rate |
| Samples | `POST /sources/{id}/samples`, `GET /samples/{id}` | Submit bounded onboarding sample and retrieve safely rendered analysis | Publisher; content scan/size limits; no raw sample export without evidence permission |
| Format detection | `POST /format-detections` | Create deterministic format/source-candidate analysis | Publisher; async/job response; per-user/source quota |
| Parsers | `POST /parsers`, `GET /parsers`, `GET /parsers/{id}/versions/{version}`, `POST /parsers/{id}/versions/{version}/approve|publish|revoke` | Govern parser-pack lifecycle | separated author/reviewer/publisher roles; all changes idempotent/audited |
| Mappings | `POST /mappings`, `GET /mappings/{id}`, `POST /mappings/{id}/versions/{version}/approve|publish` | Govern semantic mappings | same controlled publication policy |
| Schemas | `GET /schemas`, `POST /schemas`, `POST /schemas/{id}/versions/{version}/approve|publish` | Registry and compatibility lifecycle | Schema Admin; compatibility report required |
| Events | `GET /events`, `GET /events/{id}`, `GET /events/{id}/raw` | Search UCE, inspect event, request raw evidence subject to policy | Analyst/Auditor; evidence permission for raw; query rate/cost limits |
| Traceability/lineage | `GET /events/{id}/trace`, `GET /lineage/{id}` | Return event/field transformation trail | Analyst/Auditor; raw locators masked by classification policy |
| Replay | `POST /replay-jobs`, `GET /replay-jobs/{id}`, `POST /replay-jobs/{id}/cancel`, `GET /replay-jobs/{id}/comparison` | Controlled replay request and status | Replay permission, source/classification scope, quotas, approval policy |
| DLQ | `GET /dlq-events`, `GET /dlq-events/{id}`, `POST /dlq-events/{id}/retry|resolve` | Review, repair, and retry failures | Analyst for review; Publisher/Admin for remediation; audit mutation |
| Quality/drift | `GET /quality`, `GET /schema-drift`, `POST /schema-drift/{id}/triage` | Quality trends and governed drift handling | Analyst; triage requires Publisher/Admin |
| Enrichment | `GET /enrichment-packs`, `POST /enrichment-packs/import`, `POST /enrichment-packs/{id}/activate` | Manage optional local enrichment | Admin; signed bundle validation; no runtime Internet fetch |
| Analytics | `GET /analytics/aggregations`, `GET /timelines`, `GET /correlations` | Bounded, downstream-of-normalization analysis | Analyst; read/query cost limits |
| Audit | `GET /audit-events`, `GET /audit-events/{id}` | Governance and security trace | Auditor/Admin only; append-only read model |
| Health/metrics | `GET /health`, `GET /ready`, `GET /metrics`, `GET /airgap/status` | Service, dependency, and air-gap state | health is scoped; operational metrics require role/network policy |
| Identity | `GET /me`, `GET /roles`, OIDC token endpoints via local identity provider | Session/identity integration | delegated to offline-capable IdP; no custom password transport |

## Response and job behavior

Synchronous responses are appropriate only for bounded reads and validation. Long-running detection, testing, parser publication, imports, replay, and export work return `202 Accepted` with a `job_id`, status URI, correlation ID, immutable request parameters, and audit reference. Web clients poll with backoff or consume a local authenticated event stream; they do not infer success from a spinner.

## Authorization matrix

| Action | Viewer | Analyst | Auditor | Parser Publisher | Administrator |
|---|---:|---:|---:|---:|---:|
| Search normalized events | scoped | scoped | scoped | scoped | scoped |
| Retrieve raw evidence | no | policy-scoped | policy-scoped | policy-scoped | policy-scoped |
| Read audit | no | limited own actions | yes | limited own actions | yes |
| Create/edit drafts | no | no | no | yes | yes |
| Approve/publish/revoke parser/schema/mapping | no | no | no | separated reviewer/publisher policy | yes, subject to dual control where configured |
| Start controlled replay | no | request if granted | review | request/approve according to policy | yes |
| Configure security/air-gap/import bundles | no | no | audit only | no | yes |

## Contract and change policy

The raw, parsed, normalized, parser, mapping, schema, source, replay, DLQ, lineage, and audit contracts are published in `contracts/jsonschema`. An endpoint never returns a value with a different meaning merely to maintain a convenient UI. Changes require compatibility tests, release notes, versioning, and an ADR if they alter an architectural decision. API documentation must distinguish planned endpoints from measured integrations.
