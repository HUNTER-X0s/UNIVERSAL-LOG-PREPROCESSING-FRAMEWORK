# Phase 2 Handoff

## What Phase 1 provides

- `apps/api/ulpf_api`: FastAPI composition root and only foundation health/readiness/liveness/metadata endpoints.
- `apps/worker/ulpf_worker`: graceful lifecycle shell; it has no queue or task behavior.
- `packages/contracts/ulpf_contracts`: read-only access to frozen JSON Schemas and typed foundation envelopes.
- `packages/domain/ulpf_domain`: framework-independent identifiers and UTC primitives.
- `packages/platform/ulpf_platform`: configuration, structured logging, correlation, errors, and HTTP safety middleware.
- `tools/ulpf.py`: canonical local quality command; the CI workflow mirrors it on Python 3.12.

## Where to build ingestion

Phase 2 may add the smallest approved intake boundary beneath `apps/api` or an explicitly named ingress application. It must use the RawEvent schema through `ContractRegistry`, create no direct evidence-store bypass, preserve exactly received content once the evidence phase is introduced, and propagate request/correlation/trace IDs through its future worker handoff. It must not place transport or persistence behavior in `ulpf_domain`.

## Non-negotiable references

- `docs/ARCHITECTURAL_GUARDRAILS.md`
- `docs/REQUIREMENTS_TRACEABILITY.md`
- `docs/EVIDENCE_ARCHITECTURE.md`
- `docs/PARSER_ARCHITECTURE.md`
- `docs/SECURITY_ARCHITECTURE.md`
- ADR-001, ADR-003, ADR-005 through ADR-009, and ADR-013
- `contracts/jsonschema/raw-event.v1.schema.json` and `contracts/jsonschema/ulpf-common.v1.schema.json`

## Do not bypass

- Frozen JSON Schemas are authoritative; do not duplicate or casually edit them.
- Use typed configuration and never commit/inject secrets through code or logs.
- Use the standardized error and correlation model for externally reachable routes.
- Preserve the API/worker/domain/contracts dependency direction.
- Do not implement parser/normalizer, AI, Kafka, data-store, or SIEM behavior as part of an intake-only change unless the phase scope is explicitly amended.

## Intentionally unimplemented

All ULPF business pipeline stages and external integrations remain absent by design. Reserved package directories are ownership markers, not usable implementations. Tests currently prove only foundation invariants, contract validation, and API shell behavior.

## First Phase 2 checks

1. Read the applicable ADRs and Phase 0 contracts before making any intake design decision.
2. Decide whether the Phase 2 artifact boundary needs an ADR amendment; stop if it alters evidence-first semantics.
3. Add contract-driven tests before implementation, then run `python tools/ulpf.py verify`.
4. Record contract/traceability/manual-task changes honestly; do not claim source-format or throughput coverage without evidence.
