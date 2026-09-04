# Implementation Roadmap

Phase 0 is architecture only. The following phases are an ordered implementation plan; their acceptance criteria must be satisfied with evidence before expanding scope. "Files/components" are planned locations from [REPOSITORY_ARCHITECTURE.md](REPOSITORY_ARCHITECTURE.md), not present code.

| Phase | Goal, inputs, and dependencies | Planned outputs / components | Contracts, tests, documentation, acceptance |
|---|---|---|---|
| 0. Architecture | NTRO brief, blank-repository audit | docs, ADRs, JSON Schema contracts | architecture review and Phase 0 report complete |
| 1. Foundation | Phase 0 approved; Git and team governance | monorepo skeleton, typed domain, config validation, local dev profile, CI baseline | contract validation, lint/type/test setup; developer guide; no product pipeline claim |
| 2. Ingestion | RawEvent contract, secure config | bounded collectors/intake, source registration, immutable raw evidence receipt | receipt/hash/size/retry tests; evidence handling docs; accepted event either persisted or explicitly rejected/audited |
| 3. Parsing | source profiles, parser contract, fixtures | format detection, safe format adapters, parser registry, ParsedEvent | parser unit/fuzz/regression/security tests; supported-format matrix; raw links and residue retained |
| 4. Schema and normalization | UCE, mapping/schema contracts | mapping engine, validation, UCE, OCSF first projection | contract/equivalence/type/lineage tests; mapping guide; deterministic pinned output |
| 5. AI intelligence | deterministic onboarding first | optional local proposal interface, confidence/explanation/version capture | offline/fallback/prompt-injection tests; AI capability statement; never production dependency |
| 6. No-code onboarding | source/parser/mapping lifecycle | sample analysis, review/approval/publish workflow | UX/API/authorization/regression tests; onboarding runbook; no auto-publish |
| 7. Streaming and processing | vertical path verified | durable transport, workers, retries/DLQ/backpressure/idempotency | integration/failure/order/duplicate tests; operational topic/runbook docs |
| 8. Storage and data lake | data model/retention policy | PostgreSQL metadata, MinIO evidence, OpenSearch projection, Parquet output | backup/restore/query/export tests; storage/lifecycle docs; separate data ownership verified |
| 9. Evidence and lineage | raw-to-UCE path working | integrity manifests, field lineage, trace/replay services | tamper/round-trip/replay comparison tests; forensic runbook; no historical overwrite |
| 10. Security | prior services and deployment profiles | OIDC/RBAC, isolation, secrets/TLS, signing/SBOM, air-gap import | threat/fuzz/authorization/supply-chain/air-gap tests; security review docs |
| 11. Frontend foundation | stable APIs/contracts | React/TypeScript shell, auth, navigation, API client, accessible states | component/contract/accessibility tests; UI guide |
| 12. Core UX | vertical capabilities | sources, event explorer/detail, raw-parsed-normalized trace, quality/DLQ/replay screens | end-to-end flows and authorization tests; UX flow evidence |
| 13. Cyber analytics | normalized/searchable data | bounded aggregations, timelines, optional enrichment/context | query correctness/data-origin tests; scope statement |
| 14. Interoperability | stable UCE/output artifacts | OTel/ECS/NDJSON/Kafka/Parquet adapters as justified | adapter contract/delivery/audit tests; integration manifests |
| 15. Testing and performance | corpus, hardware, repeatable environment | full test pyramid, load/stress/recovery suite, measured reports | benchmark artifacts with config/corpus/hardware; no synthetic results presented as measurements |
| 16. Hardening and submission | all selected MVP criteria | release bundle, restore/air-gap rehearsal, demo/video/slides, final documentation | security/restore/demo rehearsal evidence; formal scope/claim review and manual submission tasks |

## Critical path and parallelism

Critical path: contracts and foundation -> immutable evidence intake -> parser/normalization -> lineage/evidence trace -> stable APIs/UI -> integration/rehearsal. Frontend shell, test-corpus curation, deployment manifests, and optional AI research can begin in parallel after contracts stabilize. High-risk gates are parser safety, raw-evidence durability, schema/version discipline, air-gap packaging, and truthful performance measurement.

## Phase definition of done

No phase is complete until requirements are mapped, contract/data ownership is clear, authorization and failure behavior are implemented/tested, observability exists, deployment implications are documented, relevant lint/type/contract tests pass, and resulting documentation is updated. Phase owners must record material architectural changes in ADRs.
