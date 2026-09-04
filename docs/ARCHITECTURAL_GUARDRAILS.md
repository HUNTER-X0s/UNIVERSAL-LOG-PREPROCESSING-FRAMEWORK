# Architectural Guardrails

These rules are binding for future ULPF phases unless a reviewed ADR explicitly changes a rule without violating NTRO requirements.

1. No feature may violate the NTRO requirement traceability matrix or the product boundary.
2. An accepted raw event is never silently discarded, overwritten, truncated, or mutated.
3. Every normalized event links to raw evidence, its verification material, and versioned processing artifacts.
4. Every security-meaningful field declares whether it is observed, inferred, enriched, or derived.
5. Unrecognized fields and parse residue remain recoverable; a clean-looking projection cannot erase them.
6. Every parser, mapping, schema, source profile, enrichment pack, contract, and model/prompt/template that changes meaning is versioned.
7. Parser/schema/mapping changes require fixtures, compatibility checks, approval, audit, and controlled rollback/replay paths.
8. AI is advisory until explicitly validated and approved; it cannot mutate evidence, publish parsers, execute code, or bypass safety controls.
9. The core air-gapped runtime has no required Internet, SaaS, cloud API, or external-model dependency.
10. Log content is data, not code. No shell/eval/dynamic import/path/URL from a log may execute with platform privileges.
11. All critical failures are explicit, observable, and routed through bounded retry/DLQ/quarantine/replay behavior.
12. Security boundaries are explicit: input, evidence, control plane, identity, output/export, parser sandbox, bundle/import, and administrative boundaries.
13. Secrets, private keys, proprietary logs, personal data, and unlicensed datasets never enter source control.
14. All data access, evidence retrieval/export, configuration activation, replay, and privileged changes are authorized and auditable.
15. Performance, vendor compatibility, scale, security, dataset, integration, and deployment claims require documented measured or verified evidence. Never invent them.
16. Dataset licenses, provenance, versions, transformations, and restrictions are documented before use.
17. Controllers/UI code must not contain business logic or bypass domain contracts; no magic constants, silent fallbacks, or unvalidated external input.
18. Architecture favors modular, typed, testable, secure-by-default, configuration-driven, schema-driven, observable, documented, and maintainable design over premature abstraction.
19. Backward compatibility is preserved where feasible; breaking change requires semantic versioning, migration plan, compatibility evidence, and ADR.
20. Each phase ends in a runnable/testable state for its declared scope, with documentation and release artifacts consistent with reality.
