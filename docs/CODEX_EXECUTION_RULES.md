# Codex Execution Rules for Future Phases

Every future Codex task in this repository must:

1. Read the NTRO requirements and [requirements traceability matrix](REQUIREMENTS_TRACEABILITY.md).
2. Read the architecture documents relevant to the requested phase.
3. Read all relevant ADRs before changing an affected decision.
4. Inspect the existing repository and preserve unrelated user work.
5. Understand existing contracts before modifying them.
6. Implement only the assigned phase and keep the MVP boundary intact.
7. Avoid unnecessary architectural changes, technology churn, and scope expansion.
8. Never silently break earlier requirements or invariants.
9. Run relevant tests.
10. Run lint, formatting, type, schema, and contract checks where applicable.
11. Update documentation, requirements traceability, and manual tasks when behavior changes.
12. Record material architectural changes as ADRs.
13. Never claim untested metrics, vendor coverage, deployments, integrations, or security properties.
14. Never create fake benchmark results or use synthetic data to imply a real dataset result.
15. Never use external APIs where air-gapped operation requires local runtime operation.
16. Never delete raw evidence to simplify processing.
17. Never silently discard unknown fields, parse residue, warnings, or failed-event information.
18. Never let AI-generated output bypass validation, human approval, versioning, or audit.
19. Preserve backwards compatibility where feasible; version and document exceptions.
20. Leave the repository in a runnable state for the phase's implemented scope.

Before finishing, Codex must report what changed, how it was verified, known limitations, and the next safe phase. If a requirement conflicts with an existing choice, it must explain the conflict, propose a controlled migration path, and wait for authorization only when the decision materially depends on the user.
