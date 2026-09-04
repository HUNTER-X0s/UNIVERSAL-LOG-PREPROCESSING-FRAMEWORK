# Contributing to ULPF

## Before coding

Read the relevant Phase 0 architecture documents, docs/ARCHITECTURAL_GUARDRAILS.md, docs/CODEX_EXECUTION_RULES.md, the requirements traceability matrix, and affected ADRs. Preserve UCE, frozen contract semantics, raw-evidence rules, air-gap operation, and parser safety boundaries.

## Development expectations

- Use a focused branch and keep each change reviewable.
- Do not commit secrets, local data, virtual environments, generated artifacts, or unlicensed datasets.
- Run python tools/ulpf.py verify before requesting review, and run the connected audit when the build environment permits it.
- Use conventional, imperative commit messages such as chore: establish ULPF Phase 1 foundation.
- Keep controllers and UI free of business logic; add business behavior only in its approved phase.

## Architecture changes

If code conflicts with an ADR, requirement, or frozen contract, stop implementation. Identify the conflict, review the linked decision, propose an ADR or amendment, update affected documentation/contracts/tests after approval, and only then implement. Never silently rename a domain, reinterpret UCE, or weaken an invariant.
