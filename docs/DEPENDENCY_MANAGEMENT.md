# Dependency Management

## Policy

Python 3.12 is the implemented and verified Phase 1 runtime. Direct dependencies are pinned in pyproject.toml and requirements.lock; the fully resolved Python 3.12 verification set is requirements.resolved.lock. The virtual environment is project-local and ignored. Runtime dependencies are intentionally limited to FastAPI, Pydantic, Uvicorn, and JSON Schema validation. Development-only tooling is separated into the dev dependency group.

| Dependency class | Direct packages | Purpose |
| --- | --- | --- |
| Runtime | FastAPI, Pydantic, Uvicorn, JSON Schema | API shell, typed settings/responses, local process serving, frozen contract validation |
| Development | HTTPX, Ruff, mypy, pip-audit | API test client, formatting/linting, static types, connected-build dependency audit |

No database client, broker client, object-storage client, search client, AI SDK, parser library, front-end package, or cloud SDK is introduced in Phase 1. This is intentional scope control.

## Reproducibility

Use a clean project-local virtual environment, install requirements.resolved.lock, then install the project without dependency resolution and build isolation. Connected builds must refresh and review requirements.lock and requirements.resolved.lock together before changing package versions.

The canonical offline-safe verification command does not query a package registry. The pip-audit command is intentionally a connected build/update check because vulnerability metadata is external; it is not a runtime dependency and must be recorded with an air-gap release bundle.

## Supply-chain rules

- Review each new direct dependency against an architectural need and air-gap consequence.
- Pin direct production dependencies; do not add floating production requirements.
- Run pip check locally and pip-audit in the connected CI path.
- Generate an SBOM in the controlled release/bundle workflow before an offline deployment claim.
- Record license evidence before redistribution. Third-party notices are not invented from memory.
