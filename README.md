# ULPF - Universal Log Pre-processing Framework

**SIH26156 | National Technical Research Organisation (NTRO)**

This repository contains the frozen **Phase 0 architecture baseline** and a runnable **Phase 1 engineering foundation**. It deliberately contains no ULPF business pipeline implementation, deployed service, parser, benchmark result, or claimed integration.

ULPF is designed as a vendor-agnostic, lossless, traceable, air-gapped preprocessing fabric for heterogeneous perimeter-security telemetry. It preserves source evidence, extracts source-specific fields, creates a versioned ULPF Universal Canonical Event (UCE), and produces controlled interoperability projections for downstream SIEM, data-lake, analytics, and ML consumers.

## Start here

1. [Architecture overview](docs/ARCHITECTURE_OVERVIEW.md)
2. [Requirements traceability](docs/REQUIREMENTS_TRACEABILITY.md)
3. [Technology decisions](docs/TECHNOLOGY_DECISIONS.md)
4. [Architecture decision records](docs/adr/)
5. [Implementation roadmap](docs/IMPLEMENTATION_ROADMAP.md)
6. [Codex execution rules](docs/CODEX_EXECUTION_RULES.md)
7. [Phase 0 completion report](docs/PHASE_0_COMPLETION_REPORT.md)

The machine-readable Phase 0 contracts are under [`contracts/jsonschema`](contracts/jsonschema/). They remain authoritative design contracts; Phase 1 validates them but does not expose their business APIs.

## Phase boundary

Phase 0 is complete only when the architecture documents have passed the architecture review. Phase 1 may establish the repository skeleton and developer tooling; it must not bypass the contracts, ADRs, or architectural guardrails defined here.

No dataset, throughput, vendor-support, security-certification, or production-deployment claim should be inferred from this repository.

## Phase 1 status

**Implemented:** repository structure; Python API and worker shells; typed non-secret configuration; structured logging; correlation/error/safety middleware; health, readiness, liveness, metadata, and OpenAPI foundation; JSON Schema registry and fixtures; tests; lint/format/type/security/boundary/documentation/build checks; local OCI/Compose foundation; CI definition; developer and air-gap guidance.

**Planned / future:** all ULPF business capabilities, including ingestion, parsing, normalization, evidence persistence, Kafka, data stores, AI onboarding, replay, SIEM/data-lake adapters, and the React operational console.

## Quick start

Python 3.12 is the required and locally verified project baseline. The CI workflow is also configured for Python 3.12.

~~~text
python -m venv .venv
.venv\\Scripts\\python.exe -m pip install -r requirements.resolved.lock
.venv\\Scripts\\python.exe -m pip install --no-deps --no-build-isolation .
.venv\\Scripts\\python.exe tools\\ulpf.py verify
.venv\\Scripts\\python.exe tools\\ulpf.py dev
~~~

On POSIX, activate the virtual environment or replace the Windows interpreter path with `.venv/bin/python`.

The only implemented HTTP routes are under `/api/v1`: `health`, `readiness`, `liveness`, `metadata`, and generated OpenAPI. Their existence is a platform check, not an implementation of an ULPF workflow.

## Developer references

- [Developer runbook](docs/DEVELOPER_RUNBOOK.md)
- [Repository structure and module boundaries](docs/REPOSITORY_STRUCTURE.md)
- [Contract/type mapping](docs/CONTRACT_MODEL_MAPPING.md)
- [Dependency management](docs/DEPENDENCY_MANAGEMENT.md)
- [Air-gap runtime checklist](docs/AIRGAP_RUNTIME_CHECKLIST.md)
- [Phase 1 completion report](docs/PHASE_1_COMPLETION_REPORT.md)
- [Phase 2 handoff](docs/PHASE_2_HANDOFF.md)

## Security and air gap

No secret, private key, production log, restricted dataset, runtime cloud dependency, or hidden telemetry belongs in the repository. A connected build may download, scan, and bundle pinned artifacts; the runtime path must use approved local artifacts. See the air-gap checklist and security architecture before expanding the foundation.

