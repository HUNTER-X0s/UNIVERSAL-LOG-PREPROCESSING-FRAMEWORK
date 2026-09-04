# Developer Runbook

## Prerequisites

- Git 2.54 or compatible
- Python 3.12 (required and locally verified)
- Docker or another OCI-compatible runtime only for the optional container check
- Internet access only for a controlled dependency/bootstrap update, never for API or worker startup

## Setup

~~~text
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.resolved.lock
.venv\Scripts\python.exe -m pip install -e . --no-deps --no-build-isolation
~~~

On POSIX, use .venv/bin/python instead of the Windows interpreter path. Copy .env.example only to a local ignored .env when a local environment loader is deliberately introduced; Phase 1 reads normal ULPF_ environment variables and needs no secret.

## Commands

| Goal | Cross-platform command |
| --- | --- |
| formatting check | python tools/ulpf.py format |
| lint | python tools/ulpf.py lint |
| static types | python tools/ulpf.py typecheck |
| contract validation | python tools/ulpf.py contracts |
| unit and contract tests | python tools/ulpf.py test |
| local security checks | python tools/ulpf.py security |
| Phase 1 architecture guard | python tools/ulpf.py architecture |
| documentation links | python tools/ulpf.py docs |
| package build | python tools/ulpf.py build |
| all local Phase 1 checks | python tools/ulpf.py verify |
| connected dependency audit | python tools/ulpf.py audit |
| API shell | python tools/ulpf.py dev |

The API health surface is at http://127.0.0.1:8080/api/v1/health. Readiness, liveness, metadata, and OpenAPI are under the same versioned prefix. No business endpoint exists.

## Troubleshooting

| Symptom | Safe action |
| --- | --- |
| configuration error at startup | compare non-secret ULPF_ variables to .env.example; do not paste secrets into logs or issues |
| Ruff or mypy unavailable | confirm the command uses the project virtual environment and install the pinned development tools in a controlled build |
| contract validation fails | do not edit schemas casually; inspect the named schema, fixture, ADR, and contract mapping documentation |
| Docker build needs packages | build in the controlled connected environment, retain approved artifacts, then transfer them according to the air-gap process |
| port 8080 unavailable | set a local process port when invoking Uvicorn; do not hardcode machine-specific settings into source |
