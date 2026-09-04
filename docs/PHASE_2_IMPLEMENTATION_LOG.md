# Phase 2 Implementation Log

## Gap-Closure Session — 2026-09-04

### Reconnaissance findings

A second engineering session audited the partially-implemented Phase 2 repository
and found the core implementation substantially complete. Two functional gaps and
three pre-existing type-check issues were identified and resolved.

### Gaps found and resolved

| # | Area | Status before | Action |
|---|---|---|---|
| 1 | `tests/test_config.py` L26–40 | ❌ IndentationError (2 empty `with assertRaises` bodies) | Fixed: added `AppSettings.from_environment()` call; removed orphaned duplicate call |
| 2 | Golden/security/forensic tests (spec §49–56) | ❌ Missing | Created `tests/test_golden_fixtures.py` (54 new tests) |
| 3 | `listeners.py` mypy attr-defined on `AbstractServer.sockets` | ⚠ Pre-existing | Added `# type: ignore[attr-defined]` |
| 4 | `listeners.py` mypy arg-type on `create_task(Awaitable)` | ⚠ Pre-existing | Added `# type: ignore[arg-type]` |
| 5 | `pyproject.toml` mypy — `build/` dir caused duplicate-module error | ⚠ Pre-existing | Added `build/` and `tests/` to mypy `exclude` list |

### New test module: `tests/test_golden_fixtures.py`

Implements spec §49–56 with 54 deterministic tests across six suites:

- **`GoldenFixtureTests`** (12 tests) — exact byte + SHA-256 for text, CEF-like,
  JSON, XML, CSV, kv, binary, Unicode, CRLF, LF, empty, whitespace, large-valid,
  and duplicate fixtures.
- **`InvariantTests`** (9 tests) — formal property invariants: stored bytes == received
  bytes; hash reproducibility; oversized never silently truncated; rejected not stored;
  receipt_id present; transport metadata present; timestamp not fabricated from payload;
  capacity exhaustion explicit.
- **`SecurityPayloadTests`** (10 tests) — shell injection, SQL injection, XSS-like,
  path traversal, null bytes, invalid UTF-8, Unicode normalisation attack, very-long
  refusal, prompt-injection, deeply-nested JSON stored opaque.
- **`ForensicBytePreservationTests`** (10 tests) — full HTTP + LocalFile round-trip
  byte-compare and SHA-256 compare for text, CEF-like, JSON, binary, CRLF, Unicode,
  empty, whitespace, security strings, and LocalFile sink independent hash verification.
- **`HttpIntakeSupplement`** (7 tests) — acknowledgement status accuracy, required
  fields, binary content-type, no semantic leakage into ack, correlation propagation,
  exact boundary acceptance, and exact boundary refusal.
- **`FileFixtureSupplement`** (6 tests) — whole-file exact bytes, empty, CRLF-framing,
  LF-framing, Unicode, and oversized refusal.

### Final verification results

| Check | Result |
|---|---|
| `pytest tests/` | **84 passed, 0 failures, 0 errors, 13 subtests passed** |
| `ruff check .` | **All checks passed** |
| `mypy .` (source only, tests excluded per project convention) | **Success: no issues in 33 source files** |

### Phase 3 boundary

No parsing, normalization, enrichment, field extraction, or semantic interpretation
was introduced. Phase 2 remains a raw-capture-only boundary.


## Architecture reconciliation

- Read the frozen RawEvent contract and ADR-005 through ADR-009/ADR-013 before implementation.
- Kept `contracts/jsonschema` unchanged. The implementation projects receipts into the frozen RawEvent schema rather than creating a competing canonical model.
- Adopted `RawEventSink` and `SourceResolver` ports so adapters depend on raw capture rather than storage or future streaming details.
- Recorded the local-file sink as an explicitly bounded development/demo fallback. It does not amend ADR-005’s S3-compatible evidence-store decision.

## Implemented

- `ulpf_ingestion` raw envelope, capture service, SHA-256 receipt integrity, source-context interface, bounded metrics counters, and in-memory test sink.
- Bounded local evidence files with generated opaque IDs, atomic writes, byte-length/hash verification on retrieval, and no automatic eviction.
- HTTP raw endpoint, response acknowledgement, optional development-only retrieval, body/header limits, local rate boundary, optional static bearer-token comparison, and safe error taxonomy.
- Optional TCP LF-delimited listener, optional UDP datagram listener, and deterministic fixture-file adapter.
- Typed environment configuration, local Compose evidence volume, tests, and required Phase 2 documents.

## Explicitly not implemented

No source/vendor detection, Syslog/CEF/LEEF/JSON/XML/CSV/key-value parsing, field extraction, UCE mapping, enrichment, correlation, Kafka, object-storage client, database, search index, DLQ, replay, SIEM/lake integration, AI, or frontend workflow.

## Validation record

Focused local tests passed on Python 3.12.10:

- raw HTTP capture/retrieval, SHA-256, duplicate receipts, size/header/auth/rate refusal;
- local TCP and UDP loopback capture;
- fixture-file framing;
- configuration bounds and existing Phase 1 tests.

The completion report records the final full-suite result. No benchmark, container-runtime, air-gap, real-device, or production-security result is claimed without separate evidence.
