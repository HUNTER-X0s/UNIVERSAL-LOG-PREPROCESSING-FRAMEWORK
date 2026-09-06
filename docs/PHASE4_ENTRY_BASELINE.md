# ULPF Phase 4 Entry Baseline

**Recorded Date**: 2026-09-06  
**Status**: VERIFIED & AUDITED (READY FOR PHASE 4)  
**Lead Authority**: NTRO / ULPF Master Architecture Team

---

## 1. System & Environment Baseline

- **Operating System**: Windows 11 / Windows Server
- **Python Version**: `Python 3.12.10`
- **Git Commit**: `75d2ca8` (Branch: `main`)
- **Virtual Environment**: Active Python 3.12 runtime with zero third-party drift

---

## 2. Test & Quality Suite Baseline

- **Pytest Suite**: `pytest -q`
  - **Tests Passed**: 217 / 217 (100% PASS)
  - **Subtests Passed**: 13
  - **Failures / Errors**: 0
  - **Duration**: ~1.8s
- **Linter (Ruff)**: `ruff check .`
  - **Status**: Exit code 0 (`All checks passed!`)
- **Type Checker (Mypy)**: `mypy apps packages`
  - **Status**: Exit code 0 (`Success: no issues found in 71 source files` with `strict = true`)

---

## 3. Telemetry Corpus Forensic Baseline

- **Total Physical Files**: 344
- **Payload Files**: 284
- **Metadata Files**: 60
- **Total Physical Bytes**: 6,409,480,667 B (6.41 GB)
- **Baseline Immutability**: 306/306 golden hashes match exact SHA-256 cryptographic baseline.
- **Round-2 Additions**: 38 audited files.
- **Deduplication Audit**: 0 duplicate payload content groups.
- **Secrets & Privacy Audit**: 0 real secrets detected (94 benign synthetic test artifacts verified).
- **Master Forensic Audit Gate**: Score `9.7 / 10.0` (`READY_FOR_PHASE_3` / `READY_FOR_PHASE_4`).

---

## 4. Phase 3 Architecture & Runtime Baseline

- **Total Registered Parsers**: 20
- **Tier A Generic Parsers**: 10 (JSON, NDJSON, CSV, TSV, Key=Value, Syslog RFC 3164, Syslog RFC 5424, ArcSight CEF, IBM LEEF, XXE-safe XML, W3C Extended)
- **Tier B/C Specialized Parsers**: 10 (PAN-OS, FortiGate, Cisco ASA/IOS-XE, Suricata EVE, OPNsense filterlog, Snort fast alert, Web access NGINX/Apache, Zeek TSV/JSON, Cloud audit AWS/Azure/GCP, Linux Auditd)
- **Supported Formats**: 25 formats
- **Supported Vendors**: 31 vendors
- **Canonical Contracts**:
  - `contracts/jsonschema/normalized-event.v1.schema.json` (UCE v1.0.0)
  - `contracts/jsonschema/parsed-event.v1.schema.json`
  - `contracts/jsonschema/dlq-event.v1.schema.json`
- **Performance Benchmark Metrics**:
  - Throughput: 4,449 to 28,712 eps (SLA $\ge 1,000$ eps met across 100% of parsers)
  - Average Latency: 0.034 to 0.224 ms (SLA $< 1.0$ ms met across 100% of parsers)
  - Memory & Resource Bounds: Max record size 1MB, max nesting depth 30, max key pairs 2000.

---

## 5. Documented Phase 3 Operational Limits

1. **Nesting Bounds**: Payloads with object hierarchy depth $> 30$ are safely truncated to prevent stack overflow, accompanied by a `NESTING_LIMIT_EXCEEDED` warning.
2. **XXE Protection**: XML documents containing `<!DOCTYPE` or `<!ENTITY` declarations are strictly rejected via pre-scan validation to guard against Billion Laughs and XXE attacks.
3. **W3C Format**: Single-line W3C entries without an in-stream `#Fields:` directive fall back deterministically to standard IIS W3C header definitions.

---

## 6. Baseline Verification Decision

The Phase 3 baseline is completely intact, fully passing, cryptographically verified, and officially frozen. **Phase 4 implementation is authorized to begin.**
