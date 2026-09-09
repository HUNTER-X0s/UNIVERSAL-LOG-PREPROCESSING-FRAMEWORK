# ULPF Phase 15 — Release & Audit Index

This directory contains the authoritative machine-readable and markdown evidence artifacts generated for **ULPF Phase 15 (SIH26156 Final Certification)**.

## Reports Catalog

| Artifact | Type | Description | Verdict |
|---|---|---|---|
| `airgap_assurance_report.json` | JSON | Static AST check + dynamic runtime socket interception proof | `PASS` |
| `baseline_claims.json` | JSON | Formal claims regarding packages, parsers, and test coverage | `VERIFIED` |
| `baseline_git_state.json` | JSON | Baseline Git commit hash, branch, and tree state | `ANCHORED` |
| `baseline_inventory.json` | JSON | Enumeration of packages, concrete parsers, and tests | `20 PARSERS` |
| `baseline_metrics.json` | JSON | Verified quantitative baselines (EPS, latency, LOC) | `CONFIRMED` |
| `benchmark_evidence.json` | JSON | Multi-workload P50/P90/P99 latency and throughput evidence | `P99 < 0.1ms` |
| `clean_install_report.md` | Markdown | Isolated virtual environment installation verification | `PASS` |
| `continuous_assurance_phase15_fast.json` | JSON | Fast-path continuous assurance and anti-tampering scan | `0 FINDINGS` |
| `continuous_assurance_phase15_security.json`| JSON | Deep security and vulnerability assurance scan | `0 VULNS` |
| `controlled_chaos_report.json` | JSON | 8/8 chaos conditions, RTO/RPO metrics, and recovery logs | `8/8 PASS` |
| `forensic_lineage_report.json` | JSON | Bi-directional SHA-256 cryptographic lineage tracking | `13/13 STAGES` |
| `license_inventory.json` | JSON | Permissive software license auditing (MIT/Apache-2.0/BSD) | `100% COMPLIANT` |
| `ntro_traceability_matrix.json` | JSON | 16-point NTRO requirement traceability mapping | `16/16 VERIFIED` |
| `package_manifest.json` | JSON | SHA-256 hashes and file counts for 22 packages | `22/22 VERIFIED` |
| `PHASE15_BASELINE_ATTESTATION.md` | Markdown | Formal cryptographic baseline attestation certificate | `CERTIFIED` |
| `release_claims.json` | JSON | Release claims verification matrix | `VALIDATED` |
| `sbom.json` | JSON | CycloneDX-compatible Software Bill of Materials | `COMPLETE` |
| `sih_judge_mode_report.json` | JSON | Deterministic 10-scenario SIH Judge Mode evaluation | `10/10 PASS` |
| `standards_interoperability.json` | JSON | OCSF v1.1.0, OpenTelemetry, and CEF conformance | `COMPLIANT` |

## Cryptographic Sealing

All artifacts are deterministically generated from sovereign offline source code and verifiable via SHA-256 checksums.
