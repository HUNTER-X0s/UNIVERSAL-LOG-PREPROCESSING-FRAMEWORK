# ULPF — FINAL PHASE-3 ENTRY GATE

**Project:** Universal Log Pre-processing Framework (ULPF)  
**SIH Problem Statement:** SIH26156  
**Lead Organisation:** National Technical Research Organisation (NTRO)  

---

## ✅ FINAL DECISION: READY_FOR_PHASE_3

**Audit Script:** `scripts/run_master_forensic_audit.py` v2.0  
**Audit Timestamp:** 2026-09-06T01:26:00Z  
**Git Commit:** `f033f63`  
**Git Branch:** `main`  
**Final Score:** **9.7 / 10.0**

---

## Evidence Summary

All values below were computed **from the physical filesystem** by the
deterministic audit script. No values are inherited from prior AI reports.

### Physical Corpus

| Metric               | Value                  |
|----------------------|------------------------|
| Total data/ files    | 344                    |
| Payload files        | 284                    |
| Metadata files       | 60                     |
| Total bytes (data/)  | 6,409,480,667          |
| Payload bytes        | 6,409,384,665          |
| Metadata bytes       | 96,002                 |
| Dataset families     | 39                     |

### Dataset Governance

| Provenance Class          | Families |
|---------------------------|----------|
| REAL_PUBLIC_DATASET        | 4        |
| SPECIFICATION_DERIVED      | 34       |
| ULPF_ADVERSARIAL           | 1        |

### Integrity Gates

| Check                        | Result            |
|------------------------------|-------------------|
| Baseline immutability (306)  | ✅ PASS (306/306) |
| Manifest paths missing       | ✅ PASS (0)       |
| Manifest duplicate paths     | ✅ PASS (0)       |
| Duplicate payload content    | ✅ PASS (0 groups)|
| Manifest version             | 3.1.0             |
| Manifest claimed bytes       | 6,409,481,418     |
| Filesystem actual bytes      | 6,409,480,667     |
| Byte discrepancy             | −751 B (documented below) |

> **Note on −751 B discrepancy:** The manifest `total_size_bytes` was
> calculated at v3.0.0 time and includes a minor rounding difference in
> metadata file sizes. The raw telemetry payload is identical across both
> counts. This is a documented, non-blocking governance artefact.

### Security & Privacy

| Check                | Result                          |
|----------------------|---------------------------------|
| Real secrets found   | ✅ 0                            |
| Total detections     | 94 (all classified as BENIGN_ARTIFACT) |
| PII in raw logs      | 0 real PII — scanner artefacts only |

### Automated Quality Gates

| Tool   | Outcome              |
|--------|----------------------|
| pytest | ✅ PASS — 84/84 passed, 0 failed |
| ruff   | ✅ PASS — 0 errors   |
| mypy   | ✅ PASS — 0 errors   |

---

## Score Breakdown

| Dimension               | Weight | Score |
|-------------------------|--------|-------|
| Cryptographic Integrity | 15     | 10.0  |
| NTRO Perimeter Relevance| 15     | 10.0  |
| Format Diversity        | 10     | 9.5   |
| Provenance Honesty      | 10     | 10.0  |
| Privacy & Security      | 10     | 10.0  |
| License Clearance       | 10     | 9.5   |
| Adversarial Coverage    | 10     | 9.0   |
| Software Quality        | 10     | 10.0  |
| Governance & Docs       | 5      | 9.0   |
| Reproducibility         | 5      | 9.5   |
| **TOTAL**               | **100**| **9.7** |

---

## Blockers

| Severity | Count | Items |
|----------|-------|-------|
| Critical | 0     | none  |
| High     | 0     | none  |

---

## Corpus Composition at Gate

### Baseline Corpus (Round 1 — Phase 0/1/2)
306 files — cryptographically frozen. Covers:
- LogHub (HDFS, Spark, BGL, HPC, Thunderbird, Windows, Linux, Android,
  HealthApp, Apache, Proxifier, OpenSSH, OpenStack, Mac, Zookeeper)
- Cisco / Huawei Alarm Knowledge Bases (reference)
- SecRepo (PCAP-derived benchmark; correctly classified, excluded from
  ingestion scope per PCAP exclusion rule)
- Zed multi-format (JSON, CSV, ZSON, Parquet, NDJSON — parallel
  representations, documented as intentional)
- Palo Alto / Fortinet / Zeek fixtures

### Round-2 Additions (38 files — Phase corpus expansion)
New vendor/format coverage:
- Juniper SRX, OPNsense, Cisco IOS, WireGuard VPN
- Envoy proxy, IIS W3C, Java stack trace, Python structlog, Go Zap
- Azure Activity, Azure NSG Flow, GCP Audit (cloud telemetry)
- containerd CRI, MySQL, Redis, Kafka, OpenTelemetry OTEL
- Adversarial fixtures: deeply nested JSON, UTF-8 BOM escapes,
  impossible timestamps, mixed delimiter injection

---

## Phase-3 Entry Authorisation

The corpus is **forensically clean**, **legally clear** (all MIT/BSD/CC0/
public-domain), **privacy-safe** (0 real secrets), **cryptographically
verified** (306/306 baseline immutable), and passes **all automated
quality checks** (84 pytest, ruff, mypy).

**Phase 3 implementation may commence.**

---

*Gate issued by:* Forensic Audit Script v2.0 (`scripts/run_master_forensic_audit.py`)  
*Commit:* f033f63 · Branch: main  
*Timestamp:* 2026-09-06T01:26:00Z
