# ULPF Dataset Expansion Baseline (Phase 1)

**Document ID:** ULPF-DOC-DATA-BASELINE-001  
**Timestamp:** 2026-09-05T13:45:00Z  
**Audit Scope:** Pre-expansion baseline snapshot of the frozen corpus  
**Governing ADRs:** ADR-001, ADR-004, ADR-008  

---

## 1. Baseline Summary

Prior to adding any new universal or perimeter telemetry fixtures, the audited repository baseline is frozen as follows:

- **Total Data Files:** 263
- **Total Payload Files:** 260
- **Total Byte Volume:** 6,409,386,968 bytes (~6,112.46 MB / 5.97 GB)
- **Top-Level Storage Directories:**
  - `data/fixtures/real_world/` (174 files, ~1,905.22 MB)
  - `data/reference/` (71 files, ~16.84 MB)
  - `data/benchmarks/` (14 files, ~4,190.40 MB)
- **Placeholder Fixtures:**
  - `data/fixtures/synthetic/.gitkeep` (38 bytes)
  - `data/fixtures/adversarial/.gitkeep` (40 bytes)
- **Manifest:** `data/DATASET_MANIFEST.json` (5,873 bytes)
- **Repository Policy:** `data/README.md` (1,469 bytes)

---

## 2. Baseline Inventory by Category

| Category / Family | Canonical Directory | File Count | Size (MB) | Role |
| :--- | :--- | :---: | :---: | :--- |
| **Operating System** | `data/fixtures/real_world/operating_system/` | 8 | 1.70 MB | Raw 2k slices (Android, Linux, Mac, Windows) |
| **Applications** | `data/fixtures/real_world/application/` | 10 | 1.49 MB | Raw 2k slices (Apache, HealthApp, OpenSSH, Proxifier, Thunderbird) |
| **Distributed Systems** | `data/fixtures/real_world/distributed_system/` | 14 | 2.29 MB | Raw 2k slices (BGL, Hadoop, HDFS, HPC, OpenStack, Spark, Zookeeper) |
| **Multi-Format Network** | `data/fixtures/real_world/multi_format/zed/` | 142 | 1,900.97 MB | 4 parallel format streams (TSV, JSON, SUP, BSUP) |
| **Alarm Knowledge Bases** | `data/reference/alarm_knowledge/` | 6 | 3.36 MB | Cisco (17,370 templates) & Huawei (10,816 descriptions) |
| **Loghub Ground Truth** | `data/reference/loghub/` | 66 | 13.48 MB | Structured CSVs & template dictionaries |
| **Network Security Benchmarks** | `data/benchmarks/secrepo/` | 13 | 4,174.41 MB | High-volume Bro/Zeek logs (conn.log 2.59GB, http.log 1.32GB) |
| **Scale Benchmarks** | `data/benchmarks/scale/mac_full/` | 1 | 15.99 MB | Full un-sliced Mac.log |
| **Metadata & Placeholders** | Root & fixtures subdirectories | 3 | 0.01 MB | Manifest, policy, gitkeeps |
| **TOTAL** | **Complete Frozen Baseline** | **263** | **6112.47 MB** | **Frozen Pre-Expansion State** |

---

## 3. Cryptographic Baseline Lock

All 263 files have been hashed with SHA-256. This snapshot serves as the immutable benchmark to ensure that future expansions:
1. Never alter or overwrite any pre-existing file bytes.
2. Never delete existing ground-truth reference data.
3. Preserve exact byte fidelity across the entire historical corpus.
