# ULPF Dataset Organization Plan (Phases 18 & 21)

**Document ID:** ULPF-DOC-DATA-004  
**Status:** PROPOSAL / AWAITING APPROVAL (Phase 21 Mandatory Stop)  
**Governing Phases:** Phase 12 (Raw vs Reference), Phase 13 (Design), Phase 18 (Plan), Phase 21 (Propose Before Modifying)  
**Audit Date:** 2026-09-05  

---

## 1. Architectural Authority & Mandatory Stop Rule

Per **Phase 21 (PROPOSE BEFORE MODIFYING)**:
> "After completing the audit, produce `docs/DATASET_ORGANIZATION_PLAN.md`. Then STOP before modifying dataset paths. The plan must clearly show CURRENT → TARGET → ACTION. Only after the plan is complete should you execute the reorganization."

Per **Phase 12 & 14 (DO NOT OVER-CLASSIFY)**:
> "Avoid unnecessary fragmentation. Preserve dataset relationships. Group into logical functional tiers without breaking provenance."

---

## 2. Current Structure Analysis & Deficiencies

The current repository layout under `data/` has four major governance defects:
1. **Space in Directory Name:** `data/fixtures/real_world/Zed data/` contains an unescaped space, which breaks POSIX shell scripts, CLI path arguments, and CI pipeline runners.
2. **Incorrect Domain Nesting:** `data/fixtures/real_world/luk/network/SecRepo/` places Mike Sconzo's 4.17 GB Bro/Zeek network flow logs inside `luk/` (which is Cisco/Huawei router/switch alarm knowledge).
3. **Collocation of Raw Inputs and Reference Ground Truth:** In `loghub/`, raw input logs (`Apache_2k.log`) sit side-by-side with ground-truth evaluation references (`Apache_2k.log_structured.csv`, `Apache_2k.log_templates_corrected.csv`).
4. **Collocation of Micro-Fixtures and Multi-Gigabyte Benchmarks:** The 2.59 GB `conn.log` and 1.32 GB `http.log` sit in `fixtures/real_world/` right alongside 140 KB test files.

---

## 3. Target Three-Pillar Architecture

We propose reorganizing `data/` into three functional, mutually non-interfering pillars:

```
data/
├── README.md                      <- Dataset Policy & Catalog Guide
├── DATASET_MANIFEST.json          <- Machine-readable canonical catalog
│
├── fixtures/                      <- TIER 1: Light Raw Inputs for Unit/Integration Tests (< 10MB)
│   ├── real_world/
│   │   ├── operating_system/      <- Loghub Linux, Mac (2k), Windows, Android
│   │   ├── application/           <- Loghub Apache, OpenSSH, Proxifier, HealthApp, Thunderbird
│   │   ├── distributed_system/    <- Loghub BGL, HDFS, Hadoop, HPC, OpenStack, Spark, Zookeeper
│   │   └── multi_format/
│   │       └── zed/               <- zeek-default, zeek-json, sup, bsup (renamed from 'Zed data')
│   ├── synthetic/                 <- Controlled generator outputs
│   └── adversarial/               <- Fuzzing, malformed syntax, injection tests
│
├── reference/                     <- TIER 1: Ground Truth & Knowledge Bases (Evaluation Only)
│   ├── loghub/
│   │   ├── structured/            <- *_structured.csv & *_structured_corrected.csv
│   │   └── templates/             <- *_templates.csv & *_templates_corrected.csv
│   └── alarm_knowledge/
│       ├── cisco/                 <- cs_routers_5k.json, cs_switch_5k.json, cs_wlan.json
│       └── huawei/                <- hw_routers_desc.json, hw_switch_desc.json, hw_wlan_desc.json
│
└── benchmarks/                    <- TIER 2 & 3: High-Volume / Scale Corpora (Git-Ignored)
    ├── secrepo/                   <- Relocated from luk/network/SecRepo (4.17 GB Bro/Zeek logs)
    └── scale/
        └── mac_full/              <- Mac.log (16.76 MB raw full capture)
```

---

## 4. Comprehensive Move & Action Mapping Table

| Item | Current Path | Proposed Target Path | Action | Rationale | Risk & Verification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `data/fixtures/real_world/Zed data/` | `data/fixtures/real_world/multi_format/zed/` | RENAME / MOVE | Eliminates forbidden space in dirname; preserves 4-format symmetry | Low. Verify 142 files, sizes, and SHA-256 unchanged. |
| 2 | `data/fixtures/real_world/luk/network/SecRepo/` | `data/benchmarks/secrepo/` | MOVE | Removes 4.17 GB benchmark logs from fixtures; corrects false nesting under `luk` | Low. Files already ignored in Git; preserves exact bytes and timestamps. |
| 3 | `data/fixtures/real_world/luk/Cisco/*.json` | `data/reference/alarm_knowledge/cisco/` | MOVE | Recognizes Cisco alarm templates as reference knowledge, not raw log streams | Low. Verify 3 JSON files and element counts (5k, 5k, 7.37k). |
| 4 | `data/fixtures/real_world/luk/Huawei/*.json` | `data/reference/alarm_knowledge/huawei/` | MOVE | Recognizes Huawei alarm descriptions as reference knowledge, not raw log streams | Low. Verify 3 JSON files and element counts (4.98k, 5k, 836). |
| 5 | `data/fixtures/real_world/loghub/Mac/Mac.log` | `data/benchmarks/scale/mac_full/Mac.log` | MOVE | 16.76 MB raw file exceeds test fixture budget; belongs in scale benchmark | Low. Sliced 2k version remains in fixtures. |
| 6 | `data/fixtures/real_world/loghub/<System>/*_2k.log` | `data/fixtures/real_world/<category>/<system>/` | ORGANIZE | Groups 2k raw log inputs into logical OS/App/Dist-Sys domains per Phase 13 | Low. Verify all 16 raw slices present. |
| 7 | `data/fixtures/real_world/loghub/<System>/*.csv` | `data/reference/loghub/<system>/` | SEGREGATE | Separates ground-truth parsing/templates from raw inputs per Phase 12 | Low. Verify all 66 CSV files match original hashes. |
| 8 | `data/fixtures/real_world/loghub/README.md` & `CITATION` | `data/reference/loghub/` | PRESERVE | Retains upstream academic attribution and license | Zero risk. |

---

## 5. Risk Assessment & Safety Guardrails

1. **Phase 2 Ingestion Safety:** Phase 2 intake components (`ulpf_ingestion`) do NOT hardcode any `data/fixtures` paths (they use in-memory inputs or `data/evidence`). Zero regression risk.
2. **Test Suite Safety:** The repository tests (`test_contracts.py`, `test_golden_fixtures.py`) use `tests/fixtures/contracts`, NOT `data/fixtures`. Zero test regression risk.
3. **Git History Safety:** No `git filter-branch`, `git reset --hard`, or destructive history rewrites will be performed. Moves will be recorded cleanly via standard filesystem operations.
4. **Byte Identity:** All moves preserve exact byte content. SHA-256 hashes will be verified before and after any physical relocation.

---

## 6. Execution Gate

**STOP:** Awaiting explicit user approval on this plan before executing any directory or file moves.
