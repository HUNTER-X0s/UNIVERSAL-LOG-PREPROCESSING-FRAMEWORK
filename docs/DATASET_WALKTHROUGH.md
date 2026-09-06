# ULPF Dataset Corpus Audit and Governance Walkthrough (Phase 51)

**Document ID:** ULPF-DOC-DATA-009  
**Status:** COMPLETE AUDIT  
**Audit Date:** 2026-09-05  

---

## 1. Audit Overview

In compliance with the **ULPF Dataset Corpus Audit, Organization & Validation Master Prompt**, a complete, non-destructive audit of the repository's data corpus has been executed.

### Key Metrics Verified:
- **Total Local Files:** 260 files
- **Total Data Volume:** 6,112.46 MB (~5.97 GB)
- **Exact Byte Duplicates:** **0 files** (Every file is unique content)
- **Tracked in Git:** 195 files (CSVs, JSONs, SUP, BSUP, Markdown)
- **Ignored in Git:** 65 files (Files blocked by generic `.gitignore: *.log`)

---

## 2. Discoveries & Governance Findings

1. **Zero Data Duplication:** A full SHA-256 cryptographic sweep verified that no byte-level duplication exists in the repository.
2. **Multi-Format Network Symmetry:** The `Zed data` directory (142 files, 1.9 GB) was proven to be 4 parallel format exports (`zeek-default` TSV, `zeek-json` JSON streaming, `sup` text, `bsup` binary LZ4) of the exact same WRCCDC 2018 network capture.
3. **Misplaced Benchmark Logs:** SecRepo's 4.17 GB Bro/Zeek logs (`conn.log` 2.59 GB, `http.log` 1.32 GB) were nested erroneously under `luk/network/SecRepo/`.
4. **Knowledge Bases Classified:** Cisco (17,370 alarm templates) and Huawei (10,816 alarm descriptions) were identified as reference knowledge bases rather than streaming log files.
5. **Gitignore Rectification Identified:** The blunt `*.log` rule in `.gitignore` suppressed small 2k test fixtures alongside multi-gigabyte logs.

---

## 3. Governance Artifacts Produced

The following comprehensive governance documents have been authored and added to `docs/`:
- `docs/DATASET_INVENTORY.md`: Authoritative file-level inventory across all families.
- `docs/DATASET_PROVENANCE.md`: Provenance, upstream URLs, DOIs, and citations for all sources.
- `docs/DATASET_STORAGE_POLICY.md`: Three-tier storage policy (Git, Local Benchmark, External Mount).
- `docs/DATASET_ORGANIZATION_PLAN.md`: Proposed target architecture and migration map.
- `docs/DATASET_SCORECARD.md`: 14-dimension rigorous scorecard (mean score: 7.7/10).
- `docs/DATASET_GAP_ANALYSIS.md`: Real vs theoretical gap analysis for NTRO perimeter focus.
- `docs/DATASET_RECOMMENDATIONS.md`: Prioritized candidate additions (Palo Alto, Fortinet, Suricata).
- `docs/DATASET_MANUAL_TASKS.md`: Clear separation of human-required tasks.
- `data/DATASET_MANIFEST.json`: Machine-readable canonical dataset manifest.
- `data/README.md`: Complete guide to local data policies and usage.

---

## 4. Phase 3 Consumption Guidelines

When Phase 3 (Parser & Normalization Plane) begins:
1. Load test fixtures exclusively from `data/fixtures/real_world/<domain>/`.
2. Evaluate parser accuracy and template extraction against `data/reference/loghub/<system>/`.
3. Use `data/reference/alarm_knowledge/<vendor>/` to populate vendor dictionary lookups.
4. Execute high-throughput stress tests against `data/benchmarks/secrepo/`.
