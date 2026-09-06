# ULPF Dataset Storage and Version Control Policy

**Document ID:** ULPF-DOC-DATA-003  
**Status:** APPROVED / GOVERNANCE  
**Governing ADRs:** ADR-001 (Architecture Guardrails), ADR-004 (Bounded Memory & Loss Awareness)  
**Audit Date:** 2026-09-05  

---

## 1. Principle of Repository Hygiene

The ULPF Git repository must remain agile, cloned quickly, and free of massive binary blobs or multi-gigabyte production captures. At the same time, deterministic automated tests and contract validations require reproducible, version-controlled fixtures.

To achieve this balance, ULPF strictly enforces a **Three-Tier Storage Policy**:

```
┌─────────────────────────────────────────────────────────────┐
│ TIER 1: VERSION CONTROLLED (GIT)                            │
│ Max File Size: < 10 MB per file                             │
│ Path: data/fixtures/, data/reference/, tests/fixtures/      │
│ Contents: 2k log slices, ground-truth CSVs, manifests       │
├─────────────────────────────────────────────────────────────┤
│ TIER 2: LOCAL BENCHMARK CORPUS (GIT-IGNORED / ON-DEMAND)    │
│ Size Range: 10 MB to 500 MB                                 │
│ Path: data/benchmarks/                                      │
│ Contents: Multi-format Zed logs, medium PCAP/log traces     │
├─────────────────────────────────────────────────────────────┤
│ TIER 3: EXTERNAL HIGH-VOLUME DATA ROOT (EXTERNAL MOUNT)     │
│ Size Range: > 500 MB (Gigabyte / Terabyte scale)            │
│ Path: Configured via ULPF_DATA_ROOT or dedicated mount      │
│ Contents: SecRepo 4.2GB logs, full PCAP, enterprise flows   │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Storage Tier Rules

### Tier 1: Version Controlled Fixtures (< 10 MB)
- **Permitted in Git:**
  - Curated unit/integration test fixtures (`data/fixtures/real_world/` slices under 2,000 lines).
  - Ground truth structured CSVs and template dictionaries (`data/reference/`).
  - Contract schemas, manifest JSONs, and documentation.
- **Strict Prohibition:**
  - No uncompressed multi-megabyte log dumps.
  - No production credentials, internal IP spaces, or classified payload evidence.

### Tier 2: Local Benchmark Corpus (10 MB – 500 MB)
- **Storage Location:** `data/benchmarks/`
- **Git Policy:** Git-ignored by directory rule.
- **Distribution:** Downloaded or hydrated via scripted manifest (`scripts/fetch_benchmarks.py`).
- **Use Case:** Local throughput benchmarks, parser stress tests, memory allocation benchmarks.

### Tier 3: External High-Volume Data Root (> 500 MB)
- **Examples in Current Repo:**
  - `SecRepo/conn.log` (2.59 GB)
  - `SecRepo/http.log` (1.32 GB)
  - `Zed/sup/conn.sup` (612 MB)
- **Policy:**
  - These files MUST NEVER be committed to Git.
  - They reside in a dedicated external data root or local disk path outside the standard repository tree.
  - Tests consuming Tier 3 data must feature `@pytest.mark.benchmark` or `@pytest.mark.scale` skips when the external files are absent.

---

## 3. Gitignore Remediation

The initial repository `.gitignore` contained a broad rule:
```gitignore
*.log
```
While this prevented the 4.17 GB SecRepo logs from entering Git, it inadvertently hid the 16 small 2k test fixtures (`Apache_2k.log`, `Linux_2k.log`, etc.) and Zeek default logs.

### Remediated Policy in `.gitignore`:
```gitignore
# Ignore high-volume benchmark and external data
data/benchmarks/
data/evidence/
data/runtime/
data/tmp/

# Ignore large log files (> 10MB) specifically
*.log.gz
*.pcap

# Explicitly track curated test fixtures
!data/fixtures/**/*.log
```
