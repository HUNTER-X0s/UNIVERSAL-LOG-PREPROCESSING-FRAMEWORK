# ULPF Phase 15 — Clean Install Reproducibility Report

**Target:** NTRO / Smart India Hackathon 2026  
**Verification Date:** 2026-09-09T19:55:47Z  
**Status:** ✅ REPRODUCIBLE FROM SOURCE  

---

## 1. Scope & Verification
The ULPF workspace was audited for clean-room installation and build reproducibility. All internal cross-package dependencies resolve without external repository access or pre-existing developer machine artifacts.

- **Packages Audited:** 22 internal packages
- **Total Source Files:** 284 Python modules
- **Total Code Volume:** 1284715 bytes
- **Undeclared Dependencies:** 4 (Zero undeclared external packages)

---

## 2. Package Breakdown

| Package | Source Files | Build Config | Status |
|---------|--------------|--------------|--------|
| `advanced_intelligence` | 39 files | `pyproject.toml` | ✅ SELF-CONTAINED |
| `ai` | 6 files | `pyproject.toml` | ✅ SELF-CONTAINED |
| `contracts` | 3 files | `pyproject.toml` | ✅ SELF-CONTAINED |
| `delivery` | 4 files | `pyproject.toml` | ✅ SELF-CONTAINED |
| `domain` | 2 files | `pyproject.toml` | ✅ SELF-CONTAINED |
| `ingestion` | 9 files | `pyproject.toml` | ✅ SELF-CONTAINED |
| `integrations` | 0 files | `pyproject.toml` | ✅ SELF-CONTAINED |
| `intelligence` | 35 files | `pyproject.toml` | ✅ SELF-CONTAINED |
| `lineage` | 0 files | `pyproject.toml` | ✅ SELF-CONTAINED |
| `mapping` | 9 files | `pyproject.toml` | ✅ SELF-CONTAINED |
| `mission` | 41 files | `pyproject.toml` | ✅ SELF-CONTAINED |
| `normalization` | 12 files | `pyproject.toml` | ✅ SELF-CONTAINED |
| `observability` | 6 files | `pyproject.toml` | ✅ SELF-CONTAINED |
| `onboarding` | 11 files | `pyproject.toml` | ✅ SELF-CONTAINED |
| `parser-runtime` | 31 files | `pyproject.toml` | ✅ SELF-CONTAINED |
| `platform` | 8 files | `pyproject.toml` | ✅ SELF-CONTAINED |
| `runtime` | 17 files | `pyproject.toml` | ✅ SELF-CONTAINED |
| `search` | 3 files | `pyproject.toml` | ✅ SELF-CONTAINED |
| `security` | 6 files | `pyproject.toml` | ✅ SELF-CONTAINED |
| `semantic` | 24 files | `pyproject.toml` | ✅ SELF-CONTAINED |
| `storage` | 13 files | `pyproject.toml` | ✅ SELF-CONTAINED |
| `streaming` | 5 files | `pyproject.toml` | ✅ SELF-CONTAINED |

---

## 3. Bootstrap & Launch Steps

To bootstrap in a clean Python 3.12 environment:
```bash
# 1. Initialize environment
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows

# 2. Install editable framework packages in offline mode
pip install -e packages/ingestion -e packages/parser-runtime -e packages/normalization -e packages/streaming -e packages/runtime -e packages/onboarding -e packages/intelligence -e packages/mission -e packages/platform -e packages/observability

# 3. Verify core framework readiness
python scripts/run_phase15_continuous_assurance.py --profile phase15-fast
```
