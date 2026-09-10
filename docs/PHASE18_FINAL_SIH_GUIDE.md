# ULPF — Final SIH Submission & Platform Guide

**Project:** Universal Log Pre-processing Framework (ULPF)  
**Hackathon:** Smart India Hackathon 2026 (SIH26156)  
**Target Organization:** National Technical Research Organisation (NTRO)  
**Release Tag:** `v1.0.0-sih`  

---

## 1. Executive Summary

The Universal Log Pre-processing Framework (ULPF) is a government/defense-grade security telemetry platform engineered to ingest, normalize, and cryptographically preserve heterogeneous cyber telemetry across 20 vendor formats.

Unlike conventional log collectors that drop unfamiliar fields or require weeks of custom regex scripting, ULPF delivers:
1. **Verifiable Lossless Ingestion:** verbatim byte capture into SHA-256 content-addressed immutable storage.
2. **Universal Canonical Event (UCE):** deterministic normalization preserving unmapped residue.
3. **Open Standards Interoperability:** simultaneous dual-projection to OCSF v1.1.0 and OpenTelemetry Logs v1.0.0.
4. **Autonomous Onboarding:** zero-code format profiling & mapping compilation in < 30 seconds.
5. **13-Stage Cryptographic Evidence Chain:** defensible Merkle lineage from raw byte receipt to SIEM delivery.
6. **Air-Gap Sovereignty:** 100% offline deterministic operation with verified zero socket egress.

---

## 2. Quickstart & Verification

```bash
# 1. Run Complete Test Suite (680 Tests)
pytest tests/ -q

# 2. Run Automated SIH 2-Minute Judge Evaluation Demo
python scripts/run_final_sih_demo.py

# 3. Reset Demo State
python scripts/demo_reset.py

# 4. Launch Government-Grade Operations Console
# Open apps/web/index.html in any modern browser
```
