# ULPF Phase 16 — SIH Final Evaluation & Judge Demo Guide

**Problem Statement:** Smart India Hackathon — SIH26156 / NTRO  
**Target Audience:** Technical Evaluation Panel & Senior Systems Evaluators

---

## 1. Quick Start (< 60 Seconds)

To reset the environment and run the full 10-stage live demonstration:

```bash
# 1. Reset demo state to clean baseline
python scripts/reset_final_sih_demo.py

# 2. Execute full 10-stage live evaluation
python scripts/run_final_sih_demo.py
```

The script will complete in under **1.0 second** and output the comprehensive report to:
`reports/phase16/SIH_FINAL_DEMO_REPORT.md`

---

## 2. Interactive 2-Minute Judging Walkthrough

When presenting to judges, follow this concise script:

| Timestamp | Stage Name | What to Highlight to Judges |
|---|---|---|
| **00:00 - 00:10** | **Heterogeneous Telemetry Challenge** | Point out the 6 distinct format families: Syslog, JSON, CEF, XML, Delimited CSV, and Cloud Audit. Show that ULPF does not assume a single format. |
| **00:10 - 00:25** | **Raw Ingestion & Fingerprinting** | Explain that raw bytes are hashed with SHA-256 immediately upon wire arrival before memory mutation. This guarantees legal evidence admissibility. |
| **00:25 - 00:40** | **Format & Vendor Intelligence** | Show `FormatDetector` and `SourceDetector` automatically inferring that the event is CEF from Palo Alto Networks without user intervention. |
| **00:40 - 00:55** | **UCE Normalization & Zero Data Loss** | Highlight `CanonicalEventBuilder`. Crucially show `unmapped_fields`: vendor-proprietary keys (`cs1`, `cs2`) are preserved rather than dropped. |
| **00:55 - 01:10** | **Standards Interoperability** | Demonstrate simultaneous dual projection to OCSF v1.1.0 (`class_uid=4001`) and OpenTelemetry Logs v1.0.0. Eliminates vendor lock-in. |
| **01:10 - 01:25** | **Tamper-Evident Evidence Lineage** | Show `EvidencePackageGenerator` generating a cryptographic manifest with individual item checksums and overall manifest SHA-256. |
| **01:25 - 01:40** | **MITRE ATT&CK Attack Correlation** | Walk through the automated correlation of T1110 (Brute Force) to T1078 (Valid Accounts) showing threat progression across stages. |
| **01:40 - 01:50** | **Unknown Onboarding & Drift** | Demonstrate `SchemaDriftDetector`. Show that when a vendor introduces a new field (`threat_category`), ULPF self-heals without breaking the pipeline. |
| **01:50 - 01:55** | **Air-Gap Sovereignty & AI Copilot** | Prove 100% offline air-gap execution (zero network egress). Show `AIAnalystCopilot` generating grounded 5W analytical summaries. |
| **01:55 - 02:00** | **NTRO Requirements Traceability** | Display the 16/16 requirements coverage matrix. Confirm all SIH26156 requirements are fully verified by reproducible code. |

---

## 3. Dedicated Verification Commands

To independently audit individual milestones:

```bash
# Multi-vendor normalization proof (Milestones A & B)
python scripts/run_phase16_corpus_and_multivendor.py

# Autonomous onboarding & schema drift (Milestones C, D & E)
python scripts/run_phase16_onboarding_and_drift.py

# Forensic superiority & security analytics (Milestones F, G & H)
python scripts/run_phase16_forensics_and_security.py

# Analyst productivity & competitive baseline (Milestones I, J, K & L)
python scripts/run_phase16_milestones_i_to_l.py

# Security isolation & air-gap verification (Milestones M, N, O & P)
python scripts/run_phase16_milestones_m_to_p.py

# Chaos resilience & NTRO traceability (Milestones Q, R, S & T)
python scripts/run_phase16_milestones_q_to_t.py

# Red team validation & claim governance (Milestones X, Y, Z & AA)
python scripts/run_phase16_security_and_governance.py
```
