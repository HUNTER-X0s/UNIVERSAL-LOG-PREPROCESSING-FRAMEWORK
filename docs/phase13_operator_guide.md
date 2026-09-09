# ULPF Phase 13 Operator Guide

**Audience:** Security Operations Center (SOC) Platform Engineers & Site Reliability Engineers  
**System Scope:** Telemetry Ingestion, Pipeline Monitoring, Schema Drift Management, and Packaging  

---

## 1. Pipeline Operation

ULPF runs as a sovereign, air-gapped log pre-processing service. Operators interact via the CLI or HTTP API.

### Common Operational Commands
- **Run Live SIH Showcase:**
  `python scripts/run_phase13_sih_showcase.py`
- **Run Pre-Phase-13 Master Audit:**
  `python scripts/run_phase12_pre_phase13_forensic_audit.py`
- **Run Phase 13 Final Certification Audit:**
  `python scripts/run_phase13_final_audit.py`
- **Run Full Regression Suite:**
  `python -m pytest tests/ -q`

---

## 2. Unknown Source Onboarding Lifecycle

When new log types are introduced:
1. **Upload Sample Batch:** Provide representative raw lines to `OnboardingService.onboard_sample_batch()`.
2. **Review Structural Profile:** Inspect discovered field inventory and type inferences.
3. **Inspect Mapping Diff:** View proposed field transformations and risk impact assessment.
4. **Approve & Activate:** Require authorized human reviewer sign-off to activate the mapping definition in production.

---

## 3. Schema Drift & Source Health Monitoring

- `SourceHealthMonitor` continuously calculates event velocity, error rate, and ingestion latencies.
- If schema drift is detected on an active stream, `SchemaDriftDetector.evaluate_severity()` classifies the change:
  - `INFORMATIONAL` / `LOW`: Safe additive new fields. Ingestion continues uninterrupted.
  - `HIGH` / `CRITICAL`: Field deletions or type mutations. Raw events remain lossless in storage; alerts flag operator review.
