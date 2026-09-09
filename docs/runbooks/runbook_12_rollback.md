# RUNBOOK-12: Production Component Rollback Procedure

## 1. Trigger & Condition
**Condition:** Newly deployed release or parser causes unpredicted operational degradation.  
**Trigger:** SRE / Release manager decision following failed smoke test or SLO breach.  

---

## 2. Diagnosis & Root Cause Identification
1. Determine affected component scope (whole release, single package, or single parser).
2. Verify state store schema backwards-compatibility.
3. Ensure queue drain or pause active ingestion to prevent state divergence.

---

## 3. Mitigation & Resolution Steps
1. For parser regression: disable candidate parser in registry; promote fallback parser.
2. For release binary: switch systemd symlink to previous verified release: `ln -sfn /opt/ulpf-prev /opt/ulpf-active`.
3. Restart pipeline daemons and resume ingestion.

---

## 4. Verification & Health Restoration
Run 657-test regression suite to confirm restored baseline stability.

---

## 5. Rollback & Post-Incident Safeguards
Capture pre-rollback forensic core dump and memory snapshot before termination.

---
*ULPF SRE Runbook — Standard Operating Procedure (Phase 15)*
