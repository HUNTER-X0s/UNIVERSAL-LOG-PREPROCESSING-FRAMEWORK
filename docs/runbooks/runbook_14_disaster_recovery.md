# RUNBOOK-14: Full Site Disaster Recovery (Cold Standby / Air-Gap)

## 1. Trigger & Condition
**Condition:** Primary datacenter or operations site completely unavailable.  
**Trigger:** Catastrophic site outage declaration by incident commander.  

---

## 2. Diagnosis & Root Cause Identification
1. Declare disaster recovery state and activate cold-standby hardware site.
2. Ensure network isolation and air-gap integrity at standby site.
3. Retrieve encrypted backup media from offsite vault.

---

## 3. Mitigation & Resolution Steps
1. Bootstrap base OS and Python 3.12 environment from signed offline media.
2. Restore ULPF packages, configuration, and state store from verified backup archive.
3. Redirect collector telemetry forwarding to standby site ingestion VIP.

---

## 4. Verification & Health Restoration
Execute 10-scenario SIH Judge Mode demo to verify full operational readiness.

---

## 5. Rollback & Post-Incident Safeguards
Calculate and record actual RTO (Recovery Time Objective) and RPO (Recovery Point Objective) in DR log.

---
*ULPF SRE Runbook — Standard Operating Procedure (Phase 15)*
