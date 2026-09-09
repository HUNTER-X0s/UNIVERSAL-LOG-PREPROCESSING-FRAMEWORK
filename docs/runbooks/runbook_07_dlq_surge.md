# RUNBOOK-07: Dead-Letter Queue (DLQ) Surge

## 1. Trigger & Condition
**Condition:** DLQ volume suddenly increases beyond standard baseline (> 100 eps).  
**Trigger:** SLO-DLQ warning alert; DLQ disk growth rate monitor.  

---

## 2. Diagnosis & Root Cause Identification
1. Group DLQ records by `failure_reason` and `source_id`.
2. Identify whether surge is caused by schema validation, parser crash, or intentional security payload.
3. Verify SHA-256 manifests on DLQ batches.

---

## 3. Mitigation & Resolution Steps
1. If unmapped source, isolate source to quarantine partition.
2. If transient mapping bug, apply patch via canary pipeline.
3. Execute DLQ replay once patch is certified: `ulpf-dlq --replay --batch-id <ID>`.

---

## 4. Verification & Health Restoration
Verify replayed events successfully normalize into UCE without re-entering DLQ.

---

## 5. Rollback & Post-Incident Safeguards
Quarantined records remain sealed in DLQ storage; no records are deleted without audit sign-off.

---
*ULPF SRE Runbook — Standard Operating Procedure (Phase 15)*
