# RUNBOOK-08: Cryptographic Evidence Integrity Breach

## 1. Trigger & Condition
**Condition:** SHA-256 manifest mismatch detected during forensic verification or backup drill.  
**Trigger:** CRITICAL ALERT: `CasePackageVerificationResult.is_valid == False` or manifest hash divergence.  

---

## 2. Diagnosis & Root Cause Identification
1. Quarantine affected case package or archive volume immediately.
2. Compare computed SHA-256 vs manifest SHA-256 for each event record.
3. Identify specific byte offsets containing alterations.
4. Check system access logs for unauthorized file modification.

---

## 3. Mitigation & Resolution Steps
1. Mark affected case package as `COMPROMISED_EVIDENCE` in audit trail.
2. Restore authentic copy from write-once read-many (WORM) secondary archive.
3. Notify security incident response team and generate forensic tampering report.

---

## 4. Verification & Health Restoration
Re-run `CasePackageManager.verify_package` on restored bundle to confirm `is_valid == True`.

---

## 5. Rollback & Post-Incident Safeguards
Retain corrupted byte image in forensic quarantine folder for hostile tampering investigation.

---
*ULPF SRE Runbook — Standard Operating Procedure (Phase 15)*
