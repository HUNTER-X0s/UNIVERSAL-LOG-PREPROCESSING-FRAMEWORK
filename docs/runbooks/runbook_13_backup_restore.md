# RUNBOOK-13: Backup & Restore Verification Drill

## 1. Trigger & Condition
**Condition:** Routine or emergency restoration of configuration, schemas, and evidence repositories.  
**Trigger:** Scheduled monthly recovery drill or disaster restoration requirement.  

---

## 2. Diagnosis & Root Cause Identification
1. Identify latest verified backup archive in backup repository.
2. Verify SHA-256 archive manifest before unpacking.
3. Prepare isolated clean-room staging directory for restoration test.

---

## 3. Mitigation & Resolution Steps
1. Execute restore runner: `python -m ulpf_platform.backup_restore --restore <archive> --target <dir>`.
2. Verify database records, schema registry files, and raw evidence checksums match manifest exactly.
3. Confirm zero byte data loss.

---

## 4. Verification & Health Restoration
Validate restored system by executing end-to-end ingestion and normalization test.

---

## 5. Rollback & Post-Incident Safeguards
If archive manifest fails verification, reject archive and fail over to previous signed backup.

---
*ULPF SRE Runbook — Standard Operating Procedure (Phase 15)*
