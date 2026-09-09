# RUNBOOK-03: Storage / Evidence Volume Unavailability

## 1. Trigger & Condition
**Condition:** Underlying disk, NAS volume, or storage engine becomes read-only or unresponsive.  
**Trigger:** I/O error during raw payload write; SLO-EVID failure alert.  

---

## 2. Diagnosis & Root Cause Identification
1. Check mount status and dmesg for SCSI/disk errors.
2. Check available disk space (`df -h`).
3. Check inode exhaustion (`df -i`).

---

## 3. Mitigation & Resolution Steps
1. Immediately engage in-memory burst buffer and spool pending writes to temporary spool path.
2. Remount or attach spare storage volume.
3. Execute storage flush and re-verify SHA-256 digests against memory ledger.

---

## 4. Verification & Health Restoration
Run `ulpf_platform.diagnostics.PlatformSelfDiagnostics` to verify storage read/write integrity.

---

## 5. Rollback & Post-Incident Safeguards
If primary volume corrupted, initiate cryptographic disaster recovery from latest verified backup archive.

---
*ULPF SRE Runbook — Standard Operating Procedure (Phase 15)*
