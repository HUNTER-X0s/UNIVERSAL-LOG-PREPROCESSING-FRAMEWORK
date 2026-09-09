# RUNBOOK-10: Disk Pressure / High Watermark Condition

## 1. Trigger & Condition
**Condition:** Disk capacity utilization exceeds 85% warning or 95% critical watermark.  
**Trigger:** Disk capacity alert; PlatformSelfDiagnostics reporting `DISK_PRESSURE`.  

---

## 2. Diagnosis & Root Cause Identification
1. Run `df -h` and `du -sh /var/log/ulpf/*` to locate high-growth directories.
2. Check DLQ volume, debug traces, and temporary spillover queues.
3. Verify age of retention tiers.

---

## 3. Mitigation & Resolution Steps
1. Compress and archive verified cold storage bundles to secondary tape/network storage.
2. Purge non-critical debug logs and ephemeral traces older than 7 days.
3. Ensure raw evidence and DLQ archives remain preserved and unmodified.

---

## 4. Verification & Health Restoration
Confirm available disk space returns above 25% safety margin.

---

## 5. Rollback & Post-Incident Safeguards
If local disk remains full, enable storage quota throttling on non-priority sources.

---
*ULPF SRE Runbook — Standard Operating Procedure (Phase 15)*
