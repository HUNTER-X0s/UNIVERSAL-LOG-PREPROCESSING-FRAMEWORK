# RUNBOOK-15: Air-Gapped Release Update & Patch Procedure

## 1. Trigger & Condition
**Condition:** Deploying software updates or parser extensions into a strictly air-gapped sovereign environment.  
**Trigger:** Scheduled security patch or version update cycle.  

---

## 2. Diagnosis & Root Cause Identification
1. Build signed offline release bundle and dependency wheels on clean packaging workstation.
2. Generate cryptographic SHA-256 release manifest (`PHASE15_RELEASE_MANIFEST.json`).
3. Transfer bundle to read-only optical or cryptographically approved removable media.
4. Perform security virus/malware scan at air-gap transfer kiosk.

---

## 3. Mitigation & Resolution Steps
1. Mount media on target air-gapped host.
2. Verify release manifest SHA-256 signature against offline public key.
3. Install wheel packages: `pip install --no-index --find-links=/media/wheels <package>`.
4. Run `PlatformSelfDiagnostics` and `scripts/run_phase15_continuous_assurance.py`.

---

## 4. Verification & Health Restoration
Confirm zero network socket connections attempted during post-update execution.

---

## 5. Rollback & Post-Incident Safeguards
If verification fails, unmount media and restore previous verified wheel installation.

---
*ULPF SRE Runbook — Standard Operating Procedure (Phase 15)*
