# RUNBOOK-11: Configuration Corruption / Schema Incompatibility

## 1. Trigger & Condition
**Condition:** Platform fails to start due to malformed YAML/JSON configuration or incompatible schema version.  
**Trigger:** Fatal error during `PlatformSelfDiagnostics.run_diagnostics` or startup configuration parse.  

---

## 2. Diagnosis & Root Cause Identification
1. Identify offending configuration file from startup traceback.
2. Run JSON/YAML schema validation against specification schema.
3. Run `git diff` against known-good configuration revision.

---

## 3. Mitigation & Resolution Steps
1. Revert corrupted configuration to last known-good revision from git or backup: `git checkout HEAD~1 config/`.
2. Validate configuration syntax with schema validator.
3. Restart service with validated configuration.

---

## 4. Verification & Health Restoration
Run `PlatformSelfDiagnostics` to confirm all configuration assertions pass.

---

## 5. Rollback & Post-Incident Safeguards
Keep invalid configuration copy in `/var/log/ulpf/invalid_config_<ts>` for defect triage.

---
*ULPF SRE Runbook — Standard Operating Procedure (Phase 15)*
