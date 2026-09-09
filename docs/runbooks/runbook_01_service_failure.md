# RUNBOOK-01: Service / Process Crash or Unavailability

## 1. Trigger & Condition
**Condition:** Ingestion listener or core pipeline worker process terminates unexpectedly.  
**Trigger:** Systemd watchdog alert, Prometheus probe failure, or container exit code > 0.  

---

## 2. Diagnosis & Root Cause Identification
1. Identify terminated PID and reason from system journal (`journalctl -u ulpf-*`).
2. Inspect crash stack trace in `/var/log/ulpf/crash.log` or Windows Event Viewer.
3. Verify file descriptor and memory limits (`ulimit -a`).
4. If out-of-memory (OOM-killer), verify heap allocation in configuration.

---

## 3. Mitigation & Resolution Steps
1. Restart daemon process: `systemctl restart ulpf-worker`.
2. In high-availability mode, verify FailoverCoordinator transferred leases to surviving node.
3. Validate zero dropped partitions using `ulpf-diagnostics --check-leases`.

---

## 4. Verification & Health Restoration
1. Run platform health check: `python scripts/run_phase14_sih_demo.py --quick`.
2. Confirm listener port 514/TCP and 8080/TCP active and accepting records.

---

## 5. Rollback & Post-Incident Safeguards
If process fails repeatedly upon restart, rollback to previous release binary or container image.

---
*ULPF SRE Runbook — Standard Operating Procedure (Phase 15)*
