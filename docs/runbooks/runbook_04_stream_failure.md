# RUNBOOK-04: Stream / Partition Rebalance Disruption

## 1. Trigger & Condition
**Condition:** Partition consumer loses lease or stream buffer drops out of sync.  
**Trigger:** Lag accumulation across one or more stream partitions.  

---

## 2. Diagnosis & Root Cause Identification
1. Inspect `DistributedIngestionFabric` partition queue depth.
2. Identify stuck partition index.
3. Check worker lease heartbeat timestamps.

---

## 3. Mitigation & Resolution Steps
1. Trigger forced lease eviction for unresponsive worker: `ulpf-stream --evict-worker`.
2. Trigger partition rebalance across healthy active workers.
3. Verify committed offset resumption without rewind or message skip.

---

## 4. Verification & Health Restoration
Monitor partition consumption rate until lag returns to 0.

---

## 5. Rollback & Post-Incident Safeguards
Restart fabric in single-partition fallback mode if network partition prevents consensus.

---
*ULPF SRE Runbook — Standard Operating Procedure (Phase 15)*
