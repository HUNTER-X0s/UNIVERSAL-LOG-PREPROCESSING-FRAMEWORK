# RUNBOOK-05: Metadata / State Database Unavailability

## 1. Trigger & Condition
**Condition:** State store (PostgreSQL or SQLite metadata store) becomes unavailable.  
**Trigger:** Connection refused on state store socket; metadata sync failure.  

---

## 2. Diagnosis & Root Cause Identification
1. Verify database service status (`systemctl status postgresql`).
2. Check connection pool exhaustion.
3. Check database disk space and lock contention.

---

## 3. Mitigation & Resolution Steps
1. Fail over to read-only replica or standby database instance.
2. Route in-flight state mutations to local write-ahead log (WAL) buffer.
3. Replay buffered WAL mutations once primary database recovers.

---

## 4. Verification & Health Restoration
Verify state table row counts and integrity hashes match WAL transaction ledger.

---

## 5. Rollback & Post-Incident Safeguards
Restore database state from latest continuous WAL archive or snapshot.

---
*ULPF SRE Runbook — Standard Operating Procedure (Phase 15)*
