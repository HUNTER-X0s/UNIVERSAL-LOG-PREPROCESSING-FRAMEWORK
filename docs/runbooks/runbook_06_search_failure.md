# RUNBOOK-06: Search Indexer / Index Cluster Degraded

## 1. Trigger & Condition
**Condition:** Downstream search cluster (Elasticsearch/OpenSearch/ClickHouse) slows or drops indexing.  
**Trigger:** Indexer backpressure signal activated; buffer queue rising.  

---

## 2. Diagnosis & Root Cause Identification
1. Check downstream cluster cluster health (`GET /_cluster/health`).
2. Check bulk thread pool rejections.
3. Check indexing disk watermarks (flood stage watermark).

---

## 3. Mitigation & Resolution Steps
1. Enable ULPF downstream backpressure rate limiter.
2. Spool excess normalized events to local disk buffer (`BoundedLatenessBuffer`).
3. Expand downstream search nodes or resolve shard allocation blocks.

---

## 4. Verification & Health Restoration
Validate zero event drops; drain spool queue at controlled throttle rate.

---

## 5. Rollback & Post-Incident Safeguards
Divert search index output to cold archive object storage until index cluster recovers.

---
*ULPF SRE Runbook — Standard Operating Procedure (Phase 15)*
