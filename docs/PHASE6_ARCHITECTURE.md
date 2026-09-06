# ULPF Phase 6 Target Architecture

## Operational Production Telemetry Platform

Phase 6 wraps the validated canonical core of ULPF (Raw Intake -> Parser Runtime -> Canonical UCE -> Semantic Engine -> Governed Phase 5 Mapping -> Projections) with a resilient, observable, multi-tier operational data plane and decoupled control plane.

```
                         ┌───────────────────────┐
                         │ SOURCE SYSTEMS        │
                         │ FW / IDS / DNS / WAF  │
                         └──────────┬────────────┘
                                    │
                                    ▼
                         ┌───────────────────────┐
                         │ INGESTION ADAPTERS    │
                         │ HTTP / Syslog / File  │
                         └──────────┬────────────┘
                                    │
                                    ▼
                         ┌───────────────────────┐
                         │ BUFFER / STREAM LAYER │
                         │ Partitioned Stream    │
                         └──────────┬────────────┘
                                    │
                                    ▼
                         ┌───────────────────────┐
                         │ PROCESSING WORKERS    │
                         │ Graceful WorkerHost   │
                         └──────────┬────────────┘
                                    │
                                    ▼
                         ┌───────────────────────┐
                         │ PHASE 3               │
                         │ PARSE / NORMALIZE     │
                         └──────────┬────────────┘
                                    │
                                    ▼
                         ┌───────────────────────┐
                         │ CANONICAL UCE         │
                         │ Write-Once Canonical  │
                         └──────────┬────────────┘
                                    │
                                    ▼
                         ┌───────────────────────┐
                         │ PHASE 4 SEMANTICS     │
                         │ Classification & Graph│
                         └──────────┬────────────┘
                                    │
                                    ▼
                         ┌───────────────────────┐
                         │ PHASE 5 MAPPINGS      │
                         │ Governed Rules & DSL  │
                         └──────────┬────────────┘
                                    │
         ┌──────────────────────────┼──────────────────────────┐
         ▼                          ▼                          ▼
   OCSF PROJECTION            OTEL PROJECTION           INTERNAL CANONICAL
         │                          │                          │
         ▼                          ▼                          ▼
   ┌───────────┐              ┌───────────┐              ┌───────────┐
   │ SIEM SINK │              │ TELEMETRY │              │ STORAGE   │
   └───────────┘              └───────────┘              └─────┬─────┘
                                                               │
                                                               ▼
                                                         ┌───────────┐
                                                         │ SEARCH &  │
                                                         │ DATA LAKE │
                                                         └───────────┘
```

### Invariants Maintained
1. **Canonical UCE as Source of Truth**: Internal representation is invariant.
2. **Immutable Raw Evidence**: Zero in-place edits or destructive operations.
3. **Deterministic Semantics**: Zero online AI or nondeterministic logic in the hot path.
4. **Governed Mappings**: Human-in-the-loop activation gate with version pinning.
