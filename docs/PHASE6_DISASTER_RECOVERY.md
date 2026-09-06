# ULPF Phase 6 Disaster Recovery & Business Continuity

## Recovery Priority
1. **Priority 1**: Raw Evidence Store (Forensic Source of Truth)
2. **Priority 2**: Canonical UCE Store (Analytical Truth)
3. **Priority 3**: Mapping Registry & Audit Logs (Governance Truth)
4. **Priority 4**: Search Index (Derived representation - can be rebuilt)

## Recovery Procedures
- **Index Rebuild**: Execute `search_adapter.rebuild_index(events)` from canonical storage.
- **Replay**: Execute historical replay with pinned mapping versions.
