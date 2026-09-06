# ULPF Phase 6 Search & Analytics Adapter

## 1. Structured Indexing
Indexes high-value normalized fields (vendor, product, event type, severity, action, result, risk level, fingerprint, entity, indicator). Arbitrary vendor fields are preserved in residue but do not create index explosion.

## 2. Query Safety & Limits
- Hard upper bound on result sets (`limit <= 1000`).
- No raw arbitrary backend query DSL execution.
- Negative offset rejection.

## 3. Disaster Recovery Index Rebuild
The index is a derived artifact. In case of index corruption or disaster recovery, `rebuild_index()` safely repopulates the index from the canonical `SemanticEvent` and `UCE` repositories.
