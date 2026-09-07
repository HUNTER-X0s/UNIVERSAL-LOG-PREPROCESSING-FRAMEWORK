# Phase 7 Failover & Degraded Mode Controller

## Fault Tolerance Behavior
- Search index outage: Degrades search query capabilities while canonical intake and persistence continue.
- Relational store outage: Rejects incoming batches (fail closed); prevents false acknowledgments.
