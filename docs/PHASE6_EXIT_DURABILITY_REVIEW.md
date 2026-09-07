# ULPF Phase 6 Durability Review

**Date:** 2026-09-06T20:58:53.020333+00:00  
**Scope:** Raw evidence persistence, canonical UCE write-once guarantees, and crash recovery.

---

## 1. Raw Evidence Durability
- `FilesystemRawEvidenceRepository` stores raw bytes to local disk organized by date, source, and SHA-256 hash prefix.
- Written records survive process restarts and can be independently verified with `verify()`.

## 2. Canonical UCE & Semantic Storage Durability
- `MemoryUCERepository` and `MemorySemanticEventRepository` provide in-memory reference implementations.
- Write-once immutability is strictly enforced.
- Process restart loses in-memory UCE state; historical replay from raw filesystem store can rebuild canonical state.
- Production multi-node deployments in Phase 7 will wrap these interfaces with durable SQL/NoSQL backends.
