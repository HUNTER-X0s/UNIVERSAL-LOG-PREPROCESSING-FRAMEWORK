# ULPF Phase 6 Multi-Tier Storage Architecture

## 1. Storage Tiers
- **Raw Evidence Tier (`RawEvidenceRepository`)**:
  Stores immutable raw bytes using a partitioned directory structure: `raw/{date}/{source}/{hash_prefix}/{event_id}.raw`. Every read verifies the SHA-256 cryptographic digest to guarantee tamper detection.
- **Canonical UCE Tier (`UCERepository`)**:
  Stores canonical UCE payloads with write-once semantics. In-place mutation raises `PersistenceError`.
- **Semantic Event Tier (`SemanticEventRepository`)**:
  Stores enriched `SemanticEvent` records indexed by risk level, vendor, classification, and event fingerprint.

## 2. Cryptographic Integrity
Bit-rot and tampering are detected immediately upon retrieval via SHA-256 validation. Overwrites are strictly prohibited.
