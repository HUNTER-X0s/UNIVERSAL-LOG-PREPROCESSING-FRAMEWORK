# ULPF Duplicate & Redundancy Forensic Audit

**Document ID:** ULPF-DOC-DUPLICATE-FORENSIC-AUDIT  
**Corpus Version:** v3.1.0  

---

### 1. Hash Duplicate Analysis

Physical scan of all 344 files identified:
- **Total Duplicate Hash Groups:** 1 group (empty `.gitkeep` placeholder files used across directories).
- **Meaningful / Telemetry Duplicate Groups:** **0 (Zero)**.

### 2. Multi-Format Intentional Parallel Representations (BrimData Zed)

The Zed dataset represents the same underlying WRCCDC 2018 network capture across multiple serialization formats:
- `zeek-default/` (TSV)
- `zeek-json/` (JSON lines)
- `sup/` (Zed super-structured text)
- `bsup/` (Zed binary super-structured)

These parallel representations are **intentional benchmark fixtures** designed to evaluate parser efficiency across representations, and are not accidental duplicates.
