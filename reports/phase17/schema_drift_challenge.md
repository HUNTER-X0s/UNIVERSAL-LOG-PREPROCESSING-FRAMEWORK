# Phase 17 Schema Drift Evolution Challenge

## 1. Multi-Stage Evolution Scenario
- **V1 Base Schema:** `{"src_ip", "dst_ip", "action", "bytes"}`
- **V2 Ingest (Attribute Expansion):** Vendor adds `tls_cipher` and `risk_score`.
  - *Engine Action:* Added fields detected; non-breaking; mapping updated to version `1.1.0`.
- **V3 Ingest (Breaking Renaming & Type Shift):** Vendor renames `src_ip` to `client_ip` and changes `bytes` to string `"8.2MB"`.
  - *Engine Action:* Renaming detected; type change flagged as `HIGH` behavioral impact; existing telemetry continues processing safely into `unmapped_fields` residue without pipeline panic.

## 2. Forensic Guarantees
- Raw bytes remain 100% lossless regardless of schema mutations.
- Historical replay using V1 mapping definitions produces identical original outputs.
