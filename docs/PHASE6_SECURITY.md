# ULPF Phase 6 Security Architecture

## 1. Core Security Invariants
- **S1 (Zero Code Execution)**: No `eval()`, `exec()`, `pickle`, dynamic imports in data plane.
- **S2 (Zero Unauthorized Activation)**: Mappings require explicit human approval.
- **S3 (Zero Raw Mutation)**: Raw evidence is write-once and cryptographically verified.
- **S4 (Zero Silent Data Loss)**: Bounded queues reject or route to DLQ with audit events.
- **S5 (Zero Secret Leakage)**: Automatic redaction in logging and API responses.
- **S6 (Air-Gap Compliance)**: Zero external internet or cloud SaaS dependencies.
