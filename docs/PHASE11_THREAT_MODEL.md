# Phase 11 — Threat Model & Attack Surface Analysis

**Project:** Universal Log Preprocessing Framework (ULPF)  
**Mission:** NTRO / Smart India Hackathon &mdash; SIH26156  
**Scope:** Complete End-to-End System (Phases 0–10 Frozen Baselines)  
**Methodology:** STRIDE + Trust Boundary Matrix + Attack Tree Modeling  

---

## 1. System Assets & Criticality Matrix

| Asset Class | Assets | Criticality | Security Properties Required |
|-------------|--------|:-----------:|------------------------------|
| **Raw Evidence** | Ingested raw log bytes, file chunks, sidecars | **CRITICAL** | Confidentiality, Integrity, Immutability, Proof of Origin |
| **Canonical Telemetry** | Universal Canonical Events (UCE), normalized fields | **CRITICAL** | Write-Once Immutability, Schema Conformance, Determinism |
| **Semantic Intelligence** | Classified events, entity graphs, indicators | **HIGH** | Lineage Traceability, Tenant Isolation, Explainability |
| **Detections & Cases** | Correlated alerts, campaign graphs, investigation cases | **HIGH** | Tamper-Evidence, RBAC Governance, No Dangling Refs |
| **Cryptographic Material** | JWT signing keys, TLS certs, HMAC salts | **CRITICAL** | Secrecy, Controlled Rotation, Zero Exposure in Logs |
| **System Governance** | Detection rules, DSL mappings, SOAR playbooks | **HIGH** | Versioned Approvals, Dry-Run Guardrails, Sandboxed Exec |
| **Operational State** | Pipeline queues, health state machine, metrics | **MEDIUM** | Availability, Resilience under DDoS / Alert Storms |

---

## 2. Threat Actor Profiles

1. **Unauthenticated External Attacker:** Probes network intake interfaces (Syslog, HTTP, TCP/UDP), attempts parser crashes, ReDoS, injection attacks, and resource exhaustion.
2. **Authenticated Low-Privilege User (`viewer`):** Attempts horizontal privilege escalation to view other tenants' telemetry or cases, or vertical escalation to trigger SOAR actions or modify detection rules.
3. **Malicious / Compromised Data Source:** Emits malformed framing, oversized payloads, nested bomb structures (JSON/XML), spoofed timestamps, or baseline poisoning traffic.
4. **Malicious Insider / Rogue Operator:** Attempts unauthorized evidence tampering, deletion of UCE audit records, or bypass of SOAR safety guardrails.
5. **Hostile AI Adversary:** Injects adversarial prompt overrides (`IGNORE PREVIOUS INSTRUCTIONS`, `SYSTEM PROMPT OVERRIDE`) into log payloads or TI feeds to manipulate the offline analyst copilot.

---

## 3. Trust Boundaries & Control Architecture

```
[ UNTRUSTED ZONE ]                 [ TRUST BOUNDARY 1: INTAKE ]
Network / Sockets / Files    ───>  Framing, Encoding & Size Clamping (Max 2MB)
                                                │
                                   [ TRUST BOUNDARY 2: PARSER ]
Raw Bytes                    ───>  Safe AST-Free Parsers (11 formats), ReDoS Protection
                                                │
                                   [ TRUST BOUNDARY 3: CANONICAL STORAGE ]
Parsed Record                ───>  SHA-256 Digest & Immutable Append-Only Storage
                                                │
                                   [ TRUST BOUNDARY 4: RBAC & TENANCY ]
API / Query / Search         ───>  Cryptographic Token / mTLS + Tenant Partition Filter
                                                │
                                   [ TRUST BOUNDARY 5: SOAR DISPATCH ]
Automated Actions            ───>  Strict Whitelist + Human In-The-Loop Dry-Run Mode
```

---

## 4. STRIDE Threat Analysis & Mitigation Verification

### 4.1 Spoofing (Identity & Source)
- **Threat:** Attacker forges JWT identity or injects spoofed tenant ID.
- **Controls:** Cryptographic signature verification (HMAC-SHA256), strict claim parsing (`sub`, `iss`, `aud`, `exp`, `nbf`), and tenant claim binding directly from token context.
- **Verification:** Unit and adversarial tests in `tests/security/test_phase11_security.py`.

### 4.2 Tampering (Evidence & Logs)
- **Threat:** Attacker attempts post-write modification of raw evidence files or UCE records.
- **Controls:** SHA-256 integrity verification, write-once file permissions, and cryptographic manifest generation for evidence packages.
- **Verification:** Proof in `tests/evidence/test_phase11_evidence_integrity.py`.

### 4.3 Repudiation
- **Threat:** Operator denies executing an action or investigation modification.
- **Controls:** Immutable security audit logging with chained cryptographic provenance hashes for all state mutations.

### 4.4 Information Disclosure (Tenant Leakage & Exfiltration)
- **Threat:** Tenant A accesses Tenant B's events, cases, or search indices.
- **Controls:** Multi-tenant query isolation enforced at storage repository and search adapter layers (`WHERE tenant_id = ?`).
- **Air-Gap Guarantee:** Zero outbound internet sockets prevent data exfiltration.

### 4.5 Denial of Service (Parser & Engine Flooding)
- **Threat:** Algorithmic complexity attacks (ReDoS, XML entity expansion, deep JSON recursion, unbounded graph BFS).
- **Controls:** Hard input size limits (<=2MB), bounded recursion depth (<=10), strict regex execution timeouts, and BFS depth limits (`max_depth=4`).
- **Verification:** Fuzzing tests in `tests/fuzz/test_phase11_fuzzing.py` and `tests/redteam/test_phase11_redteam.py`.

### 4.6 Elevation of Privilege
- **Threat:** `viewer` executes destructive SOAR actions or approves unverified mapping rules.
- **Controls:** RBAC matrix enforced via FastAPI middleware; destructive actions (`DELETE_*`, `DROP_*`) are permanently blocked by policy.
