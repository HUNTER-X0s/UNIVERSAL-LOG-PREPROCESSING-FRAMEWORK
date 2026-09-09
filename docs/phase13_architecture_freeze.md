# ULPF Phase 13 Architecture Freeze Specification

**Mission:** NTRO / Smart India Hackathon (SIH26156)  
**Project:** Universal Log Pre-processing Framework (ULPF)  
**Baseline Status:** `PHASE12_FINAL_RELEASE_CANDIDATE_APPROVED` (pinned at `545e4ba66d`)  
**Phase 13 Freeze Target:** `PHASE13_RELEASE_CANDIDATE`  
**Security Classification:** Air-Gapped High-Assurance Architecture  

---

## 1. Architectural Principles

Phase 13 elevates the ULPF foundation from a high-throughput parser pipeline into an air-gapped, evidence-grounded intelligence and investigation platform.

1. **Deterministic Core Invariance (Rule 4):**
   The authoritative data path remains 100% deterministic and cryptographically anchored. AI assistance is strictly confined to heuristic suggestions, semantic drafting, and analyst explanation. Under no circumstances can AI mutate raw evidence, alter production parsing, or bypass RBAC.
2. **Lossless Evidence & Dual View (Workstream E):**
   Raw telemetry bytes are stored immutably with SHA-256 verification alongside semantic projections (Universal Common Event / UCE, OCSF v1.1, and OpenTelemetry).
3. **Universal Source Intelligence (Workstream A):**
   Incoming streams are fingerprinted via weighted signature matching without external network lookup, yielding explicit confidence and explainable evidence.
4. **Governed Unknown Onboarding (Workstream B & C):**
   Unseen log formats undergo boundary profiling, semantic alias mapping, and diff impact analysis, requiring human approval before production runtime activation.
5. **Multi-Source Correlation & Chronological Storytelling (Workstream G & H):**
   Heterogeneous perimeter, cloud, and host events correlate across shared entities into an explainable chronological Attack Story linked to MITRE ATT&CK.
6. **Verifiable Forensic Case Packages (Workstream N):**
   Investigations export cryptographically sealed bundles whose manifest and byte digests can be verified independently offline.

---

## 2. Frozen Subsystem Interfaces

```
RAW INGESTION (Lossless Raw Capture + SHA-256)
      ↓
UNIVERSAL SOURCE INTELLIGENCE (Format Detection + Parser Selection)
      ↓
DETERMINISTIC NORMALIZATION (20 Concrete Parsers + Universal UCE)
      ↓
DUAL VIEW PROJECTION (UCE + OCSF v1.1 + OpenTelemetry)
      ↓
ANALYST INVESTIGATION WORKBENCH & ATTACK STORY (One-Click Pivot + Timeline)
      ↓
LOCAL AIR-GAPPED AI COPILOT (Grounded Facts + Safe Action Model)
      ↓
CRYPTOGRAPHIC CASE PACKAGING & EXPORT (Bit-Exact Offline Verification)
```
