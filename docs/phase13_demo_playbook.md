# ULPF Phase 13 SIH Demonstration Playbook

**Target Audience:** Smart India Hackathon Evaluators / NTRO Technical Judges  
**Execution Command:** `python scripts/run_phase13_sih_showcase.py`  
**Expected Duration:** ~1.5 - 2.5 seconds (Timebox constraint: <120 seconds)  
**Environment:** 100% Offline / Air-Gapped (Zero network dependencies)  

---

## 15-Step Scripted Narrative

1. **Step 1 & 2: Ingestion & Universal Source Intelligence:**
   Heterogeneous telemetry streams enter (Palo Alto, FortiGate, Cisco ASA, Suricata, Linux Auditd, AWS CloudTrail). The engine deterministically classifies each stream with explicit confidence and supporting evidence.
2. **Step 3: Cryptographic Raw Evidence Preservation:**
   Every event's raw bytes are hashed with SHA-256 before normalization, guaranteeing 100% bit-exact non-repudiation.
3. **Step 4 & 5: Universal Normalization & Dual View:**
   Events are normalized to Universal Common Event (UCE) schema and projected to OCSF v1.1 and OpenTelemetry, accompanied by a multi-factor Data Quality score.
4. **Step 6 & 7: Unknown Log Onboarding & Mapping Diff:**
   An unrecognized custom IoT/OT sensor line arrives. The system recognizes the format, drafts candidate field mappings, computes the version diff, and presents a rollback-safe preview.
5. **Step 8 & 9: Local Threat Intelligence & Security Correlation:**
   Local air-gapped IOC feed matches perimeter probe indicators without outbound network traffic.
6. **Step 10, 11 & 12: One-Click Investigation & Attack Story:**
   Analyst triggers a single pivot on seed IP `198.51.100.25`. The engine compiles related events into a chronological attack story across MITRE tactics (Initial Access -> Privilege Escalation -> C2 Outbound).
7. **Step 13: Grounded Local AI Copilot:**
   Offline copilot presents an evidence-grounded summary strictly separating `[VERIFIED FACT]`, `[SYSTEM INFERENCE]`, and `[ANALYST SUGGESTION]`.
8. **Step 14 & 15: Case Package Sealing & Bit-Exact Verification:**
   Full investigation context is packaged into an exportable bundle with a cryptographic manifest. The verifier recomputes all raw digests offline to guarantee zero tampering.
