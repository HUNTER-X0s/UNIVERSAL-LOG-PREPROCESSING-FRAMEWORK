# Smart India Hackathon (SIH26156) — 2-Minute Master Demonstration Runbook

**Challenge:** Universal Log Pre-processing Framework (ULPF)  
**Organization:** National Technical Research Organisation (NTRO)  
**Timebox:** 120 Seconds (2 Minutes)  
**Environment:** 100% Sovereign Offline Air-Gap (0 outbound sockets)  
**Authoritative Baseline:** 20 Concrete Parsers | 614 Passing Tests  

---

## Live Demonstration Script

### [00:00 - 00:20] Introduction & Sovereign Architecture
- **Spoken:**
  > "Respected Jury, modern national defense SOCs are flooded with heterogeneous logs from dozens of vendors—Palo Alto, Cisco, FortiGate, Linux, and Cloud. Today, security teams face format fragmentation, high licensing costs, and catastrophic loss of raw evidence during normalization.
  > We present the **Universal Log Pre-processing Framework (ULPF)**: Different vendors. Different formats. One universal canonical representation. One semantic layer. Zero loss of raw forensic evidence."
- **Screen Action:**
  ```bash
  python scripts/run_sih_demo.py
  ```

### [00:20 - 00:45] Multi-Vendor Ingestion & Bit-Exact Forensic Integrity
- **What Happens:**
  - Ingestion of 4 heterogeneous feeds simultaneously (Palo Alto PAN-OS, Cisco ASA Syslog, FortiGate UTM, Suricata EVE JSON).
  - The engine extracts 30+ structured fields while computing the bit-exact raw SHA-256 digest before any transformation.
- **Spoken:**
  > "Notice Scene 1 and Scene 2: Four distinct vendor streams are framed, parsed, and mapped into our Universal Canonical Event (UCE) schema. Crucially, the raw byte stream is cryptographically locked. Even if an attacker attempts to exploit parser ambiguity or schema drift, our immutable raw store ensures court-admissible forensic lineage."

### [00:45 - 01:10] Cross-Vendor Attack Graph & Correlation
- **What Happens:**
  - Attack Path BFS discovers a 3-hop multi-vendor attack chain spanning from external port scanning (Palo Alto) through perimeter breach (Cisco) into internal C2 communication (Suricata).
- **Spoken:**
  > "Scene 3: An individual vendor only sees isolated fragments. ULPF fuses telemetry across network boundaries into a unified attack graph. Using bounded graph traversal, ULPF isolates the full multi-stage lateral movement path across disparate telemetry in sub-millisecond time."

### [01:10 - 01:35] Air-Gapped AI Analyst Copilot
- **What Happens:**
  - AI Analyst Copilot synthesizes the incident, outputs actionable containment steps, and generates targeted SQL hunt queries without creating any network sockets.
- **Spoken:**
  > "Scene 4: Operating in strict national security air-gap environments, ULPF features an embedded, prompt-injection shielded AI Analyst Copilot. Zero external LLM calls, zero data leakage, and instant explainable triage recommendations."

### [01:35 - 02:00] Sealed Evidence Export & Verification
- **What Happens:**
  - The platform exports a sealed evidence container with cryptographic manifest and SHA-256 tamper verification.
- **Spoken:**
  > "Finally, Scene 5: An unbroken cryptographic audit trail packages the case, detections, and raw events. If a single bit in the raw telemetry is altered, the package seal immediately fails verification.
  > ULPF provides deterministic replay, verified 94k+ EPS throughput, and complete sovereign operational readiness. Thank you."

---

## Clean Reset & Re-run Instructions

To reset the demonstration environment to clean baseline:
```bash
python scripts/demo_reset.py
```
To run the live test suite proof:
```bash
python -m pytest tests/ -q
```
