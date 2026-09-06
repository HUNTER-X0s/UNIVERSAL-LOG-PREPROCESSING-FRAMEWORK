# ULPF Final Dataset Rejection Log

**Document ID:** ULPF-DOC-REJECTION-LOG-FINAL  
**Corpus Version:** v3.1.0  

---

### 1. Formal Rejection Records

1. **Candidate:** `UWF-ZeekData` (University of West Florida Zeek captures)
   - *Date of Evaluation:* 2026-09-05
   - *Size:* Multi-hundred gigabyte raw TSV archives
   - *Evaluation Determination:* **REJECTED FROM DIRECT GIT INGESTION**
   - *Rationale:* Redundant with the existing 4.17 GB SecRepo and 1.94 GB Zed datasets. Ingesting multi-GB archives into Git repository violates storage policy and causes severe bloat. Documented as an optional external benchmark for Tier 3 mounts.

2. **Candidate:** `Raw PCAP Dumps` (Full packet captures)
   - *Date of Evaluation:* 2026-09-05
   - *Evaluation Determination:* **ARCHITECTURALLY EXCLUDED**
   - *Rationale:* ULPF is a universal log and telemetry preprocessor. Parsing link-layer packet frames belongs to packet analyzers (Wireshark/Zeek/Suricata), whose generated logs ULPF ingests.
