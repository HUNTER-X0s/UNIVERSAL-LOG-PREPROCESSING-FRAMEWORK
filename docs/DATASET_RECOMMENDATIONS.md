# ULPF Recommended Future Dataset Additions (Phase 49)

**Document ID:** ULPF-DOC-DATA-007  
**Status:** PROPOSED (Governance Review Required)  
**Rule:** NO AUTOMATIC DOWNLOADS PERMITTED. Human review mandatory.  
**Audit Date:** 2026-09-05  

---

## Prioritized Acquisition Candidates

| Candidate ID | Target Dataset | Target Format | Priority | Target Phase | Size | Justification & Expected Benefit |
| :--- | :--- | :--- | :---: | :---: | :---: | :--- |
| **REC-01** | **Palo Alto PAN-OS Syslog** | CSV-over-Syslog | **CRITICAL** | Phase 3 | < 2 MB | Essential for NTRO perimeter firewall parser validation. |
| **REC-02** | **Fortinet FortiGate UTM Logs** | Key=Value Syslog | **HIGH** | Phase 3 | < 2 MB | Fills top-tier perimeter vendor gap; validates key-value tokenization. |
| **REC-03** | **Suricata EVE-JSON** | JSON Lines | **HIGH** | Phase 3 | < 5 MB | Validates standard open-source network IDS alert ingestion. |
| **REC-04** | **Synthetic Adversarial Fixtures** | Multi-format | **HIGH** | Phase 2/3 | < 500 KB | Fuzzing, memory bounds, and DLQ rejection test suites. |
| **REC-05** | **AWS CloudTrail Audit** | JSON Array/Stream | **MEDIUM** | Phase 4 | < 5 MB | Validates nested JSON normalization and cloud control-plane telemetry. |
