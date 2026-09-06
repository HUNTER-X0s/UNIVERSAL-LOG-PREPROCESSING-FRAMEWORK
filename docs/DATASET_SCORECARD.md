# ULPF Dataset Corpus Scorecard (Phase 47)

**Document ID:** ULPF-DOC-DATA-005  
**Evaluation Standard:** NTRO Perimeter Log Pre-processing Architecture  
**Evaluation Scale:** 1 to 10 (Strict, un-inflated scoring)  
**Audit Date:** 2026-09-05  

---

## 1. Quantitative Scorecard Summary

| Dimension | Score (1–10) | Status | Primary Strengths | Identified Gap / Defect |
| :--- | :---: | :---: | :--- | :--- |
| **1. Source Diversity** | **8 / 10** | Strong | Includes Logpai, SecRepo, WRCCDC, Zed, Tsinghua/Huawei | Missing national-scale defense perimeter feeds |
| **2. Vendor Diversity** | **6 / 10** | Moderate | Cisco, Huawei, Linux, Apple, Microsoft, Apache, IBM | **Critical Gap:** Missing Palo Alto, Fortinet, Check Point, F5 |
| **3. Format Diversity** | **9 / 10** | Excellent | Syslog, JSON, TSV, CSV, SUP, BSUP (LZ4 binary) | Missing RFC 5424 structured-data XML, binary EVTX |
| **4. Network-Security Coverage** | **7 / 10** | Moderate | Zeek conn, http, dns, ssl, weird, ssh, notice | Heavily skewed to Zeek; missing NGFW & WAF device logs |
| **5. System Coverage** | **9 / 10** | Excellent | Android, Linux, Mac, Windows, IBM BGL, HPC clusters | Fully covers standard OS and supercomputer systems |
| **6. Application Coverage** | **8 / 10** | Strong | Apache, OpenSSH, Proxifier, HealthApp, Thunderbird | Missing enterprise database logs (Oracle, PostgreSQL) |
| **7. Real-World Relevance** | **8 / 10** | Strong | WRCCDC, CCDC, real HPC cluster failures, real OS logs | Academic & competition captures; not live perimeter ISP logs |
| **8. Ground-Truth Availability** | **9 / 10** | Excellent | Loghub structured CSVs + Khan et al. corrected templates | Highly verifiable ground truth for template parsing |
| **9. Adversarial Coverage** | **4 / 10** | **Deficient** | SecRepo weird.log has protocol anomalies | **Critical Gap:** Lacks deliberate injection & malformed fixtures |
| **10. Benchmark Suitability** | **9 / 10** | Excellent | SecRepo 4.17 GB + Zed 1.9 GB provide true stress data | Excellent for throughput and backpressure validation |
| **11. Provenance Quality** | **9 / 10** | Excellent | Explicit citations, upstream repos, and DOIs verified | Outstanding traceability for all 4 dataset families |
| **12. Storage Efficiency** | **5 / 10** | **Deficient** | Data on disk is uncorrupted | **Defect:** 4.17 GB benchmark logs mixed into test fixtures |
| **13. Licensing Clarity** | **8 / 10** | Strong | CC-BY-SA 4.0, CC-BY 4.0, Open Data, Academic | Cisco/Huawei vendor extraction terms need legal review |
| **14. Future Parser Usefulness**| **9 / 10** | Excellent | Loghub and Zed offer immediate parser test suites | Directly enables Phase 3 parsing & normalization plane |

**Overall Mean Score: 7.7 / 10**

---

## 2. Rationale for Sub-9 Scores & Remediation Roadmap

### Dimension 2: Vendor Diversity (Score: 6/10)
- **Why below 9:** The NTRO mission specifies Universal Log Pre-processing for perimeter and infrastructure devices. The current corpus has excellent Cisco and Huawei alarm dictionaries, but **zero** real-world samples from Palo Alto Networks (PAN-OS), Fortinet (FortiOS), Check Point Gaia, or F5 BIG-IP.
- **Remediation:** Curate authorized, anonymized syslog samples for Palo Alto traffic/threat logs and FortiGate UTM events during Phase 3.

### Dimension 4: Network-Security Coverage (Score: 7/10)
- **Why below 9:** Network security is dominated by Bro/Zeek protocol analyzer logs (SecRepo and Zed). While Zeek is an industry-standard network telemetry source, perimeter security also depends on Next-Gen Firewalls, Intrusion Prevention Systems (Suricata/Snort), and VPN gateways.
- **Remediation:** Add Suricata EVE-JSON fixtures and Cisco ASA connection/drop syslogs.

### Dimension 9: Adversarial Coverage (Score: 4/10)
- **Why below 9:** Real-world datasets naturally exhibit few deliberate edge-case attacks or parser stress constructs (such as deeply nested JSON, catastrophic regex backtracking triggers, null-byte poisoning, or corrupted framing).
- **Remediation:** Populate `data/fixtures/adversarial/` with synthetic adversarial fixtures (already designed in Phase 2 `test_golden_fixtures.py`).

### Dimension 12: Storage Efficiency (Score: 5/10)
- **Why below 9:** The current layout has 6.11 GB sitting inside `data/fixtures/real_world/`. This places huge multi-gigabyte benchmark files (`conn.log` 2.59 GB, `http.log` 1.32 GB) inside the test fixtures tree and uses a blunt `.gitignore: *.log` rule.
- **Remediation:** Execute the Dataset Organization Plan to separate Tier 1 fixtures (<10MB) from Tier 2/3 benchmarks.
