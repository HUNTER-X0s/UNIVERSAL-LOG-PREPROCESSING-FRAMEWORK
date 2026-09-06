# ULPF Dataset Expansion Recommendations & Candidate Evaluation

**Document ID:** ULPF-DOC-DATA-REC-002  
**Evaluation Standard:** 14-Dimension Rubric (Phase 6 Master Prompt)  

---

## 1. Evaluated Candidate Scoring Summary

| Candidate | Domain | Vendor | Format | Overall Score | NTRO Score | Parser Value | Decision |
| :--- | :--- | :--- | :--- | :---: | :---: | :---: | :---: |
| **Palo Alto PAN-OS** | NetSec | Palo Alto | CSV/Syslog | **9.6 / 10** | 10.0 | 9.5 | **ACQUIRED / CURATED** |
| **Fortinet FortiGate**| NetSec | Fortinet | Key=Value | **9.5 / 10** | 10.0 | 9.5 | **ACQUIRED / CURATED** |
| **Cisco ASA** | NetSec | Cisco | Syslog | **9.4 / 10** | 9.5 | 9.0 | **ACQUIRED / CURATED** |
| **Check Point Gaia** | NetSec | Check Point | Pipe-KV | **9.2 / 10** | 9.5 | 9.0 | **ACQUIRED / CURATED** |
| **Suricata EVE-JSON** | NetSec | OISF | NDJSON | **9.5 / 10** | 9.5 | 9.5 | **ACQUIRED / CURATED** |
| **Snort Fast Alert** | NetSec | Cisco Talos | Text | **9.0 / 10** | 9.0 | 8.5 | **ACQUIRED / CURATED** |
| **AWS CloudTrail** | Cloud | AWS | JSON | **9.3 / 10** | 8.5 | 9.5 | **ACQUIRED / CURATED** |
| **AWS VPC Flow** | Cloud | AWS | Space-delim | **9.1 / 10** | 8.5 | 8.5 | **ACQUIRED / CURATED** |
| **Kubernetes Audit** | Container | CNCF | NDJSON | **9.3 / 10** | 8.0 | 9.5 | **ACQUIRED / CURATED** |
| **PostgreSQL Server** | Database | Postgres | Prefixed | **8.8 / 10** | 7.0 | 8.5 | **ACQUIRED / CURATED** |
| **MongoDB Server** | Database | MongoDB | NDJSON | **9.0 / 10** | 7.0 | 9.0 | **ACQUIRED / CURATED** |
| **Windows Sec XML** | Identity | Microsoft | XML | **9.4 / 10** | 9.0 | 9.5 | **ACQUIRED / CURATED** |
| **Linux Auditd** | Identity | Linux | Key=Value | **9.3 / 10** | 9.0 | 9.5 | **ACQUIRED / CURATED** |
| **NGINX Access/Error**| Web | F5/NGINX | CLF / Text | **9.1 / 10** | 8.5 | 9.0 | **ACQUIRED / CURATED** |
| **HAProxy Edge** | Web | HAProxy | HTTP Log | **9.0 / 10** | 8.5 | 9.0 | **ACQUIRED / CURATED** |
| **CEF / LEEF / RFC5424**| Multi | Industry | Standard | **9.7 / 10** | 10.0 | 10.0 | **ACQUIRED / CURATED** |
| **UWF-ZeekData24** | NetSec | UWF | TSV | **6.5 / 10** | 7.0 | 5.0 | **REJECTED (Redundant with SecRepo/Zed)** |
