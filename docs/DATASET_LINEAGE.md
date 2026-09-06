# ULPF Dataset Lineage and Transformation Register

**Document ID:** ULPF-DOC-DATA-LINEAGE-001  
**Governing ADR:** ADR-008 (Evidence, Proof & Lineage)  

---

## 1. Lineage Classification Principles

Every data file in the ULPF repository belongs to one of three lineage classes:
1. **Upstream Raw (`RAW`):** Direct authentic bytes preserved exactly as emitted by the system or publisher.
2. **Upstream Reference Ground Truth (`REF`):** External benchmark ground truth (e.g. Loghub parsed CSVs, LUK alarm dictionaries).
3. **Derived Curated Test Fixtures (`DERIVED_FIXTURE`):** Canonical, de-identified fixtures synthesized strictly to conform to official vendor specifications and standards without embedding proprietary production secrets.

---

## 2. Lineage Traceability Table

| Family | Lineage Class | Parent Source / Upstream Specification | Transformations Applied | Hash Stability |
| :--- | :--- | :--- | :--- | :---: |
| **Loghub Systems** | Upstream Raw / Ref | Loghub 2.0 (ISSRE 2023) & Khan et al. (Figshare 2022) | None (Exact upstream bytes) | Immutable |
| **LUK Alarm KBs** | Upstream Reference | LUK Benchmark (Tsinghua / Huawei 2022) | None (Exact JSON templates) | Immutable |
| **SecRepo Network** | Upstream Raw | SecRepo.org (CCDC 2012 / Mike Sconzo) | None (Exact Zeek logs) | Immutable |
| **Zed Multi-Format** | Upstream Raw | Brim Data / Zed Sample Data (WRCCDC 2018) | None (Exact multi-format) | Immutable |
| **Palo Alto PAN-OS** | Derived Fixture | Official Palo Alto PAN-OS 10.x Syslog Guide | RFC 5737 IP de-identification | Verified |
| **Fortinet FortiGate**| Derived Fixture | Official FortiOS 7.4 Log Reference | RFC 5737 IP de-identification | Verified |
| **Cisco ASA** | Derived Fixture | Official Cisco ASA Series Syslog Guide | RFC 1918 / TEST-NET de-identification | Verified |
| **Check Point Gaia** | Derived Fixture | Official Check Point R81 Logging Guide | RFC 5737 IP de-identification | Verified |
| **Suricata EVE** | Derived Fixture | OISF Suricata 7.x EVE-JSON Specification | RFC 5737 IP de-identification | Verified |
| **Snort Fast** | Derived Fixture | Cisco Talos Snort 3 Alert Output Specification | RFC 5737 IP de-identification | Verified |
| **AWS CloudTrail** | Derived Fixture | AWS CloudTrail User Guide Schema 1.08 | Fictitious account & principal IDs | Verified |
| **Kubernetes Audit** | Derived Fixture | CNCF `audit.k8s.io/v1` API Server Schema | Fictitious service accounts | Verified |
| **Windows Security** | Derived Fixture | Microsoft Security Auditing Event Reference | Fictitious domain accounts & SIDs | Verified |
| **Linux Auditd** | Derived Fixture | Linux Kernel 6.x Audit Framework | Synthetic command execution | Verified |
| **PostgreSQL** | Derived Fixture | PostgreSQL 16 Logging Reference | Synthetic SQL statements | Verified |
| **MongoDB** | Derived Fixture | MongoDB 5.0+ Structured JSON Reference | Synthetic collection & query filter | Verified |
| **CEF / LEEF / RFC** | Derived Fixture | Micro Focus CEF, IBM LEEF, IETF RFC 5424 | Vendor-agnostic demonstration | Verified |
| **Adversarial** | Derived Fixture | ULPF Security & Robustness Research Suite | Deterministic fuzzing vectors | Verified |
