# ULPF Comprehensive Dataset Catalog

**Document ID:** ULPF-DOC-DATA-CATALOG-002  
**Status:** EXPANDED / AUTHORITATIVE  
**Release:** Phase 2 Freeze & Phase 3 Onboarding  
**Corpus Scope:** Universal Multi-Domain Telemetry with NTRO Perimeter Security Priority  

---

## 1. Catalog Overview

The Universal Log Pre-processing Framework (ULPF) maintains an authoritative multi-domain telemetry corpus designed for deterministic parser verification, semantic extraction, normalization, and scale benchmarking.

The corpus is formally partitioned into three storage tiers:
- **Tier 1 (Version-Controlled Git Fixtures):** High-density test slices (< 10 MB per file) under `data/fixtures/` and ground-truth references under `data/reference/`.
- **Tier 2 (Local Benchmark Corpora):** Medium-to-large telemetry captures (10 MB – 500 MB) under `data/benchmarks/`.
- **Tier 3 (External Data Mount):** Massive multi-gigabyte production captures (> 500 MB) like SecRepo's 4.17 GB Bro/Zeek attack logs.

---

## 2. Complete Dataset Registry Table

| Dataset ID | Family / Product | Domain | Format | Role | Priority | File Count | Size |
| :--- | :--- | :--- | :--- | :--- | :---: | :---: | :---: |
| **DS-PANOS-FW** | Palo Alto PAN-OS | Network Security | CSV-over-Syslog | Fixture | CORE_NTRO | 3 | 1.8 KB |
| **DS-FORTINET-UTM** | Fortinet FortiGate | Network Security | Key=Value Syslog | Fixture | CORE_NTRO | 2 | 1.4 KB |
| **DS-CISCO-ASA** | Cisco ASA / FTD | Network Security | Syslog RFC 3164 | Fixture | CORE_NTRO | 2 | 800 B |
| **DS-CHECKPOINT-FW1**| Check Point Gaia | Network Security | Pipe-delimited KV | Fixture | CORE_NTRO | 2 | 950 B |
| **DS-SURICATA-EVE** | Suricata IDS/IPS | Network Security | NDJSON | Fixture | CORE_NTRO | 2 | 850 B |
| **DS-SNORT-FAST** | Snort Network IDS | Network Security | Bracketed Text | Fixture | CORE_NTRO | 2 | 650 B |
| **DS-SECREPO-CCDC** | SecRepo Bro/Zeek | Network Security | Zeek TSV | Benchmark | CORE_NTRO | 13 | 4,174.41 MB |
| **DS-BRIMDATA-ZED** | Zed Multi-Format | Network Security | TSV, JSON, SUP, BSUP | Fixture | CORE_NTRO | 142 | 1,900.97 MB |
| **DS-ENTERPRISE-STD**| CEF, LEEF, RFC5424| Multi-Format | Multi-Format | Fixture | CORE_NTRO | 4 | 2.1 KB |
| **DS-AWS-CLOUDTRAIL**| AWS CloudTrail | Cloud | Nested JSON | Fixture | EXTENDED | 2 | 1.2 KB |
| **DS-AWS-VPCFLOW** | AWS VPC Flow | Cloud | Space-Delimited | Fixture | EXTENDED | 2 | 550 B |
| **DS-K8S-AUDIT** | Kubernetes Audit | Container | NDJSON | Fixture | EXTENDED | 2 | 1.1 KB |
| **DS-DOCKER-EVENTS** | Docker Daemon | Container | Logrus KV | Fixture | EXTENDED | 2 | 600 B |
| **DS-POSTGRESQL-LOG**| PostgreSQL Server | Database | Prefixed Text | Fixture | EXTENDED | 2 | 800 B |
| **DS-MONGODB-JSON** | MongoDB Server | Database | NDJSON | Fixture | EXTENDED | 2 | 1.2 KB |
| **DS-WINDOWS-SEC** | Windows Security | Identity | XML (EVTX export) | Fixture | EXTENDED | 2 | 2.5 KB |
| **DS-LINUX-AUDITD** | Linux Auditd | Identity | Key=Value Syslog | Fixture | EXTENDED | 2 | 900 B |
| **DS-NGINX-WEB** | NGINX Access/Error | Application | Combined Log / Text| Fixture | EXTENDED | 3 | 1.1 KB |
| **DS-HAPROXY-EDGE** | HAProxy Load Balancer| Application | HTTP Timer Tuple | Fixture | EXTENDED | 2 | 750 B |
| **DS-ADVERSARIAL** | Fuzzing & Malformed | Adversarial | Corrupted / Multi | Fixture | FORMAT_STRESS | 5 | 8.5 KB |
| **DS-LOGHUB-2K** | Loghub 2.0 (16 Sys)| Multi-Domain | Syslog, CSV, Text | Raw & Ref | EXTENDED | 98 | 35.35 MB |
| **DS-LUK-NETKB** | LUK Cisco & Huawei | Network KB | JSON Arrays | Reference | REFERENCE | 6 | 3.36 MB |
| **TOTAL** | **22 Active Datasets**| **All 10 Tiers** | **All Major Formats**| **Curated**| **Balanced** | **306** | **6,112.49 MB** |
