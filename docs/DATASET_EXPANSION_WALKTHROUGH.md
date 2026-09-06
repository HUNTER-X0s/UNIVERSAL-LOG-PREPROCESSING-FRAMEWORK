# ULPF Dataset Expansion and Phase-3 Readiness Walkthrough

**Document ID:** ULPF-DOC-DATA-WALKTHROUGH-002  
**Execution Timestamp:** 2026-09-05T14:30:00Z  

---

## 1. Executive Walkthrough

In compliance with the **ULPF Master Mission: Universal Log Corpus Expansion, Real-World Dataset Research, Curation, Organization, Validation & Phase-3 Readiness**, the ULPF telemetry corpus has been expanded into a world-class, vendor-agnostic, multi-domain dataset collection.

### Core Metrics Summary:
- **Total Registered Datasets:** **22 datasets** (8 Core NTRO, 14 Extended Universal/Stress/Reference)
- **Total On-Disk Files:** **306 files**
- **Total Volume:** **6,409,411,884 bytes (~6,112.49 MB / 5.97 GB)**
- **Core NTRO Datasets:** **8** (Palo Alto, Fortinet, Cisco ASA, Check Point, Suricata, Snort, SecRepo, Zed)
- **Extended Universal Datasets:** **14** (AWS CloudTrail, VPC Flow, K8s, Docker, Postgres, Mongo, Windows, Linux Auditd, NGINX, HAProxy, Enterprise Standards, Adversarial, Loghub, LUK)
- **Format Coverage Count:** **12 distinct formats** (Syslog RFC 3164, RFC 5424, JSON, NDJSON, CSV, Key=Value, Pipe-KV, XML, TSV, SUP, BSUP, Bracketed Text)
- **Domain Coverage Count:** **8 domains** (Network Security, Cloud, Container, Database, Identity, Application, Operating System, Infrastructure)
- **Vendor Coverage Count:** **17 distinct vendors / open-source projects**
- **Cryptographic Hash Verification:** **306 / 306 verified (0 mismatches)**
- **Byte Duplicate Groups:** **0** (All files distinct)
- **Automated Test Suite:** **84 / 84 passing**

---

## 2. What Was Researched, Selected and Rejected

1. **Selected & Curated:**
   - **Perimeter Firewalls:** Palo Alto PAN-OS (Traffic & Threat CSV-over-syslog), Fortinet FortiGate (Key=Value UTM), Cisco ASA (Connection/Drop syslogs), Check Point Gaia (Pipe-KV FireWall-1).
   - **Intrusion Detection:** Suricata EVE-JSON (NDJSON alert streams), Snort fast-alert format.
   - **Web & Proxy:** NGINX (Combined log format with upstream timing), HAProxy (HTTP timer tuples).
   - **Cloud Telemetry:** AWS CloudTrail (Nested management JSON), AWS VPC Flow Logs (Space-delimited network flows).
   - **Cloud-Native / Containers:** Kubernetes API server audit events (`audit.k8s.io/v1` NDJSON), Docker daemon logrus events.
   - **Databases:** PostgreSQL (Operational & SQL error logs), MongoDB (Structured 5.0+ JSON server telemetry).
   - **Identity & Host:** Windows Security Event Log XML (Logon 4624 / Failure 4625), Linux Auditd (Privilege escalation & syscall logs).
   - **Enterprise SIEM Formats:** ArcSight Common Event Format (CEF), IBM QRadar Log Event Extended Format (LEEF), IETF RFC 5424 structured syslog.
   - **Adversarial & Edge Cases:** Malformed JSON, truncated streams, null-byte injections, and regex backtracking stress vectors.
2. **Evaluated & Rejected:**
   - **UWF-ZeekData (UWF-ZeekData22 / UWF-ZeekData24):** Rejected for Git ingestion. The repository already possesses 4.17 GB of SecRepo Zeek logs and 1.9 GB of Zed Zeek logs. Ingesting multi-hundred-gigabyte UWF data would offer zero new format diversity while severely bloating storage.
   - **Scraped / Unsanitized Production Dumps:** Rejected per Phase 9 privacy and safety rules.

---

## 3. Phase 3 Consumption Guide

Phase 3 can immediately ingest and parse the expanded corpus:
- Feed `data/fixtures/real_world/network_security/` into perimeter parser test suites.
- Feed `data/fixtures/real_world/multi_format/` into universal format auto-detectors.
- Feed `data/fixtures/adversarial/` into DLQ and robustness tests.
- Evaluate normalization against `data/reference/alarm_knowledge/` and `data/reference/loghub/`.
- Run scale backpressure benchmarks against `data/benchmarks/secrepo/`.
