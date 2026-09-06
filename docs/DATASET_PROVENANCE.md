# ULPF Dataset Provenance and Citation Register

**Document ID:** ULPF-DOC-DATA-002  
**Status:** DRAFT / AUDITED  
**Governing ADRs:** ADR-001 (Architecture Guardrails), ADR-008 (Evidence & Lineage)  
**Strategy Document:** `docs/DATASET_STRATEGY.md`  
**Audit Date:** 2026-09-05  

---

## 1. Provenance Policy

Per the ULPF Frozen Architecture:
1. No dataset is accepted without an immutable origin record, clear licensing terms, and documented derivation steps.
2. Original raw bytes must be preserved without in-flight truncation, sanitization, or conversion.
3. Ground-truth references (templates, annotations, structured fields) must remain clearly segregated from raw intake inputs.

---

## 2. External Dataset Provenance Records

### Source Record 1: Loghub 2.0 / Loghub-2k
- **Source Identifier:** `SRC-LOGHUB-2K`
- **Origin Organization:** Logpai Research Team (Chinese University of Hong Kong)
- **Primary Repository:** `https://github.com/logpai/loghub`
- **Release / Version:** Loghub 2.0 (2023 release)
- **License:** Freely available for academic, research, and non-commercial evaluation.
- **Redistribution Terms:** Requires attribution and citation of the ISSRE 2023 paper.
- **Citation:**
  > Jieming Zhu, Shilin He, Pinjia He, Jinyang Liu, Michael R. Lyu. "Loghub: A Large Collection of System Log Datasets for AI-driven Log Analytics." IEEE International Symposium on Software Reliability Engineering (ISSRE), 2023.
- **Scope Present Locally:** 16 systems (Android, Apache, BGL, HDFS, HPC, Hadoop, HealthApp, Linux, Mac, OpenSSH, OpenStack, Proxifier, Spark, Thunderbird, Windows, Zookeeper).
- **Original Bytes Preserved:** YES. The raw `*_2k.log` files and full `Mac.log` represent exact upstream bytes.
- **Local Modifications:** None. The files are stored as originally released.

### Source Record 2: Loghub Corrected Ground Truth (Khan et al.)
- **Source Identifier:** `SRC-LOGHUB-CORRECTED`
- **Origin Organization:** University of Waterloo / McMaster University
- **Repository / DOI:** `https://doi.org/10.5281/zenodo.1144100` / Figshare: `18858332`
- **Release / Version:** 2022 Artifact for "Guidelines for Assessing the Accuracy of Log Message Template Identification Techniques"
- **License:** Creative Commons Attribution 4.0 International (CC-BY 4.0).
- **Citation:**
  > J. Khan et al., "Guidelines for Assessing the Accuracy of Log Message Template Identification Techniques," IEEE Transactions on Software Engineering / ICSE Artifact, 2022.
- **Scope Present Locally:** `*_2k.log_structured_corrected.csv` and `*_2k.log_templates_corrected.csv` across Loghub systems.
- **Original Bytes Preserved:** YES. Reference ground-truth files are exact copies of the published benchmark artifact.

### Source Record 3: Zed Sample Data (WRCCDC 2018 Multi-Format Network Data)
- **Source Identifier:** `SRC-BRIMDATA-ZED`
- **Origin Organization:** Brim Data Inc. / Zed Project
- **Primary Repository:** `https://github.com/brimdata/zed-sample-data`
- **Release / Version:** Commit `main` (generated with Zeek v6.2.0 + Zed `super` 2024)
- **Upstream Network Capture Origin:** Western Regional Collegiate Cyber Defense Competition (WRCCDC 2018, March 24, 2018).
- **License:** Creative Commons Attribution-ShareAlike 4.0 International (CC-BY-SA 4.0).
- **Attribution Notice:** Built upon WRCCDC PCAP data distributed under CC-BY-SA 4.0.
- **Original Bytes Preserved:** YES. The raw `zeek-default/` TSV logs, `zeek-json/` JSON streaming logs, `sup/` text records, and `bsup/` binary LZ4 streams match upstream.
- **Local Modifications:** None.

### Source Record 4: SecRepo Cyber Security Repository (Bro/Zeek Network Logs)
- **Source Identifier:** `SRC-SECREPO-CCDC`
- **Origin Organization:** SecRepo.org (Curator: Mike Sconzo)
- **Primary Repository:** `https://www.secrepo.com/`
- **Release / Version:** CCDC / MACCDC 2012 Network Attack/Defense Zeek log capture.
- **License:** Public Domain / Open Security Research (SecRepo Open Data).
- **Citation:**
  > Mike Sconzo, SecRepo: Samples of Security Related Data, www.secrepo.com.
- **Scope Present Locally:** 13 Bro/Zeek TSV log files (including 2.59 GB `conn.log` and 1.32 GB `http.log`).
- **Original Bytes Preserved:** YES. Authentic Bro/Zeek 2012 network traffic monitoring logs.
- **Local Modifications:** None. Stored raw without compression or truncation.

### Source Record 5: LUK Network Device Alarm Knowledge Bases
- **Source Identifier:** `SRC-LUK-NETKB`
- **Origin Organization:** Log Understanding Knowledge (LUK) Research Initiative (Tsinghua / Huawei Network Log Analysis).
- **Primary Purpose:** Comprehensive catalog of vendor alarm and syslog templates for network routers, switches, and WLAN controllers.
- **License / Terms:** Academic Research Use / Vendor Specification Aggregation.
- **Scope Present Locally:**
  - Cisco: `cs_routers_5k.json`, `cs_switch_5k.json`, `cs_wlan.json`
  - Huawei: `hw_routers_desc.json`, `hw_switch_desc.json`, `hw_wlan_desc.json`
- **Original Bytes Preserved:** YES. JSON structured template lists preserved in full.

---

## 3. Provenance Verification Matrix

| Dataset | Provenance Verified | License Identified | Redistribution Permitted | Clean Raw/Ref Separation |
| :--- | :--- | :--- | :--- | :--- |
| **Loghub-2k Raw** | YES (`logpai/loghub`) | Academic / Research | YES (with citation) | Separation Needed |
| **Loghub Corrected** | YES (Khan et al. Figshare) | CC-BY 4.0 | YES | Separation Needed |
| **Zed Multi-Format** | YES (`brimdata/zed-sample-data`)| CC-BY-SA 4.0 | YES | Clean |
| **SecRepo Network** | YES (`secrepo.com`) | Open Security Data | YES | Requires Relocation to Benchmarks |
| **LUK Cisco/Huawei** | YES (LUK Benchmark) | Research / Vendor Doc | YES (internal evaluation)| Must classify as Reference KB |
