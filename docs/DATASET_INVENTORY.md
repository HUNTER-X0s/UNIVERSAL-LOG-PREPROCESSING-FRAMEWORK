# ULPF Dataset Corpus Inventory

**Document ID:** ULPF-DOC-DATA-001  
**Status:** DRAFT / AUDITED  
**Repository Path:** `data/`  
**Total Tracked/Local Files:** 260 files  
**Total Aggregate Volume:** 6,112.46 MB (~5.97 GB)  
**Audit Date:** 2026-09-05  

---

## Executive Summary

The ULPF repository currently houses a diverse collection of 260 data files spanning operating systems, distributed applications, cloud services, telecommunications infrastructure, and high-volume network security event captures.

This inventory provides an authoritative, file-level audit distinguishing:
1. **Raw Log Streams** (unaltered event inputs for intake and parser verification)
2. **Reference Ground Truth** (parsed event CSVs, template dictionaries, and alarm knowledge bases)
3. **Multi-Format Transformations** (Zeek TSV, JSON streaming, SUP, and Super Binary representations)
4. **High-Volume Benchmark Captures** (multi-gigabyte network flow and protocol logs)

---

## High-Level Corpus Breakdown

| Dataset Collection | Sub-Families / Domains | Files | Total Size | Primary Formats | Classification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Loghub (Logpai)** | 16 Systems (OS, Web, Cloud, HPC, Distributed) | 98 | 33.71 MB | Text Syslog, Custom log, Structured CSV | Raw Fixtures (2k) & Reference Ground Truth |
| **LUK (Log Knowledge)** | Cisco & Huawei Network Infrastructure Knowledge | 6 | 3.36 MB | JSON (template arrays) | Reference Alarm Knowledge Bases |
| **SecRepo (Bro/Zeek)** | Network Flow & Protocol Captures (MACCDC/CCDC) | 13 | 4,174.41 MB | Zeek TSV tab-delimited text | High-Volume Benchmark Corpus |
| **Zed Sample Data** | Network Traffic Multi-Format Parallel Exports | 142 | 1,900.97 MB | Zeek TSV, Zeek JSON, SUP, Super Binary (bsup) | Multi-Format Verification & Stress Corpus |
| **Repository Root** | Governance & Policy | 1 | 283 bytes | Markdown (`data/README.md`) | Governance |
| **TOTAL** | **4 Major Collections** | **260** | **6,112.46 MB** | **Multi-format** | **Complete Corpus** |

---

## Detailed Collection Audit

### 1. Loghub Collection (`data/fixtures/real_world/loghub/`)
- **Total Files:** 98 files (33.71 MB)
- **Provenance:** Logpai Research Group (Chinese University of Hong Kong / ISSRE 2023), with corrected templates from Khan et al. (ICSE/TSE Figshare artifact).
- **License:** Freely available for academic/research evaluation (attribution required).
- **Structure:** 16 System subdirectories, each typically containing:
  - `*_2k.log`: 2,000 raw log line sample slice.
  - `*_2k.log_structured.csv`: Original Loghub extracted fields (EventId, EventTemplate, Content).
  - `*_2k.log_structured_corrected.csv`: Independently verified/corrected ground truth.
  - `*_2k.log_templates.csv`: Original template dictionary.
  - `*_2k.log_templates_corrected.csv`: Corrected template dictionary.
  - `README.md`: System-specific description and parsing parameters.
- **Special Case:** `Mac/Mac.log` is a full 16.76 MB raw operating system log.

#### Loghub Sub-Family Inventory Table
| Family | Domain | Raw Log File | Raw Size | Ground Truth CSVs | Templates CSVs | Role |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Android** | Mobile OS | `Android_2k.log` | 259 KB | 2 files (447 KB) | 0 files | OS Raw Fixture & Ref |
| **Apache** | Web Server | `Apache_2k.log` | 147 KB | 2 files (634 KB) | 2 files (593 B) | App Raw Fixture & Ref |
| **BGL** | Supercomputer (IBM) | `BGL_2k.log` | 315 KB | 2 files (942 KB) | 3 files (47 KB) | HPC Raw Fixture & Ref |
| **HDFS** | Distributed Storage | `HDFS_2k.log` | 286 KB | 2 files (987 KB) | 3 files (3.1 KB) | Dist-Sys Raw Fixture & Ref |
| **HPC** | High-Perf Computing | `HPC_2k.log` | 149 KB | 2 files (558 KB) | 2 files (4.1 KB) | HPC Raw Fixture & Ref |
| **Hadoop** | Distributed Compute | `Hadoop_2k.log` | 383 KB | 2 files (1.18 MB) | 2 files (15.1 KB) | Dist-Sys Raw Fixture & Ref |
| **HealthApp** | Mobile Health App | `HealthApp_2k.log` | 185 KB | 2 files (776 KB) | 2 files (7.4 KB) | App Raw Fixture & Ref |
| **Linux** | OS Syslog | `Linux_2k.log` | 214 KB | 2 files (780 KB) | 2 files (10.7 KB) | OS Raw Fixture & Ref |
| **Mac** | Desktop OS Syslog | `Mac_2k.log` + `Mac.log` | 17.08 MB | 2 files (1.17 MB) | 2 files (70.0 KB) | OS Raw Fixture & Benchmark |
| **OpenSSH** | Security / Auth | `OpenSSH_2k.log` | 223 KB | 2 files (809 KB) | 2 files (3.8 KB) | Security Raw Fixture & Ref |
| **OpenStack** | Cloud Platform | `OpenStack_2k.log` | 593 KB | 2 files (1.71 MB) | 2 files (5.4 KB) | Cloud Raw Fixture & Ref |
| **Proxifier** | Network Proxy | `Proxifier_2k.log` | 237 KB | 2 files (827 KB) | 2 files (1.4 KB) | Net Raw Fixture & Ref |
| **Spark** | Distributed Analytics | `Spark_2k.log` | 194 KB | 2 files (685 KB) | 2 files (3.9 KB) | Dist-Sys Raw Fixture & Ref |
| **Thunderbird** | Email Client / Desktop | `Thunderbird_2k.log` | 323 KB | 2 files (1.08 MB) | 2 files (13.0 KB) | App Raw Fixture & Ref |
| **Windows** | OS Event Log | `Windows_2k.log` | 285 KB | 1 file (404 KB) | 1 file (3.3 KB) | OS Raw Fixture & Ref |
| **Zookeeper** | Coordination Service | `Zookeeper_2k.log` | 278 KB | 2 files (927 KB) | 2 files (6.1 KB) | Dist-Sys Raw Fixture & Ref |

---

### 2. LUK Network Infrastructure Collection (`data/fixtures/real_world/luk/`)
- **Total Files:** 6 files (3.36 MB)
- **Provenance:** LUK (Log Understanding Knowledge) network domain knowledge extraction (Cisco IOS-XE / Huawei VRP template collections).
- **Classification:** Reference Template Knowledge Bases (NOT raw streaming logs).
- **Contents:**
  - `Cisco/cs_routers_5k.json`: 5,000 Cisco router syslog/alarm template strings (361.8 KB)
  - `Cisco/cs_switch_5k.json`: 5,000 Cisco switch syslog/alarm template strings (353.8 KB)
  - `Cisco/cs_wlan.json`: 7,370 Cisco wireless LAN alarm template strings (558.2 KB)
  - `Huawei/hw_routers_desc.json`: 4,980 Huawei router alarm descriptions (1.02 MB)
  - `Huawei/hw_switch_desc.json`: 5,000 Huawei switch alarm descriptions (1.06 MB)
  - `Huawei/hw_wlan_desc.json`: 836 Huawei WLAN alarm descriptions (169.0 KB)

---

### 3. SecRepo Network Security Collection (`data/fixtures/real_world/luk/network/SecRepo/`)
- **Total Files:** 13 files (4,174.41 MB / ~4.17 GB)
- **Provenance:** SecRepo.org (curated by Mike Sconzo); Bro/Zeek network monitor outputs from CCDC/MACCDC cyber defense exercises.
- **Current Issue:** Nested incorrectly under `luk/network/SecRepo/` despite having no relation to Cisco/Huawei LUK template files.
- **Classification:** High-Volume Benchmark & Replay Corpus (Too large for git test fixtures).
- **File Breakdown:**
  - `conn.log`: 2,718,866,065 bytes (2,592.91 MB / ~2.59 GB) - TCP/UDP/ICMP connection records
  - `http.log`: 1,379,588,642 bytes (1,315.68 MB / ~1.32 GB) - HTTP request/response transactions
  - `files.log`: 185,998,477 bytes (177.38 MB) - File transfer analysis & hashes
  - `dns.log`: 62,075,487 bytes (59.20 MB) - DNS query/response activity
  - `ssl.log`: 20,217,776 bytes (19.28 MB) - TLS handshake and certificate records
  - `weird.log`: 7,206,707 bytes (6.87 MB) - Protocol violations and anomalies
  - `ftp.log`: 1,706,614 bytes (1.63 MB) - FTP command and data sessions
  - `ssh.log`: 1,081,141 bytes (1.03 MB) - SSH authentication and key exchanges
  - `notice.log`: 192,381 bytes (187.8 KB) - Bro/Zeek security notices & alerts
  - `dhcp.log`: 189,150 bytes (184.7 KB) - DHCP lease activity
  - `smtp.log`: 35,731 bytes (34.9 KB) - Mail transactions
  - `tunnel.log`: 30,498 bytes (29.8 KB) - Teredo / encapsulation tunnels
  - `signatures.log`: 323 bytes (323 B) - Intrusion signature matches

---

### 4. Zed Multi-Format Sample Data (`data/fixtures/real_world/Zed data/`)
- **Total Files:** 142 files (1,900.97 MB / ~1.86 GB)
- **Provenance:** Brim Data (`zed-sample-data`), generated from WRCCDC 2018 PCAP using Zeek v6.2.0 and the Zed `super` tool.
- **License:** Creative Commons Attribution-ShareAlike 4.0 International (CC-BY-SA 4.0).
- **Key Insight:** This collection contains **4 parallel representations of the exact same underlying network events** across 35 protocol log types:
  - `zeek-default/` (35 files, 215.31 MB): Standard Zeek tab-delimited text (`conn.log`, `http.log`, `dns.log`, etc.)
  - `zeek-json/` (35 files, 651.53 MB): Zeek JSON Streaming format (`conn.json`, `http.json`, `dns.json`, etc.)
  - `sup/` (35 files, 974.89 MB): Zed SUP human-readable super-structured text format
  - `bsup/` (35 files, 59.25 MB): Zed Binary Super-structured LZ4-compressed binary format
  - `README.md` & `LICENSE`: Upstream build commands, reproduction steps, and license text.
- **Structural Anomaly:** The top-level folder contains a space (`Zed data`), which breaks standard CLI pipelines and URL formatting.

---

## Git Tracking & Storage State

| Category | On-Disk Files | Tracked in Git | Ignored in Git | Reason |
| :--- | :--- | :--- | :--- | :--- |
| **Loghub CSV & Metadata** | 82 files | 82 files | 0 files | Tracked by Git |
| **Loghub Raw Logs (`*_2k.log`)** | 16 files | 0 files | 16 files | Blocked by root `.gitignore: *.log` |
| **LUK Cisco & Huawei JSON** | 6 files | 6 files | 0 files | Tracked by Git |
| **SecRepo Raw Logs (`*.log`)** | 13 files | 0 files | 13 files | Blocked by root `.gitignore: *.log` |
| **Zed JSON, SUP, BSUP** | 105 files | 105 files | 0 files | Tracked by Git |
| **Zed Default Logs (`zeek-default/*.log`)** | 35 files | 0 files | 35 files | Blocked by root `.gitignore: *.log` |
| **Root & Sub README/LICENSE** | 3 files | 3 files | 0 files | Tracked by Git |

> [!CRITICAL]
> **Gitignore Over-Blocking:** The root `.gitignore` contains `*.log`. While this successfully prevented committing SecRepo's 4.17 GB logs, it also unintentionally ignored the small 2k Loghub test fixtures (`Apache_2k.log`, `Linux_2k.log`, etc.) and the Zeek default logs in Zed data! This policy must be refined cleanly in the Storage Policy.
