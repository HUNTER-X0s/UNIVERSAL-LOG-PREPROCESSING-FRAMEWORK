# ULPF Dataset Corpus Gap Analysis (Phase 48)

**Document ID:** ULPF-DOC-DATA-006  
**Status:** COMPLETE  
**Primary Standard:** NTRO SIH26156 Operational Problem Statement  
**Audit Date:** 2026-09-05  

---

## 1. What We Have (Current Inventory)

1. **Operating System Telemetry:** Complete coverage of Linux (syslog/auth), macOS (ASL/syslog), Windows (Event log exports), and Android.
2. **Distributed Infrastructure & Cloud:** High-fidelity logs from Hadoop, HDFS, Spark, OpenStack, and Zookeeper.
3. **High-Performance Computing:** BlueGene/L (BGL) and HPC cluster operational and failure logs.
4. **Network Monitoring & Transactions:** Zeek flow (`conn`), web (`http`), resolution (`dns`), encryption (`ssl`), file (`files`), and error (`weird`) across 35 protocol log types in TSV, JSON, SUP, and BSUP formats.
5. **Network Equipment Knowledge Bases:** 28,186 alarm and syslog template definitions across Cisco IOS-XE and Huawei VRP routers, switches, and WLAN controllers.
6. **Multi-Format Symmetry:** The Zed dataset allows proving that ULPF parses identical network events identically across 4 competing wire formats.

---

## 2. What We Don't Have (Genuine Gaps)

1. **Perimeter Next-Gen Firewall (NGFW) Logs:**
   - Palo Alto Networks (PAN-OS) traffic, threat, and URL filtering syslog.
   - Fortinet FortiGate CEF / key-value format UTM logs.
   - Check Point Gaia firewall and blade audit events.
2. **Dedicated Intrusion Detection Systems (IDS/IPS):**
   - Suricata EVE-JSON (standard network security telemetry).
   - Snort fast-alert / unified2 logs.
3. **Structured Cloud Audit Feeds:**
   - AWS CloudTrail JSON audit events.
   - Kubernetes audit webhook JSON logs.
4. **Adversarial & Malformed Log Fixtures:**
   - Deliberately truncated UTF-8 sequences, null-byte injected syslog lines, regex DoS strings, and corrupted frame boundaries.

---

## 3. What We Actually Need vs What We Do NOT Need

### What We ACTUALLY NEED (Phase 3 Parser Priorities):
- Small (100–500 line) curated fixtures of **Palo Alto PAN-OS syslog** (CSV-delimited).
- Small (100–500 line) curated fixtures of **FortiGate key=value syslog**.
- Curated **Suricata EVE-JSON** alerts.
- Dedicated synthetic adversarial fixtures in `data/fixtures/adversarial/`.

### What We DO NOT NEED (Anti-Patterns to Avoid):
- **Do NOT download terabytes of raw PCAP:** ULPF is a log pre-processor, not a packet capture capture engine.
- **Do NOT download bloated commercial SIEM dumps:** Massive proprietary DB dumps add no parser value.
- **Do NOT download additional UWF Zeek archives:** The repository already contains 4.17 GB of SecRepo Zeek logs and 1.9 GB of Zed Zeek logs. Adding UWF ZeekData would be completely redundant.
