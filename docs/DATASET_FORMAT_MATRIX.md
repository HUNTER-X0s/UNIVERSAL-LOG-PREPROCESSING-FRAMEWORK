# ULPF Format Coverage Matrix

**Document ID:** ULPF-DOC-DATA-FORMAT-001  
**Status:** COMPLETE / MULTI-FORMAT  

---

## 1. Universal Format Grammar Evaluation

| Format Grammar | Evaluation Standard | Exercised By Datasets | Parser Capability Verified | Status |
| :--- | :--- | :--- | :--- | :---: |
| **Plain Text** | RFC 3164 / Line oriented | Linux 2k, Snort Fast, WireGuard | Line splitting, prefix extraction | **PRESENT** |
| **RFC 3164 Syslog** | BSD Syslog (<PRI>Mon DD HH:MM:SS) | Cisco ASA, Cisco IOS, Juniper SRX | Priority/facility decoding, timestamp parsing | **PRESENT** |
| **RFC 5424 Syslog** | IETF Structured (<PRI>1 Timestamp ...) | `enterprise_standards/rfc5424_syslog.log` | Structured Data [SD-ID] element extraction | **PRESENT** |
| **JSON Lines / NDJSON** | Line-delimited JSON objects | Suricata EVE, K8s Audit, MongoDB, OTel | Streaming JSON framing, key unescaping | **PRESENT** |
| **Nested JSON** | Multi-level hierarchical objects | AWS CloudTrail, Azure Activity, GCP Audit | Recursive object traversal, field flattening | **PRESENT** |
| **CSV-over-Syslog** | Delimited columns without headers | Palo Alto PAN-OS (Traffic & Threat) | Positional field indexing (30+ fields) | **PRESENT** |
| **BSD Packet Filter CSV** | Comma-delimited integer/text | OPNsense / pfSense Filterlog | Branching IPv4/IPv6 schema parsing | **PRESENT** |
| **Key=Value Syslog** | Unquoted & quoted `key=value` tokens | Fortinet FortiOS, Linux Auditd | Dynamic key tokenization, escape handling | **PRESENT** |
| **Pipe-Delimited KV** | Delimiter `|` separated KV tokens | Check Point Gaia FireWall-1 | Pipe splitting, rule identification | **PRESENT** |
| **Common Event Format (CEF)**| ArcSight standard (`CEF:0\|...\|ext`) | `enterprise_standards/cef_events.log` | Header positional + Extension KV split | **PRESENT** |
| **Log Event Extended (LEEF)** | IBM QRadar standard (`LEEF:2.0\|...`) | `enterprise_standards/leef_events.log` | Pipe header + Tab-delimited extension | **PRESENT** |
| **W3C Extended Log** | Directives (`#Fields:`) + space table | Microsoft IIS | Header directive compilation, positional map | **PRESENT** |
| **Combined Log Format (CLF)**| Apache / NGINX standard format | NGINX Access, Apache Loghub | Quoted HTTP request split, response timing | **PRESENT** |
| **Timer-Tuple Log** | Microsecond/millisecond latency tuples | HAProxy Traffic, Envoy Access | Timing tuple arithmetic, termination flags | **PRESENT** |
| **CRI Stream Log** | Container Runtime Interface standard | Containerd CRI (`stdout F msg`) | Stream tagging, partial frame reassembly | **PRESENT** |
| **Multiline Stack Trace** | Indented lines, `Caused by:` chains | Java Log4j / Spring Boot | Multiline record framing, exception chaining| **PRESENT** |
| **Prefixed Database Text** | Timestamp + PID + User/DB prefix | PostgreSQL, MySQL, Redis | Prefix unwrapping, duration extraction | **PRESENT** |
| **Tab-Separated Values (TSV)**| Tab-delimited columns with #fields | Zeek Default, SecRepo CCDC | Header directive parsing, typed value parsing| **PRESENT** |
| **Super Binary (BSUP)** | Zed binary LZ4 compressed frames | Zed `bsup/` | Binary frame decompression, type decoding | **PRESENT** |
| **Text Super-Structured (SUP)**| Zed human-readable ZSON | Zed `sup/` | Dynamic type annotation parsing | **PRESENT** |
| **Adversarial / Malformed** | Hostile, broken, or truncated bytes | `data/fixtures/adversarial/` | Memory bounding, regex DoS guard, DLQ routing| **PRESENT** |
