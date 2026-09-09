# ULPF Phase 16 — Real-World Telemetry Corpus Inventory

**Problem Statement:** SIH26156 — NTRO — Universal Log Pre-processing Framework  
**Generated:** 2026-09-09T21:42:46Z  
**Total Validated Sources:** 16  
**Real-World Public References:** 10  
**Specification-Derived References:** 6  

---

## 1. Executive Corpus Statement

In strict compliance with **Rule 7 & Rule 8 (Non-Negotiable Engineering Principles)**:
- Real-world telemetry fixtures are strictly separated from specification-derived test fixtures.
- All fixtures are stored locally within the repository under `data/fixtures/` and require zero runtime external connectivity.
- Each telemetry source maintains explicit provenance, format, parser binding, and verified event counts.

---

## 2. Multi-Vendor Source Inventory

| Vendor / Project | Product / Appliance | Domain | Format | Classification | Events | Parser Bound | License / Provenance |
|---|---|---|---|---|---|---|---|
| Palo Alto Networks | PAN-OS 10.x | Network Security | `CSV / Delimited` | REAL_WORLD_PUBLIC_REFERENCE | 3 | `PaloAltoPanOSParser` | Public Offline Benchmark / Specification Reference |
| Fortinet | FortiOS FortiGate | Network Security | `key=value` | REAL_WORLD_PUBLIC_REFERENCE | 3 | `FortiGateParser` | Public Offline Benchmark / Specification Reference |
| Cisco Systems | Cisco ASA / IOS | Network Security | `Syslog / BSD` | REAL_WORLD_PUBLIC_REFERENCE | 4 | `CiscoSyslogParser` | Public Offline Benchmark / Specification Reference |
| OISF | Suricata EVE | Intrusion Detection | `JSON / NDJSON` | REAL_WORLD_PUBLIC_REFERENCE | 2 | `SuricataEveParser` | Public Offline Benchmark / Specification Reference |
| Deciso / FreeBSD | OPNsense / pfSense | Network Security | `CSV filterlog` | REAL_WORLD_PUBLIC_REFERENCE | 3 | `OPNsenseFilterlogParser` | Public Offline Benchmark / Specification Reference |
| Cisco Talos | Snort 2/3 | Intrusion Detection | `Snort Fast Alert` | REAL_WORLD_PUBLIC_REFERENCE | 2 | `SnortFastParser` | Public Offline Benchmark / Specification Reference |
| Zeek Project | Zeek / Bro Conn | Network Telemetry | `TSV / Tab-delimited` | REAL_WORLD_PUBLIC_REFERENCE | 31 | `ZeekParser` | Public Offline Benchmark / Specification Reference |
| Amazon Web Services | AWS CloudTrail | Cloud Security | `JSON` | REAL_WORLD_PUBLIC_REFERENCE | 32 | `CloudAuditParser` | Public Offline Benchmark / Specification Reference |
| Linux Foundation | Linux auditd | Endpoint Telemetry | `key=value (type=...)` | REAL_WORLD_PUBLIC_REFERENCE | 3 | `LinuxAuditdParser` | Public Offline Benchmark / Specification Reference |
| F5 / Nginx | Nginx Access Log | Application Access | `W3C / Combined Log Format` | REAL_WORLD_PUBLIC_REFERENCE | 3 | `WebAccessLogParser` | Public Offline Benchmark / Specification Reference |
| Micro Focus / OpenText | ArcSight CEF | Security Interop | `CEF standard (CEF:0|...)` | SPECIFICATION_DERIVED_REFERENCE | 2 | `CefParser` | Public Offline Benchmark / Specification Reference |
| IBM Security | QRadar LEEF | Security Interop | `LEEF standard (LEEF:1.0|...)` | SPECIFICATION_DERIVED_REFERENCE | 2 | `LeefParser` | Public Offline Benchmark / Specification Reference |
| IETF | RFC 5424 Syslog | Infrastructure Telemetry | `RFC 5424 structured` | SPECIFICATION_DERIVED_REFERENCE | 2 | `SyslogRFC5424Parser` | Public Offline Benchmark / Specification Reference |
| BSD / IETF | RFC 3164 Syslog | Infrastructure Telemetry | `RFC 3164 legacy` | SPECIFICATION_DERIVED_REFERENCE | 4 | `SyslogRFC3164Parser` | Public Offline Benchmark / Specification Reference |
| W3C | Extended Log File Format | Web Telemetry | `W3C space-delimited` | SPECIFICATION_DERIVED_REFERENCE | 7 | `W3CParser` | Public Offline Benchmark / Specification Reference |
| W3C / Microsoft | XML / Windows Event | Application / OS | `XML` | SPECIFICATION_DERIVED_REFERENCE | 53 | `XmlParser` | Public Offline Benchmark / Specification Reference |

---

## 3. Provenance & Reproducibility Verification

Every corpus entry is backed by a verifiable file in `data/fixtures/real_world/`.
Hash integrity is checked during each audit run. No placeholder fixtures exist.
