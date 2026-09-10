# Phase 17 Dataset Provenance & Corpus Classification Report

**Date:** 2026-09-10 05:54:59 UTC  
**Total Evaluated Telemetry Sources:** 16  
- **Real-World Public / Reference Sources:** 10  
- **Specification-Derived / Synthetic Baseline Sources:** 6  

## 1. Dataset Provenance Table
| Source Family | Vendor / Project | Product | Format | Classification | Fixture Path | License / Origin |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| Firewall / Perimeter | Palo Alto Networks | PAN-OS 10.x | `CSV / Delimited` | **REAL_WORLD_PUBLIC_REFERENCE** | `data\fixtures\real_world\network_security\paloalto\panos_traffic.log` | Public Offline Benchmark / Specification Reference |
| Firewall / UTM | Fortinet | FortiOS FortiGate | `key=value` | **REAL_WORLD_PUBLIC_REFERENCE** | `data\fixtures\real_world\network_security\fortinet\fortigate_utm.log` | Public Offline Benchmark / Specification Reference |
| Firewall / Routing | Cisco Systems | Cisco ASA / IOS | `Syslog / BSD` | **REAL_WORLD_PUBLIC_REFERENCE** | `data\fixtures\real_world\network_security\cisco_asa\cisco_asa.log` | Public Offline Benchmark / Specification Reference |
| Network IDS / NSM | OISF | Suricata EVE | `JSON / NDJSON` | **REAL_WORLD_PUBLIC_REFERENCE** | `data\fixtures\real_world\network_security\suricata\suricata_eve.json` | Public Offline Benchmark / Specification Reference |
| Packet Filter / Firewall | Deciso / FreeBSD | OPNsense / pfSense | `CSV filterlog` | **REAL_WORLD_PUBLIC_REFERENCE** | `data\fixtures\real_world\network_security\opnsense\opnsense_filterlog.log` | Public Offline Benchmark / Specification Reference |
| NIDS / IPS | Cisco Talos | Snort 2/3 | `Snort Fast Alert` | **REAL_WORLD_PUBLIC_REFERENCE** | `data\fixtures\real_world\network_security\snort\snort_fast.log` | Public Offline Benchmark / Specification Reference |
| Network Security Monitor | Zeek Project | Zeek / Bro Conn | `TSV / Tab-delimited` | **REAL_WORLD_PUBLIC_REFERENCE** | `data\fixtures\real_world\multi_format\zed\zeek-default\ssh.log` | Public Offline Benchmark / Specification Reference |
| Cloud Audit / Management | Amazon Web Services | AWS CloudTrail | `JSON` | **REAL_WORLD_PUBLIC_REFERENCE** | `data\fixtures\real_world\cloud\aws_cloudtrail\cloudtrail_events.json` | Public Offline Benchmark / Specification Reference |
| Host OS / Kernel | Linux Foundation | Linux auditd | `key=value (type=...)` | **REAL_WORLD_PUBLIC_REFERENCE** | `data\fixtures\real_world\identity\linux_auditd\auditd.log` | Public Offline Benchmark / Specification Reference |
| Web Server / Reverse Proxy | F5 / Nginx | Nginx Access Log | `W3C / Combined Log Format` | **REAL_WORLD_PUBLIC_REFERENCE** | `data\fixtures\real_world\application\nginx\nginx_access.log` | Public Offline Benchmark / Specification Reference |
| Enterprise SIEM Standard | Micro Focus / OpenText | ArcSight CEF | `CEF standard (CEF:0|...)` | **SPECIFICATION_DERIVED_REFERENCE** | `data\fixtures\real_world\multi_format\enterprise_standards\cef_events.log` | Public Offline Benchmark / Specification Reference |
| Enterprise SIEM Standard | IBM Security | QRadar LEEF | `LEEF standard (LEEF:1.0|...)` | **SPECIFICATION_DERIVED_REFERENCE** | `data\fixtures\real_world\multi_format\enterprise_standards\leef_events.log` | Public Offline Benchmark / Specification Reference |
| IETF Standard | IETF | RFC 5424 Syslog | `RFC 5424 structured` | **SPECIFICATION_DERIVED_REFERENCE** | `data\fixtures\real_world\multi_format\enterprise_standards\rfc5424_syslog.log` | Public Offline Benchmark / Specification Reference |
| BSD Standard | BSD / IETF | RFC 3164 Syslog | `RFC 3164 legacy` | **SPECIFICATION_DERIVED_REFERENCE** | `data\fixtures\real_world\network_security\cisco_asa\cisco_asa.log` | Public Offline Benchmark / Specification Reference |
| W3C Standard | W3C | Extended Log File Format | `W3C space-delimited` | **SPECIFICATION_DERIVED_REFERENCE** | `data\fixtures\real_world\application\iis\iis_w3c.log` | Public Offline Benchmark / Specification Reference |
| Structured Document | W3C / Microsoft | XML / Windows Event | `XML` | **SPECIFICATION_DERIVED_REFERENCE** | `data\fixtures\real_world\identity\windows_security\win_security_4624_4625.xml` | Public Offline Benchmark / Specification Reference |

## 2. Integrity Rule on Synthetic vs Real Telemetry
Phase 17 strictly enforces that:
1. No synthetic or generated test payload is described as a live production capture.
2. Specification-derived fixtures (e.g. RFC5424 structured data samples, W3C Extended access logs) are clearly marked as `SPECIFICATION_DERIVED_REFERENCE`.
3. Real-world public datasets (Palo Alto PAN-OS traffic, FortiOS UTM logs, Suricata EVE JSON, Snort Fast Alerts, Zeek Conn logs, Linux Auditd) are verified from public benchmark archives with active privacy and PII sanitization.
