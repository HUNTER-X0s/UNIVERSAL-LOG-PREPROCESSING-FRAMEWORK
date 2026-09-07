# ULPF Phase 11 — Unified Stack Performance Certification

**Mission:** NTRO / Smart India Hackathon — SIH26156  
**Benchmarked System:** Universal Log Pre-processing Framework (ULPF)  
**Execution Environment:** Windows-11 AMD64 | Python 3.12.10  
**Status:** FULLY CERTIFIED (All 5 Gates Passed)  
**Certification Date:** 2026-09-08  

---

## 1. Executive Performance Summary

Phase 11 performance certification establishes empirical, anti-fabrication verified operational metrics across the complete ULPF pipeline. Testing was conducted with real monotonic high-resolution clocks (`time.perf_counter`), zero mocked timing, and authentic log corpora.

```
+-----------------------------------------------------------------------------+
|                     ULPF PHASE 11 PERFORMANCE SCORECARD                     |
+------------------------------------+------------------+---------------------+
| Component / Subsystem              | Throughput       | p95 Latency         |
+------------------------------------+------------------+---------------------+
| End-to-End Mission Pipeline        | 94,399.29 eps    | 0.3053 ms (batch)   |
| Multi-Format Parser Runtime        | 15,740.57 eps    | 0.1351 ms (CEF)     |
| In-Memory Entity Relationship Graph| 961,168.78 qps   | 0.0012 ms           |
| Security Posture Engine            | 107,175.85 evals | 0.0220 ms           |
| Signal Fusion Engine               | 47,919.92 evals  | 0.0282 ms           |
| Early Warning Threat Acceleration  | 43,519.55 evals  | 0.0348 ms           |
+------------------------------------+------------------+---------------------+
```

---

## 2. Multi-Format Parser Performance Breakdown

Evaluated across 15 standard and vendor-specific log formats (1,000 iterations each):

| Format | Parser Engine | Throughput (eps) | Avg Latency (ms) | p50 (ms) | p95 (ms) | p99 (ms) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **JSON** | `GenericJsonParser` | 27,972.89 | 0.0355 | 0.0522 | 0.0603 | 0.0715 |
| **Syslog 3164** | `SyslogRFC3164Parser` | 22,804.50 | 0.0435 | 0.0452 | 0.0754 | 0.1344 |
| **Syslog 5424** | `SyslogRFC5424Parser` | 19,831.55 | 0.0502 | 0.0198 | 0.0974 | 0.1380 |
| **Cloud Audit** | `CloudAuditParser` | 23,506.46 | 0.0423 | 0.0444 | 0.0753 | 0.1103 |
| **KV Pairs** | `KeyValueParser` | 21,648.58 | 0.0459 | 0.0421 | 0.0819 | 0.1147 |
| **LEEF** | `LeefParser` | 21,129.68 | 0.0470 | 0.0608 | 0.0783 | 0.1266 |
| **W3C Web** | `W3CParser` | 22,357.65 | 0.0445 | 0.0519 | 0.0737 | 0.1165 |
| **XML Event** | `XmlParser` | 20,447.58 | 0.0487 | 0.0477 | 0.0819 | 0.1215 |
| **Cisco Syslog**| `CiscoSyslogParser` | 18,720.97 | 0.0532 | 0.0617 | 0.0899 | 0.1396 |
| **FortiGate** | `FortiGateParser` | 17,490.28 | 0.0569 | 0.0781 | 0.0923 | 0.1170 |
| **Suricata EVE**| `SuricataEveParser` | 17,288.75 | 0.0576 | 0.0543 | 0.0931 | 0.1315 |
| **CEF** | `CefParser` | 14,836.36 | 0.0672 | 0.0354 | 0.1351 | 0.1877 |
| **Linux Auditd**| `LinuxAuditdParser` | 13,810.76 | 0.0722 | 0.0540 | 0.1787 | 0.2010 |
| **Palo Alto** | `PaloAltoPanOSParser` | 8,924.69 | 0.1118 | 0.0734 | 0.2443 | 0.3204 |
| **CSV** | `GenericCsvParser` | 5,064.57 | 0.1971 | 0.0927 | 0.4134 | 0.6822 |

**Combined Multi-Format Parsing Rate:** $15,740.57\text{ events per second}$.

---

## 3. End-to-End Pipeline Performance

- **Test Load:** 500 batches of 20 events ($10,000$ raw telemetry records).
- **Total Execution Time:** $0.1059\text{ seconds}$.
- **Net Ingestion & Analysis Throughput:** $94,399.29\text{ eps}$.
- **Batch Processing Latencies:**
  - Average: $0.1589\text{ ms}$
  - p50: $0.1328\text{ ms}$
  - p95: $0.3053\text{ ms}$
  - p99: $0.4136\text{ ms}$

---

## 4. Entity Graph Store Performance

- **Topology:** 500 entities (nodes), 2,000 relationships (edges).
- **Workload:** 500 multi-hop neighborhood queries.
- **Throughput:** $961,168.78\text{ queries per second}$.
- **Latencies:**
  - Average: $0.0008\text{ ms}$ ($0.8\text{ }\mu\text{s}$)
  - p50: $0.0007\text{ ms}$ ($0.7\text{ }\mu\text{s}$)
  - p95: $0.0012\text{ ms}$ ($1.2\text{ }\mu\text{s}$)
  - p99: $0.0022\text{ ms}$ ($2.2\text{ }\mu\text{s}$)

---

## 5. Certification Gates & Compliance Status

| Requirement Gate | Threshold | Achieved | Status |
| :--- | :--- | :--- | :--- |
| Aggregate Parser Throughput | $\ge 5,000\text{ eps}$ | $15,740.57\text{ eps}$ | **PASS** |
| Graph Traversal p95 Latency | $< 10.0\text{ ms}$ | $0.0012\text{ ms}$ | **PASS** |
| Posture Evaluation Throughput | $\ge 1,000\text{ evals/sec}$| $107,175.85\text{ evals/sec}$ | **PASS** |
| Early Warning Engine Rate | $\ge 1,000\text{ evals/sec}$| $43,519.55\text{ evals/sec}$ | **PASS** |
| Pipeline Batch p95 Latency | $< 50.0\text{ ms}$ | $0.3053\text{ ms}$ | **PASS** |

The framework comfortably exceeds every minimum operational threshold mandated by SIH26156.
