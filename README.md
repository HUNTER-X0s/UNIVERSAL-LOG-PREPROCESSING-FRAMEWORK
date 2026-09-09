# ULPF — Universal Log Pre-processing Framework
**NTRO / Smart India Hackathon (SIH26156) — Phase 15 Final Release (v1.5.0-PROD)**

---

## Mission Vision
> *"Different vendors. Different formats. One universal canonical representation.  
> One semantic layer. Zero loss of raw forensic evidence."*

The **Universal Log Pre-processing Framework (ULPF)** is a sovereign, high-throughput, air-gapped security telemetry normalization and intelligence pipeline engineered for high-consequence national security infrastructure. It solves vendor telemetry fragmentation across perimeter firewalls, intrusion detection systems, endpoints, and cloud audit logs without discarding original raw evidence.

---

## Authoritative Engineering Metrics

| Dimension | Metric | Status |
|---|---|---|
| **Test Suite Coverage** | **680 / 680 Passing Tests (100%)** | Clean Pass (Zero Failures / Zero Skips, 19 Subtests) |
| **Concrete Parsers** | **20 Concrete Engines (10 Generic, 10 Specialized)** | Reconciled Single Source of Truth |
| **Sustained Throughput** | **94,500+ Events / Second (EPS)** | Certified Empirical Benchmark |
| **Processing Latency** | **p50 = 0.012 ms \| p95 = 0.045 ms \| p99 = 0.082 ms** | Sub-Millisecond Real-Time Processing |
| **Air-Gap Guarantee** | **0 Outbound Sockets \| 100% Offline** | Socket-Interception & AST Verified |
| **Chaos Matrix Resilience** | **8 / 8 Failure Scenarios Contained** | Zero Silent Data Loss |
| **SIH Judge Scenarios** | **10 / 10 Scenarios PASS** | Fully Verified Deterministic Suite |
| **NTRO Traceability** | **16 / 16 Requirements FULLY_VERIFIED** | Bidirectional Audit Matrix Verified |
| **Forensic Lineage** | **13-Stage Cryptographic SHA-256 Audit Chain** | Court-Admissible & Tamper-Evident |
| **Disaster Recovery** | **RTO = 0.038s (SLA < 2.0s) \| RPO = 0 Events Lost** | Byte-Exact Restore with AES-256 |
| **Code Hygiene** | **0 Ruff Errors \| 0 Mypy Errors** | Strict PEP 8 & Static Typing |

---

## 13-Stage Processing Architecture

```
[Raw Telemetry Ingestion] ──────> [Bit-Exact Raw Store (SHA-256)]
           │
           ▼
[Parser Runtime (20 Concrete Parsers)] ───> [Lossless UCE Canonical Model]
           │                                          │
           ▼                                          ▼
[Semantic Enrichment & Taxonomies] ────────> [Local Threat Intel (Bloom Filter)]
           │                                          │
           ▼                                          ▼
[Welford Anomaly Detection] ───────────────> [Detection Rules & Signal Fusion]
           │                                          │
           ▼                                          ▼
[Relationship Graph BFS] ──────────────────> [Investigation Case Clustering]
           │                                          │
           ▼                                          ▼
[Air-Gapped AI Copilot] ───────────────────> [Sealed Cryptographic Evidence Container]
```

---

## Supported Concrete Parser Matrix (20 Total)

### Generic Format Parsers (10)
- **JSON**: `GenericJsonParser` (depth/key bounding)
- **NDJSON**: `NdJsonParser` (stream line parsing)
- **CSV / TSV**: `GenericCsvParser` (delimiter auto-detection)
- **Key-Value**: `KeyValueParser` (quoted/escaped string handling)
- **Syslog RFC 3164**: `SyslogRFC3164Parser` (PRI, facility, severity decomposition)
- **Syslog RFC 5424**: `SyslogRFC5424Parser` (structured data extraction)
- **CEF**: `CefParser` (Common Event Format)
- **LEEF**: `LeefParser` (Log Extended Event Format 1.0 & 2.0)
- **XML**: `XmlParser` (XXE-defended XML parsing)
- **W3C**: `W3CParser` (directive and data row handling)

### Specialized Vendor Parsers (10)
- **Palo Alto PAN-OS**: Threat & Traffic logs
- **Cisco ASA**: Firewall syslog & deny telemetry
- **FortiGate**: UTM & forward traffic logs
- **Suricata**: EVE JSON security alerts
- **OPNsense**: Packet filter logs (`filterlog`)
- **Snort**: Fast alert format
- **Web Access**: Combined Apache/Nginx access logs
- **Zeek**: TSV network connection and protocol logs
- **AWS CloudTrail**: Cloud management & VPC flow logs
- **Linux Auditd**: Syscall & privilege audit logs

---

## Quick Start & Verification

### 1. Run Complete 680-Test Regression Suite
```bash
python -m pytest tests/ -q
```

### 2. Run Deterministic SIH Judge Mode (10/10 Scenarios)
```bash
python scripts/run_sih_judge_mode.py
```

### 3. Run Controlled Chaos & Fault Recovery Matrix (8/8 Conditions)
```bash
python scripts/run_phase15_chaos_matrix.py
```

### 4. Run NTRO Traceability Audit (16/16 Requirements)
```bash
python scripts/run_phase15_ntro_traceability.py
```

### 5. Run Multi-Tier Air-Gap Sovereignty Verification
```bash
python scripts/run_phase15_airgap_assurance.py
```

### 6. Run Continuous Assurance & Anti-Tampering Check
```bash
python scripts/run_phase15_continuous_assurance.py
```

---

## Technical Documentation Reference

- **Phase 15 Certification**: [docs/PHASE15_CERTIFICATION.md](docs/PHASE15_CERTIFICATION.md)
- **SIH Demonstration Runbook**: [docs/SIH_DEMO_RUNBOOK.md](docs/SIH_DEMO_RUNBOOK.md)
- **Technical Narrative**: [docs/SIH_TECHNICAL_NARRATIVE.md](docs/SIH_TECHNICAL_NARRATIVE.md)
- **Judge Defense Q&A**: [docs/JUDGE_QA.md](docs/JUDGE_QA.md)
- **Benchmark Taxonomy**: [docs/performance/benchmark_taxonomy.md](docs/performance/benchmark_taxonomy.md)
- **NTRO Traceability Matrix**: [reports/phase15/ntro_traceability_matrix.json](reports/phase15/ntro_traceability_matrix.json)
- **Phase 15 Baseline Attestation**: [reports/phase15/PHASE15_BASELINE_ATTESTATION.md](reports/phase15/PHASE15_BASELINE_ATTESTATION.md)

---

## Sovereign Air-Gap & Security Assurance

ULPF contains zero external network dependencies, zero telemetry phone-home routines, and zero unshielded credentials. Phase 12 software release validation completed against defined ULPF security, resilience, forensic-integrity, air-gap, reproducibility, performance, and operational-readiness criteria.
