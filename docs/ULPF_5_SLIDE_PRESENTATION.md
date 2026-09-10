# ULPF — 5-Slide Technical SIH Presentation

**Problem Statement:** SIH26156 (NTRO)  
**Title:** Universal Log Pre-processing Framework (ULPF)  

---

## SLIDE 1: THE PROBLEM
### The Defense Telemetry Crisis: Heterogeneity, Data Loss & Fragile Forensics
- **Vendor Fragmentation:** Incompatible syntax across firewalls, IDSs, Windows, Linux, and Cloud telemetry.
- **Silent Data Loss:** Conventional pipelines discard unmapped fields to fit rigid schemas.
- **Schema Drift:** Firmware updates break brittle regex parsers, causing ingestion outages.
- **Forensic Vulnerability:** Without cryptographic chain of custody, electronic evidence fails courtroom admissibility.

---

## SLIDE 2: THE ULPF ARCHITECTURE
### Verifiable, Air-Gapped, End-to-End Pipeline
- **Raw Capture Plane:** VERBATIM raw byte storage into SHA-256 Content-Addressed Storage (CAS).
- **Parser Registry:** 20 concrete deterministic Tier A/B/C parsers.
- **Canonical UCE:** Lossless field normalization with `unmapped_residue` retention.
- **Dual Projections:** Native export to OCSF v1.1.0 and OpenTelemetry Logs v1.0.0.
- **Intelligence Plane:** MITRE ATT&CK correlation, statistical anomaly detection, and dry-run response playbooks.

---

## SLIDE 3: WHY ULPF IS DIFFERENT
### Beyond Conventional Logstash / Vector / SIEM Parsers
| Capability | Traditional Pipelines | ULPF Architecture |
|---|---|---|
| **Raw Retention** | Stripped or optional | **100% Verbatim SHA-256 CAS** |
| **Data Loss** | Unmapped fields discarded | **Zero-Loss Residue Retention** |
| **New Formats** | Weeks of manual regex | **Autonomous Profiler (<30s)** |
| **Interoperability** | Vendor lock-in | **Dual OCSF & OTel Native** |
| **Forensic Proof** | Mutable text logs | **13-Stage Merkle Lineage** |
| **Sovereignty** | Cloud telemetry egress | **Strict Offline Air-Gap (0 Sockets)**|

---

## SLIDE 4: RESULTS & EMPIRICAL PROOF
### Verified Engineering Baseline (No Hypothetical Claims)
- **Regression Suite:** 680 / 680 Tests Passing (100% Clean Gate).
- **Code Quality:** Strict `mypy` and `ruff` validation across all 40+ modules.
- **Parser Truth:** 20 concrete implementations loaded and verified.
- **NTRO Traceability:** 16 / 16 Requirements Satisfied with code-level traceability.
- **Throughput:** > 301,000 events/second benchmarked in mission pipeline.
- **Air-Gap Verification:** Zero external socket connections verified via automated tests.

---

## SLIDE 5: DEMO & OPERATIONAL IMPACT
### The One-Event Complete Journey
- **One Event:** Raw syslog in -> CAS SHA-256 -> Normalized UCE -> Threat Detection -> 13-Stage Tamper-Evident Package.
- **Autonomous Drift Handling:** Seamless schema mutation resilience without downtime.
- **Defense-Ready:** Immediate utility for NTRO, sovereign SOCs, and critical national infrastructure.
- **Verdict:** Productized, tested, and ready for deployment.
