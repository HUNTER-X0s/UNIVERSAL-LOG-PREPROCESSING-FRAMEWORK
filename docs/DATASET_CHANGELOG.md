# ULPF Dataset Corpus Changelog

**Document ID:** ULPF-DOC-DATA-CHANGELOG-001  

---

## Version 3.1.0 (2026-09-06) - Final Forensic Audit, Baseline Reconciliation & Phase 3 Gate
- **Mathematical Baseline Reconciliation:** Reconciled historical reported numbers across Milestones 0 to 3. Proved that all raw telemetry payload bytes remained 100% frozen and invariant at `6,409,385,655 bytes` (286 payload files).
- **Honest Provenance Reclassification:** Formally classified authentic external captures as `REAL_PUBLIC_DATASET` (SecRepo, Zed, LogHub, LUK) and specification-engineered vendor logs as `SPECIFICATION_DERIVED` or `ULPF_ADVERSARIAL`.
- **PCAP Scope Demarcation:** Removed PCAP from log format claims (classified as binary packet capture artifact). Formally verified 19 distinct log and telemetry formats.
- **Privacy & Security Verification:** Verified 0 real credentials or private keys; documented benign documentation examples and Nessus scanner artifacts.
- **Master Deterministic Audit Script:** Created `scripts/run_master_forensic_audit.py` to allow independent, reproducible verification of the complete corpus.
- **Phase 3 Formal Gate:** Declared `READY_FOR_PHASE_3` across all 17 gate dimensions.

## Version 3.0.0 (2026-09-05) - Universal Expansion & Phase 3 Readiness
- **Added 14 New Telemetry Families:** Juniper SRX, OPNsense Filterlog, Cisco IOS-XE, WireGuard, Envoy Proxy, Microsoft IIS, Java Multiline, Python Structlog, Go Zap, Azure Activity, Azure NSG, GCP Audit, Containerd CRI, MySQL, Redis, Apache Kafka, OpenTelemetry (OTel).
- **Added 4 Advanced Adversarial Vectors:** Deeply nested JSON (35 levels), UTF-8 BOM, impossible timestamps, and mixed delimiter injections.
- **Upgraded DATASET_MANIFEST.json:** Upgraded to v3.0.0 schema registering all 39 active dataset families.
- **Maintained 100% Baseline Preservation:** All 306 pre-expansion files preserved with zero byte mutations.

## Version 2.0.0 (2026-09-05) - Core NTRO Perimeter Expansion
- **Added Core Perimeter Fixtures:** Palo Alto Networks PAN-OS, Fortinet FortiGate, Cisco ASA, Check Point Gaia, Suricata EVE-JSON, Snort Fast, AWS CloudTrail, AWS VPC Flow, Kubernetes Audit, Linux Auditd, Windows Security XML.
- **Reorganized Data Directory:** Established 3-tier architecture (`fixtures/`, `reference/`, `benchmarks/`).

## Version 1.0.0 (2026-09-04) - Initial Audited Baseline
- Audited Loghub 2.0 (16 systems), LUK Alarm KBs (Cisco, Huawei), SecRepo 4.17 GB, and Zed multi-format data.
