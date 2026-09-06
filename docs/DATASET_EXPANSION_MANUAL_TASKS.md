# ULPF Dataset Expansion Manual Tasks Register

**Document ID:** ULPF-DOC-DATA-MANUAL-002  
**Status:** ACTIVE  

---

## 1. Overview

Per Phase 37 of the Master Mission, this register records strictly human-required tasks that cannot or must not be automated without external credentials, physical hardware, or legal authorization.

---

## 2. Manual Tasks Register

| Task ID | Component | Required Human Action | Trigger / Dependency | Priority |
| :--- | :--- | :--- | :--- | :---: |
| **TSK-EXP-DATA-001** | **Live Hardware Capture** | Provision live perimeter tap or mirror port on physical NTRO testbed hardware (Cisco ASA, Palo Alto PA-3200, FortiGate 100F) to collect authentic high-volume raw syslog streams for the final SIH presentation. | SIH Final On-Site Demonstration | **CRITICAL** |
| **TSK-EXP-DATA-002** | **External Benchmark Mount** | Configure dedicated high-speed NVMe or NAS mount (`ULPF_BENCHMARK_ROOT`) to host the 4.17 GB SecRepo logs when executing 100k+ eps backpressure benchmarks. | Performance Stress Testing | **HIGH** |
| **TSK-EXP-DATA-003** | **Vendor Redistribution Review** | Confirm with NTRO legal/security officers whether proprietary hardware syslog extracts require special export redactions before external presentation. | Public Release / Open Source Demo | **MEDIUM** |
