# ULPF — User & Operator Guide

**System:** Universal Log Pre-processing Framework  
**Version:** v2.1.0-Production (TRL 8/8 Certified)  
**Problem Statement:** SIH26156 · National Technical Research Organisation (NTRO)  

---

> [!TIP]
> **Dedicated Guide for SIH / NTRO Judges:**  
> For an exhaustive, panel-by-panel walkthrough detailing every feature, interactive journey, and statutory evidence tool in the operations console, please see the **[Judges Frontend User Guide](JUDGES_FRONTEND_USER_GUIDE.md)**.

---

## 1. Quick Navigation & Default Credentials

Access the web console at [`http://localhost:5173`](http://localhost:5173).

| Role | Username | Password | Access Level |
| :--- | :--- | :--- | :--- |
| **Platform Admin** *(Recommended)* | `vikram.anand` | `Ulpf@Pl@tf#1rM!x` | Superuser: All 32 panels, ingestion, RBAC, and synthesis |
| **Detection Engineer** | `kavya.reddy` | `Ulpf@D3tect#2pQw` | Rules, parsers, threat intelligence, and ReDoS lab |
| **SecOps Analyst** | `arunav.sharma` | `Ulpf@N4!yst#8x2K` | Real-time logs, 9-tab event drawer, and playbooks |
| **Auditor / Viewer** | `priya.kapoor` | `Ulpf@V!3wer#4mZ9` | Compliance, §63 BSA 2023 certs, and Merkle ledger |

---

## 2. Core Functional Groups

1. **Operations Hub:** Real-time SOC Command Center, AI Pipeline Copilot, Live Logs Stream, Log Intake, System Health, and Telemetry Simulator.
2. **Parsers & Pipeline:** 20 Glushkov Deterministic DFA engines, Parser Workbench, Autonomous <30s Synthesizer, ReDoS Shield, and SIEM Cost Optimizer.
3. **Unified Core:** Universal Transpiler, UCE v2.1 Normalization, DPDP 2023 Privacy Shield, Chronos Clock Normalizer, and Multi-Standard Projections (OCSF 1.1 / OTel / ECS).
4. **Security Intelligence:** High-fidelity Alerts, Streaming Anomaly Detection (Welford $O(1)$), Threat Intel, Investigation Desk, and Response Playbooks.
5. **Compliance & Forensics:** 13-stage Cryptographic Lineage, Automated §63 BSA 2023 Evidence Attestation, MITRE ATT&CK Matrix, and India Statutory Compliance.
6. **Blockchain & Trust:** Proof-of-Action (PoA) Merkle-DAG Explorer with 1-click cryptographic tamper testing.

---

## 3. Core API Reference

- `POST /api/v1/intake/raw` — Verbatim raw telemetry ingestion (Status 202 Accepted).
- `GET /api/v1/platform/health` — Foundation health, micro-service status, and latency.
- `GET /api/v1/platform/parsers` — List active concrete DFA parsers and state counts.
- `POST /api/v1/mission/posture` — 5-factor defense security posture evaluation.
- `POST /api/v1/forensics/certificate` — Generate Section 63 BSA 2023 court-admissible certificate.

---

*For complete visual guides, workflows, and evaluation journeys, consult the [Judges Frontend User Guide](JUDGES_FRONTEND_USER_GUIDE.md).*
