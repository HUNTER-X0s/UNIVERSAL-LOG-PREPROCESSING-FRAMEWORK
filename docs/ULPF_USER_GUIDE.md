# ULPF — User & Operator Guide

**System:** Universal Log Pre-processing Framework  
**Version:** v1.0.0-sih  

---

## 1. System Navigation
- **Command Center:** Real-time platform status, throughput, and parser health.
- **Log Intake:** Direct HTTP POST raw telemetry ingestion endpoint (`/api/v1/intake/raw`).
- **Parser Registry:** Inspection of 20 loaded concrete parsers.
- **Investigation Workspace:** MITRE ATT&CK correlation and evidence package export.

## 2. API Reference
- `POST /api/v1/intake/raw` — Verbatim raw log ingest (Status 202 Accepted).
- `GET /api/v1/platform/health` — Foundation health status.
- `GET /api/v1/platform/parsers` — List active concrete parsers.
- `POST /api/v1/mission/posture` — 5-factor security posture evaluation.
