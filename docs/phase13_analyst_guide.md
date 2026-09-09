# ULPF Phase 13 Analyst Guide

**Audience:** Incident Responders, Threat Hunters, and Forensic Analysts  
**System Scope:** Investigation Workbench, Dual View Analysis, Attack Story Exploration, and Case Packaging  

---

## 1. Investigation Workflow

### One-Click Investigation Pivot
From any alert or entity (e.g. IP `10.1.1.5` or user `admin`):
1. Execute `OneClickInvestigationService.investigate(seed_value)`.
2. Review aggregated multi-source events, correlated detections, and timeline.
3. Inspect the chronological **Attack Story** mapping event progression to MITRE ATT&CK tactics.

---

## 2. Lossless + Semantic Dual View

Analysts never have to choose between raw forensics and normalized clarity:
- **Raw Evidence Tab:** Exact bytes, encoding, and SHA-256 digest.
- **Normalized UCE Tab:** Structured universal fields (`source.ip`, `destination.ip`, `event.action`).
- **Standard Projections Tab:** OCSF v1.1 security finding representation and OpenTelemetry log records.
- **Lineage Verification:** 13-stage cryptographic hash record from wire ingestion to case package.

---

## 3. Evidence-Grounded AI Copilot

When querying the offline AI Analyst Assistant:
- **[VERIFIED FACT]:** Cites exact event IDs and cryptographic hashes present in the local database.
- **[SYSTEM INFERENCE]:** Deduces probable attacker intent or lateral correlation.
- **[ANALYST SUGGESTION]:** Prescribes concrete containment or hunting actions.
- **Action Execution:** Proposing an action (e.g. `ISOLATE_HOST`) requires operator-level authentication and an audit trail.
