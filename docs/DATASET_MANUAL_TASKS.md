# ULPF Dataset Manual Tasks Register (Phase 50)

**Document ID:** ULPF-DOC-DATA-008  
**Status:** ACTIVE  
**Audit Date:** 2026-09-05  

---

## 1. Overview

Per Phase 50 of the Dataset Governance framework, this register documents **only** tasks that strictly require human authorization, legal assessment, hardware provisioning, or external credentials.

---

## 2. Pending Manual Tasks

| Task ID | Component | Required Human Action | Rationale / Dependency | Priority |
| :--- | :--- | :--- | :--- | :---: |
| **TSK-MAN-DATA-001** | **Organization Approval** | Review and approve `docs/DATASET_ORGANIZATION_PLAN.md` before physical directory moves are executed. | Phase 21 Mandatory Stop Rule. | **CRITICAL** |
| **TSK-MAN-DATA-002** | **Perimeter Log Acquisition** | Provide sanitized/authorized sample logs from enterprise perimeter devices (Palo Alto, Fortinet, Cisco ASA). | Live hardware logs cannot be downloaded from untrusted public sources. | **HIGH** |
| **TSK-MAN-DATA-003** | **External Benchmark Mount** | Provision dedicated local storage or NAS volume for Tier 3 benchmark files (> 500 MB) when running scale tests. | Avoids local Git repository bloat. | **MEDIUM** |
| **TSK-MAN-DATA-004** | **LUK License Review** | Review redistribution terms of Cisco and Huawei alarm template knowledge bases for external demo. | Ensure compliance with vendor documentation licenses. | **LOW** |
