# PHASE 4 ADVERSARIAL EXIT FINDINGS
**Project:** Universal Log Preprocessing Framework (ULPF)  
**Problem Statement:** SIH26156 — NTRO Perimeter Network & Security Telemetry  
**Date:** 2026-09-06  

---

## 1. Summary of Findings

| Severity | Total Discovered | Corrected | Open Non-Blocking | Blocking |
|---|---|---|---|---|
| **CRITICAL** | 0 | 0 | 0 | 0 |
| **HIGH** | 2 | 2 | 0 | 0 |
| **MEDIUM** | 7 | 2 | 5 | 0 |
| **LOW** | 4 | 0 | 4 | 0 |
| **Total** | **13** | **4** | **9** | **0** |

---

## 2. Corrected Findings

### PH4-FIND-01 [HIGH] OCSF Detection Finding `class_uid` Incorrect
- **File:** `packages/semantic/ulpf_semantic/projections/ocsf/mapper.py`
- **Root Cause:** Detection Finding previously mapped to `class_uid = 2002` (which maps to Vulnerability Finding in OCSF v1.1.0).
- **Correction:** Corrected to `class_uid = 2004` (Detection Finding) per official OCSF specification.
- **Verification:** Asserted in `tests/test_semantic_ocsf.py` line 70 and verified via `scripts/run_phase4_exit_audit.py`.

### PH4-FIND-02 [HIGH] OCSF `status_id` Inverted / Non-Standard
- **File:** `packages/semantic/ulpf_semantic/projections/ocsf/mapper.py`
- **Root Cause:** Projector mapped `status_id` using a 1/2 boolean scheme instead of standard OCSF v1.1.0 status definitions (`1 = Unknown`, `2 = Success`, `3 = Failure`).
- **Correction:** Implemented official OCSF triplet: `ALLOWED`/`SUCCESS` mapped to `2` (Success); `DENIED`/`FAILURE`/`BLOCKED` mapped to `3` (Failure); unknown mapped to `1`.
- **Verification:** Unit test and independent benchmark runner verify `status_id = 3` for firewall drops.

### PH4-FIND-03 [MEDIUM] Unconditional `SemanticStatus.FULL` Assignment
- **File:** `packages/semantic/ulpf_semantic/mapping/engine.py`
- **Root Cause:** `SemanticMapper` assigned `status = SemanticStatus.FULL` unconditionally, even for fallback classifications with 0.50 confidence.
- **Correction:** Implemented graduated status threshold:
  - $\text{score} \ge 0.90 \implies \text{SemanticStatus.FULL}$
  - $\text{score} \ge 0.70 \implies \text{SemanticStatus.PARTIAL}$
  - $\text{score} < 0.70 \implies \text{SemanticStatus.UNKNOWN}$
- **Verification:** Tested against unknown vendor logs; outputs `status = UNKNOWN` with confidence `0.50`.

### PH4-FIND-09 [MEDIUM] Benchmark Runner Script Previously Missing
- **File:** `scripts/run_phase4_benchmarks.py`
- **Root Cause:** Benchmark metrics were measured inline without a dedicated automation script.
- **Correction:** Created `scripts/run_phase4_benchmarks.py` producing `reports/phase4_benchmarks.json`.
- **Verification:** Script runs independently and outputs 22,000+ eps.

---

## 3. Open Non-Blocking Findings (Scoped for Phase 5)

### PH4-FIND-04 [MEDIUM] Raw Payload SHA-256 Not Forwarded in SemanticEvent
- **File:** `packages/semantic/ulpf_semantic/mapping/engine.py`
- **Impact:** `SemanticEvent` forwards `uce_event_id` and `raw_event_id`, but does not replicate `raw_sha256`.
- **Justification for Non-Blocking:** Raw payload integrity is fully preserved in the Phase 3 UCE repository and accessible via `uce_event_id`. Root contract schema modification is deferred to Phase 5.

### PH4-FIND-05 [MEDIUM] Hardcoded Classification Rules in Python Source
- **File:** `packages/semantic/ulpf_semantic/classification/classifier.py`
- **Impact:** Adding new log sources requires editing Python code.
- **Justification for Non-Blocking:** Hardcoded rules cover all Phase 4 scope fixtures deterministically. Externalizing rules to YAML/JSON is the explicit design mission of Phase 5 (AI onboarding).

### PH4-FIND-06 [MEDIUM] Entity Type Taxonomy Partially Extracted
- **File:** `packages/semantic/ulpf_semantic/entities/extractor.py`
- **Impact:** Only `IP`, `HOST`, `USER`, and `CLOUD_RESOURCE` entities are extracted at runtime; 13 other entity types (`PROCESS`, `FILE`, etc.) remain enum definitions.
- **Justification for Non-Blocking:** Core network and security entities are fully operational without runtime errors. Expanded entity graph extraction is scheduled for Phase 5.

### PH4-FIND-07 [MEDIUM] Heuristic Risk Decisions Lack Discrete Traces
- **File:** `packages/semantic/ulpf_semantic/mapping/engine.py`
- **Impact:** Classification generates an explicit `DecisionTrace`, while risk evaluation only attaches reason codes.
- **Justification for Non-Blocking:** Reason codes (`SECURITY_FINDING_EVENT`, `RESTRICTIVE_POLICY_ACTION`) provide transparent auditability for SOC analysts.

### PH4-FIND-08 [MEDIUM] OCSF Validator Evaluates Base Fields
- **File:** `packages/semantic/ulpf_semantic/projections/ocsf/validator.py`
- **Impact:** Validates mandatory fields and types rather than bundling the entire 50MB official OCSF JSON metamodel.
- **Justification for Non-Blocking:** Structural integrity is maintained and outputs are validated without imposing heavy schema compilation overhead.

### PH4-FIND-10 [LOW] Forward-Compatible EventCategory Stubs
- **File:** `packages/semantic/ulpf_semantic/taxonomy/categories.py`
- **Description:** 42 categories are defined in taxonomy; 7 are active in current classifier rules.

### PH4-FIND-11 [LOW] Action Merging of Accept and Allow
- **File:** `packages/semantic/ulpf_semantic/taxonomy/actions.py`
- **Description:** `accept` and `allow` unify into `ActionTaxonomy.ALLOW`.

### PH4-FIND-12 [LOW] IndicatorType.EMAIL Unextracted
- **File:** `packages/semantic/ulpf_semantic/indicators/extractor.py`
- **Description:** `IndicatorType.EMAIL` is defined but unparsed in the current indicator regex set.

### PH4-FIND-13 [LOW] Conservative Unit Test Benchmark Threshold
- **File:** `tests/test_semantic_benchmarks.py`
- **Description:** Asserts `> 500 eps`, whereas actual performance is `> 11,000 eps`.
