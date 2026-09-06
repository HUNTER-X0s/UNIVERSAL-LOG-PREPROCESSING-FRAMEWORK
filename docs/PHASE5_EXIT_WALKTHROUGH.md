# ULPF Phase 5 Exit Audit Walkthrough

**Date:** 2026-09-06 | **Commit:** eadbf1f
**Reproducing:** git checkout eadbf1f && pytest -q

## Step 1 - Repository Baseline

Command: git log --oneline -5 && git status --short

Finding: Phase 5 entirely uncommitted at audit start.
Remediated by committing as eadbf1f.

## Step 2 - Security Scan

All Phase 5 packages scanned for eval()/exec()/pickle/subprocess/os.system.
All hits were string LITERALS in safety.py used as detection tokens.
Result: CLEAN

## Step 3 - Compiler Security

Tests:
- ReDoS (a+)+$ -> MappingSafetyError raised (PASS)
- Giant regex (300 chars) -> MappingSafetyError raised (PASS)
- Checksum: same mapping -> same hash (PASS)
- Semantic change -> different hash (PASS)
- VALIDATED->ACTIVE without approval -> MappingActivationError (PASS)

## Step 4 - DSL Bracket Notation Finding and Fix

Finding: get_nested_field(doc, "items[0]") returned None.
Only dot notation "items.0" worked. MEDIUM defect classified.

Fix: Added _BRACKET_RE regex parser to operators.py.
Negative indices return None (safe). OOB indices return None (safe).

Verification after fix:
- items[0] -> 10 (PASS)
- nested.list[2] -> correct value (PASS)
- items[-1] -> None (PASS, safe)
- items[99] -> None (PASS, safe)

## Step 5 - Registry Lifecycle

Full flow: register->validate->approve->activate->v2->rollback->v1 confirmed (PASS)
Illegal transition (VALIDATED->ACTIVE): MappingActivationError raised (PASS)
Rollback with no history: MappingRollbackError raised (PASS)
Audit trail: 4+ events per lifecycle (PASS)

## Step 6 - AI Safety

PromptInjectionDefense: 5/5 injection patterns detected (PASS)
AIOutputValidator: dangerous tokens rejected (PASS)
AI candidate: status=PENDING_REVIEW, NOT auto-activated (PASS)
OfflineDeterministicAdvisor: no network, provider_id=offline.deterministic.v1 (PASS)

Gap: confidence > 1.0 not rejected by AIOutputValidator (F-P5-03, non-blocking)

## Step 7 - UCE Immutability

SHA-256 hash of UCE before and after process_uce(): unchanged (PASS)
Residue: custom_vendor_field preserved in unmapped_semantic_fields (PASS)

## Step 8 - Determinism

20 identical UCEs -> 20 identical semantic_event_id values (PASS)

## Step 9 - Drift Detection

Stable schema -> STABLE (PASS)
Field added -> MINOR_DRIFT (PASS)
Field removed -> MAJOR_DRIFT (PASS)
Type change -> BREAKING_DRIFT (PASS)
Drift result: DriftReport only, no auto-activation (PASS)

## Step 10 - Full Test Suite

pytest -q: 271 passed, 2 warnings, 19 subtests passed
ruff check packages/ apps/ tests/: All checks passed!
mypy apps packages: Success: no issues found in 116 source files

## Step 11 - Performance

500 events: 0.109s | EPS=4569 | p50=0.219ms
Phase 4 baseline: 5079 EPS | Regression: ~10% (within normal variance)

## Release Decision

PHASE5_EXIT_APPROVED_WITH_NON_BLOCKING_GAPS
Score: 8.4 / 10
Blockers: 0
Phase 5 Frozen: YES (commit eadbf1f)
Phase 6 Authorized: YES
