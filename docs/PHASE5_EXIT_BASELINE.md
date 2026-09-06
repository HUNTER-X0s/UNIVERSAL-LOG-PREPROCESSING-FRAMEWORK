# ULPF Phase 5 Exit Baseline

**Date:** 2026-09-06
**Commit (pre-audit):** 8cfe492 | **Commit (post-audit):** eadbf1f

## FINDING GIT-UNCOMMIT (HIGH - REMEDIATED)

At audit start all Phase 5 code was uncommitted (20 modified + 20 untracked files).
Remediated by committing as eadbf1f during this audit.

## Package Inventory

### packages/mapping/ulpf_mapping/ (9 files)
- models.py - MappingDefinition, CompiledMapping, MappingLifecycleState
- compiler/compiler.py - MappingCompiler (schema validate, ReDoS safe, SHA-256)
- dsl/operators.py - get_nested_field, evaluate_condition, validate_regex_safety
- registry/registry.py - MappingRegistry (7-state lifecycle, rollback, audit trail)
- errors.py - Typed error hierarchy

### packages/onboarding/ulpf_onboarding/ (6 files)
- models.py - OnboardingResult, SourceProfile, DriftReport, ReplayResult
- profiler.py - SampleProfiler (format detect, field type inference)
- drift.py - SchemaDriftDetector (STABLE/MINOR_DRIFT/MAJOR_DRIFT/BREAKING_DRIFT)
- replay.py - MappingReplayEngine (deterministic replay)
- service.py - OnboardingService (orchestration + governance)

### packages/ai/ulpf_ai/ (6 files)
- interfaces.py - AISemanticAdvisor abstract interface
- models.py - AISuggestion, AIConfidenceBreakdown
- providers/offline.py - OfflineDeterministicAdvisor (no network)
- safety.py - PromptInjectionDefense + AIOutputValidator

## Contracts (7 Phase 5 JSON Schemas, Draft 2020-12)
semantic-mapping.v1, source-profile.v1, drift-report.v1,
onboarding-result.v1, mapping-approval.v1, mapping-audit-event.v1

## Phase 5 Tests (7 new files, 24 test cases)
test_mapping_registry(4), test_mapping_compiler(6), test_ai_safety(4),
test_onboarding_drift(4), test_onboarding_profiler(3),
test_onboarding_replay(2), test_cross_vendor_onboarding(1)

## New Runtime Dependencies
None. All Phase 5 uses stdlib + existing project dependencies only.
