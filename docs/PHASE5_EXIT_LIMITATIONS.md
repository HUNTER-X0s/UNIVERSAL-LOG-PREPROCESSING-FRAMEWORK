# ULPF Phase 5 Limitations

**Date:** 2026-09-06

## L-01: AIOutputValidator - Numeric Range and Enum Validation

Validates required keys and dangerous tokens but NOT confidence range or taxonomy enums.
Mitigation: registry.validate() enforces these via JSON Schema contract.
Phase 6 action: Extend AIOutputValidator with range and enum checks.

## L-02: Registry Thread-Safety

MappingRegistry uses plain Python dicts. Not thread-safe for concurrent writes.
Mitigation: Onboarding is a governance workflow (human-in-the-loop), not concurrent hot path.
Phase 6 action: Add threading.Lock around activation updates.

## L-03: Semantic Drift Not Analyzed

SchemaDriftDetector detects structural drift but not semantic drift
(meaning changes without schema changes).

## L-04: Onboarding Performance Not Benchmarked

Phase 5 benchmarks cover the semantic hot path only.

## L-05: Cross-Format Onboarding Partially Tested

Format detection supports JSON/Syslog/KV/CEF/LEEF but tests use JSON only.

## L-06: Mapping Pack Import Not Fully Implemented

MappingPack serializes correctly. Bundle import and tamper-detection not implemented.

## L-07: Flaky Benchmark Test

test_parser_benchmarks.py::test_paloalto_panos_throughput is timing-sensitive.
Not caused by Phase 5.
