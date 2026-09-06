# ULPF Universal Telemetry Corpus (v3.1.0)

This directory contains the frozen, forensically audited dataset corpus for the **Universal Log Pre-processing Framework (ULPF)**.

## Quantitative Overview
- **Total Files:** 344 files
- **Telemetry Payload Files:** 286 files (6,409,385,655 bytes)
- **Metadata & Manifest Files:** 58 files (95,763 bytes)
- **Total Volume:** 6,409,481,418 bytes (~6,112.56 MB)
- **Registered Datasets:** 39 families in `DATASET_MANIFEST.json`
- **Core Focus:** NTRO Perimeter Network & Security Telemetry

## Storage Tiers
- **Tier 1 (Git Fixtures & Reference):** Lightweight authentic test fixtures and reference templates (`<10MB`).
- **Tier 2 (Local Benchmarks):** Benchmark datasets for parser stress testing (`data/benchmarks/secrepo/`, ignored by Git).
- **Tier 3 (External Mounts):** Large-scale external network captures (>500MB).

## Directory Structure
- `data/fixtures/real_world/`: High-fidelity real and specification-derived telemetry fixtures.
- `data/fixtures/adversarial/`: Malformed, nested, and boundary stress records.
- `data/reference/loghub/`: LogHub 2,000-line benchmarks with ground truth templates and CSVs.
- `data/reference/alarm_knowledge/`: Enterprise router and switch alarm reference catalogs.
- `data/benchmarks/`: High-volume multi-gigabyte stress testing datasets.
