# ULPF Universal Telemetry Corpus (v3.2.0)

This directory contains the frozen, forensically audited dataset corpus for the **Universal Log Pre-processing Framework (ULPF)**.

## Quantitative Overview
- **Registered Datasets:** 47 families in `DATASET_MANIFEST.json`
- **Total Volume:** ~6.4 GB authentic and specification-derived security telemetry
- **Ground Truth Fixtures:** 20 verified vendor raw-to-UCE pairs in `data/reference/expected_outputs/`
- **Core Security Focus:** Enterprise Perimeter (PAN-OS, FortiOS, Cisco ASA, OPNsense), NIDS (Suricata, Snort, Zeek, CICIDS 2017, UNSW-NB15), Cloud & DevSecOps (AWS, GCP, Azure, GitHub), and Identity & EDR (Okta, CrowdStrike, SentinelOne, Falco).

## Storage Tiers
- **Tier 1 (Git Fixtures & Reference):** Lightweight authentic test fixtures and reference templates (`<10MB`).
- **Tier 2 (Local Benchmarks):** Benchmark datasets for parser stress testing (`data/benchmarks/secrepo/`, ignored by Git).
- **Tier 3 (External Mounts):** Large-scale external network captures (>500MB).

## Ground Truth & Trust Verification
For SIEM teams, CISOs, and enterprise compliance auditors, every supported vendor parser includes a dedicated expected output fixture pair:
- `raw_input.*`: Authentic raw telemetry payload
- `expected_uce.json`: Exact Universal Canonical Event v1 specification output
- `VERIFICATION.md`: Attestation and automated regression command

Run full automated verification suite across all 20 vendor parsers:
```bash
python -m unittest tests/test_expected_output_fixtures.py
```
