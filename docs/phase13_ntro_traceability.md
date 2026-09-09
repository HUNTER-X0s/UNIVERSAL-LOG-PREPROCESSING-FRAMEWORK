# ULPF Phase 13 NTRO Requirements Traceability Matrix

**Organization:** National Technical Research Organisation (NTRO) / SIH  
**Evaluation Standard:** Air-Gapped Perimeter Log Intelligence  
**Document Status:** Frozen Authoritative Matrix  

---

| Requirement ID | Description | Architecture Component | Implementation File | Verification Test | Status |
|---|---|---|---|---|---|
| **NTRO-REQ-01** | Lossless raw payload retention & tamper detection | `ulpf_runtime`, `ulpf_storage` | `models.py`, `wal.py` | `test_evidence_integrity.py` | **VERIFIED** |
| **NTRO-REQ-02** | Multi-vendor parsing across heterogeneous streams | `ulpf_parser_runtime` | `parsers/` (20 concrete engines) | `test_parser_coverage.py` | **VERIFIED** |
| **NTRO-REQ-03** | Universal Common Event (UCE) normalization | `ulpf_normalization` | `normalizer.py`, `models.py` | `test_normalization.py` | **VERIFIED** |
| **NTRO-REQ-04** | Air-gapped / zero outbound socket operation | Core Framework | All modules | `test_airgap_assurance.py` | **VERIFIED** |
| **NTRO-REQ-05** | Universal Source Intelligence & automatic fingerprinting | `ulpf_onboarding` | `source_intel.py` | `test_phase13_universal_intelligence.py` | **VERIFIED** |
| **NTRO-REQ-06** | Unknown log format onboarding & guided mapping | `ulpf_onboarding` | `service.py`, `mapping_intel.py` | `test_phase13_universal_intelligence.py` | **VERIFIED** |
| **NTRO-REQ-07** | Schema drift detection & impact classification | `ulpf_onboarding` | `drift.py` | `test_phase13_universal_intelligence.py` | **VERIFIED** |
| **NTRO-REQ-08** | Dual view representation (Raw + UCE + OCSF + OTel) | `ulpf_intelligence` | `dual_view.py` | `test_phase13_forensic_superiority.py` | **VERIFIED** |
| **NTRO-REQ-09** | Chronological multi-stage attack story generation | `ulpf_intelligence` | `attack_story.py` | `test_phase13_forensic_superiority.py` | **VERIFIED** |
| **NTRO-REQ-10** | Local air-gapped threat intelligence enrichment | `ulpf_intelligence` | `enrichment/local.py` | `test_phase13_analyst_superiority.py` | **VERIFIED** |
| **NTRO-REQ-11** | One-click analyst investigation dossier | `ulpf_intelligence` | `investigate.py` | `test_phase13_forensic_superiority.py` | **VERIFIED** |
| **NTRO-REQ-12** | Grounded local AI copilot with evidence citations | `ulpf_mission` | `copilot/advisor.py` | `test_phase13_analyst_superiority.py` | **VERIFIED** |
| **NTRO-REQ-13** | Safe AI action model with mandatory human authorization | `ulpf_mission` | `copilot/advisor.py` | `test_phase13_analyst_superiority.py` | **VERIFIED** |
| **NTRO-REQ-14** | Cryptographically sealed case packaging & export | `ulpf_intelligence` | `case_package.py` | `test_phase13_forensic_superiority.py` | **VERIFIED** |
| **NTRO-REQ-15** | Data quality scoring & source health monitoring | `ulpf_mission` | `health/source_health.py` | `test_phase13_operational_excellence.py` | **VERIFIED** |
| **NTRO-REQ-16** | Offline SIH showcase demonstration (<120s runtime) | `scripts/` | `run_phase13_sih_showcase.py` | `run_phase13_sih_showcase.py` | **VERIFIED** |
