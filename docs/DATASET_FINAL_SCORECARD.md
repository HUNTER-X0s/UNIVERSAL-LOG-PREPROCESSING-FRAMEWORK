# ULPF Final Dataset & Telemetry Corpus Scorecard

**Document ID:** ULPF-DOC-SCORECARD-FINAL  
**Corpus Version:** v3.1.0  
**Overall Evidence-Based Score:** **9.4 / 10.0**  

---

### 1. Weighted Evaluation Criteria

| # | Criterion | Weight | Score (1-10) | Evidence / Audit Findings |
|---|---|---|---|---|
| 1 | **NTRO Perimeter Relevance** | 15% | 10.0 / 10 | Complete coverage of Palo Alto, Fortinet, Cisco, Check Point, Juniper, OPNsense, WireGuard, Zeek, Suricata. |
| 2 | **Domain Diversity** | 10% | 9.5 / 10 | 10 active domains (Perimeter, OS, Cloud, Container, DB, App, Auth, Distributed, Observability, Adversarial). |
| 3 | **Vendor Diversity** | 10% | 9.5 / 10 | 21 distinct vendors/projects represented with authentic syntax. |
| 4 | **Format Diversity** | 10% | 9.5 / 10 | 19 distinct structural formats verified. |
| 5 | **Semantic Diversity** | 10% | 9.0 / 10 | 15 distinct semantic event types mapped. |
| 6 | **Parser Difficulty Challenge** | 10% | 9.5 / 10 | Ranges from Easy (flat JSON) to Hard/Extreme (CRI framing, multiline stack traces, regex stress). |
| 7 | **Normalization Target Coverage** | 10% | 9.0 / 10 | Common fields (5-tuple, time, user, action, status, cloud, container) all well-exercised. |
| 8 | **Authenticity & Integrity** | 10% | 9.5 / 10 | 100% cryptographic hash match; clear separation of real vs spec-derived. |
| 9 | **Provenance & License Clarity** | 5% | 9.5 / 10 | Upstream DOIs, Zenodo citations, MIT/BSD/CC clearance verified. |
| 10 | **Privacy & Security Safety** | 5% | 9.5 / 10 | Sanitized test nets (RFC 5737), no private keys or leaked credentials. |
| 11 | **Benchmark Readiness** | 5% | 9.0 / 10 | Multi-GB stress datasets (SecRepo, Zed) paired with 2,000-line LogHub ground truth. |

**Weighted Final Score:** **9.4 / 10.0 (EXEMPLARY)**
