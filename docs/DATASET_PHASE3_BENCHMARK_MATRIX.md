# ULPF Phase 3 Parser Benchmark & Testing Matrix

**Document ID:** ULPF-DOC-BENCHMARK-MATRIX-FINAL  
**Corpus Version:** v3.1.0  

---

### 1. Benchmark Dimensions

| Dimension | Target Dataset | Success Metric |
|---|---|---|
| **Framing Detection Accuracy** | Containerd CRI, Java Log4j multiline, Syslog | 100% record boundary identification |
| **Format Auto-Detection** | All 19 formats | >99.5% correct format classification |
| **Field Extraction Fidelity** | LogHub 2k structured, Palo Alto, Fortinet, Azure | 100% matching against expected schemas |
| **Timestamp Parsing Diversity** | ISO 8601, Epoch, BSD, W3C, Impossible | Zero unhandled timestamp format crashes |
| **Throughput & Scale** | SecRepo (4.17 GB), Zed (1.94 GB) | >100,000 events/sec sustained ingestion |
| **Adversarial Resilience** | Adversarial suite (8 fixtures) | Zero unhandled exceptions or memory leaks |
