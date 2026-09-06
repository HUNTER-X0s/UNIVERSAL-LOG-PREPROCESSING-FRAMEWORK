# ULPF Dataset Benchmark and Performance Stress Plan

**Document ID:** ULPF-DOC-DATA-BENCH-001  
**Governing ADR:** ADR-004 (Bounded Allocation & Loss Awareness)  

---

## 1. Benchmark Execution Strategy

| Benchmark Tier | Target Data | Volume | Target Metric | Success Criteria |
| :--- | :--- | :---: | :--- | :--- |
| **Throughput (100k eps)**| SecRepo `conn.log` | 2.59 GB | Events Per Second (EPS) | Sustained > 100,000 eps intake |
| **Memory Bounds** | SecRepo `http.log` | 1.32 GB | Resident Set Size (RSS) | Memory stable under 512 MB |
| **Multi-Format Parity** | Zed 4-way streams | 1.90 GB | Semantic Equivalence | Identical canonical output across TSV/JSON/SUP/BSUP |
| **Scale Capture** | Mac full capture | 16.76 MB | Long-running stream | Zero memory leaks across 100,000+ records |
