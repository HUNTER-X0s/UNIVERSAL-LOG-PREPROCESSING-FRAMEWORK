# ULPF Ground Truth & Expected Output Audit

**Document ID:** ULPF-DOC-GROUND-TRUTH-FINAL  
**Corpus Version:** v3.1.0  

---

### 1. Existing Academic Ground Truth (LogHub)

The repository preserves the complete LogHub ground truth suite across 16 benchmark systems:
- **`*_2k.log`**: 2,000 raw lines sampled uniformly from production logs.
- **`*_2k.log_structured.csv`**: Ground truth extracted fields (LineId, Time, Level, Component, Content, EventId, EventTemplate).
- **`*_2k.log_templates.csv`**: Ground truth regex templates corresponding to each extracted EventId.

### 2. ULPF Specification-Derived Expected Outputs

For all specification-derived test fixtures, expected parsed field dictionaries are maintained to benchmark Phase 3 parser accuracy:
- E.g. `panos_traffic.log` maps directly to expected extracted 5-tuple, action (`drop`/`allow`), rule name, and byte counters.
- E.g. `azure_nsg_flow.json` maps directly to flow tuple extractions (MAC address, IP, port, TCP state, packet count).
- E.g. `containerd_cri.log` maps directly to CRI timestamp, stream (`stdout`/`stderr`), tag (`F`/`P`), and message assembly.
