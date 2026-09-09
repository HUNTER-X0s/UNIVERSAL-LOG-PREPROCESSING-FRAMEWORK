# ULPF Phase 16 — Performance Benchmarking & Throughput Proof

**Target:** NTRO / Smart India Hackathon 2026  
**Benchmark:** End-to-end RAW → PARSE → UCE pipeline on single-core (no parallelism)  
**Timestamp:** 2026-09-09T22:44:29Z  

---

## 1. Throughput Benchmark Results

| Batch Size (events) | Total Time (s) | Events/sec | ms/event |
|---|---|---|---|
| **100** | `0.008s` | **12,830 EPS** | `0.078 ms` |
| **500** | `0.040s` | **12,555 EPS** | `0.080 ms` |
| **1,000** | `0.075s` | **13,245 EPS** | `0.075 ms` |
| **5,000** | `0.407s` | **12,294 EPS** | `0.081 ms` |
| **10,000** | `0.848s` | **11,799 EPS** | `0.085 ms` |

---

## 2. Peak Performance

| Metric | Value |
|---|---|
| **Peak Throughput** | **13,245 events/second** |
| **Achieved at Batch Size** | 1,000 events |
| **Latency at Peak** | 0.075 ms/event |
| **Measured on** | Single CPU core, no GPU, no SIMD |
| **Pipeline Stages** | 3 (Frame → Parse → UCE Normalize) |

---

## 3. Scalability Projection

| Configuration | Projected Throughput |
|---|---|
| Single core (measured) | 13,245 EPS |
| 4-core workstation | ~46,358 EPS (3.5× linear) |
| 16-core server | ~158,940 EPS (12× linear) |
| Distributed (4 nodes × 16 cores) | ~635,760 EPS |

---

## 4. Performance Verdict

ULPF meets and exceeds NTRO's operational throughput requirements:
- **Target:** > 10,000 EPS for operational log ingestion
- **Achieved:** **13,245 EPS** single-core
- **Status:** `✅ PASS — TARGET EXCEEDED`
