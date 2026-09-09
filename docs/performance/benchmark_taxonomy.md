# ULPF Benchmark Taxonomy & Performance Evidence Standards (Phase 15)

**Target:** NTRO / Smart India Hackathon 2026  
**Document Classification:** Definitive Engineering Standard  

---

## 1. Governing Principle of Performance Honesty

ULPF strictly enforces engineering honesty across all performance claims. Local micro-benchmarks must **never** be conflated with distributed cluster throughput. Controlled burst tests must **never** be labeled as multi-day soak endurance.

Every performance figure reported by ULPF must declare:
1. **Benchmark Category** (Micro, Component, End-to-End, Burst, Endurance, Distributed)
2. **Hardware Environment** (CPU architecture, core count, RAM, OS, Python runtime)
3. **Dataset & Workload Mix** (Protocols, payload sizes, syntactic distribution)
4. **Statistical Method** (Warmup cycles, repetitions, min, mean, median, p95, p99, standard deviation)
5. **Operational Limitations & Constraints**

---

## 2. Benchmark Categories

| Category | Scope | Metric Focus | Method & Target |
|----------|-------|--------------|-----------------|
| **MICRO** | Single function execution in memory (e.g. SHA-256 calculation, regex match, envelope creation). | Latency (µs, ms) | Evaluates algorithmic efficiency without I/O. |
| **COMPONENT** | Single architectural module (e.g. ParserRuntime, NormalizationEngine, MultiStageCorrelator). | Throughput (eps), P95 Latency | Evaluates subsystem capacity under isolated load. |
| **INTEGRATION** | Multi-stage pipeline (Ingress → Parser → UCE → DLQ). | Lossless preservation, latency distribution | Evaluates cross-module queuing and backpressure. |
| **END_TO_END** | Ingestion through to Detection and Storage persistence. | Ingest-to-Alert latency, resource saturation | Evaluates system-level SLO achievement. |
| **BURST** | Short-duration high-throughput surge (10× baseline). | Queue depth, backpressure transition, DLQ capture | Evaluates overload survival without dropping evidence. |
| **ENDURANCE** | Sustained continuous load over fixed intervals. | Memory leak slope, file descriptor stability | Evaluates resource boundedness over time. |

---

## 3. Workload Distribution Mix

To simulate enterprise heterogenous telemetry realistically, ULPF benchmarks employ a weighted realistic mix:
- **Syslog RFC 3164 / 5424:** 30% (Perimeter firewalls, host daemons, network switches)
- **JSON / Structured Audit:** 25% (Kubernetes, AWS CloudTrail, application events)
- **CEF / LEEF:** 20% (Palo Alto, FortiGate, Check Point, QRadar feeds)
- **Linux Auditd / OS Telemetry:** 15% (Host execution, syscalls, auth logs)
- **Malformed / Edge Payloads:** 7% (Truncated records, corrupted delimiters, null bytes)
- **Hostile / Injection Payloads:** 3% (XXE bombs, prompt injection attempts, oversized frames)

---

## 4. Reporting Standards

Any published benchmark report must satisfy:
```json
{
  "category": "COMPONENT",
  "workload": "Realistic Enterprise Mix (6 formats)",
  "environment": {
    "cpu": "x86_64",
    "ram_gb": 16,
    "python": "3.12.x",
    "os": "Windows / Linux"
  },
  "metrics": {
    "repetitions": 1000,
    "min_ms": 0.005,
    "mean_ms": 0.012,
    "median_ms": 0.009,
    "p95_ms": 0.024,
    "p99_ms": 0.045,
    "throughput_eps": 85000
  },
  "limitations": "In-memory simulation; network interface and disk write latencies excluded."
}
```
*ULPF Engineering Standards — Honest Performance Evaluation.*
