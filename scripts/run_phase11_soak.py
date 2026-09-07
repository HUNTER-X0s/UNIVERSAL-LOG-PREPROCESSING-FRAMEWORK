"""Phase 11 — Sustained Soak & Memory Leak Certification Suite for ULPF.

Runs sustained high-velocity cycles through the complete processing pipeline,
tracking heap allocation growth, latency drift across execution deciles,
queue stability, and error containment.

Anti-fabrication guaranteed: Empirical heap tracking via tracemalloc.
Emits: reports/phase11_soak_results.json
"""

from __future__ import annotations

import json
import math
import platform
import sys
import time
import tracemalloc
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Ensure package paths
for pkg in (
    "packages/mission",
    "packages/advanced_intelligence",
    "packages/intelligence",
    "packages/security",
    "packages/storage",
    "packages/streaming",
    "packages/runtime",
    "packages/observability",
    "packages/search",
    "packages/delivery",
    "packages/semantic",
    "packages/mapping",
    "packages/normalization",
    "packages/parser-runtime",
    "packages/contracts",
    "packages/domain",
    "packages/platform",
    "packages/ai",
    "packages/ingestion",
    "apps/api",
):
    pkg_path = str(Path(pkg).resolve())
    if pkg_path not in sys.path:
        sys.path.insert(0, pkg_path)

from ulpf_mission.orchestration.pipeline import MissionAnalysisPipeline


def _percentile(data: list[float], p: float) -> float:
    if not data:
        return 0.0
    k = (len(data) - 1) * p
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return data[int(k)]
    d0 = data[int(f)] * (c - k)
    d1 = data[int(c)] * (k - f)
    return d0 + d1


def run_soak_test(cycles: int = 2500, batch_size: int = 10) -> dict[str, Any]:
    tracemalloc.start()
    pipeline = MissionAnalysisPipeline()

    mem_samples: list[dict[str, Any]] = []
    latencies_ms: list[float] = []
    errors_encountered = 0
    sample_interval = max(50, cycles // 10)

    initial_current, initial_peak = tracemalloc.get_traced_memory()
    mem_samples.append({
        "cycle": 0,
        "current_mb": round(initial_current / (1024 * 1024), 3),
        "peak_mb": round(initial_peak / (1024 * 1024), 3),
    })

    t_start = time.perf_counter()

    for i in range(cycles):
        batch = [
            {
                "timestamp": datetime.now(UTC).isoformat(),
                "domain": "NETWORK",
                "source_ip": f"10.0.{(i % 254) + 1}.{(j % 250) + 1}",
                "dest_ip": "172.16.0.1",
                "service": "ssh" if (i + j) % 2 == 0 else "https",
                "bytes": 500 + (j * 15),
                "status": "failed" if (i + j) % 7 == 0 else "success",
            }
            for j in range(batch_size)
        ]

        t0 = time.perf_counter()
        try:
            _ = pipeline.run(events=batch)
        except Exception:
            errors_encountered += 1
        latencies_ms.append((time.perf_counter() - t0) * 1000.0)

        if (i + 1) % sample_interval == 0 or (i + 1) == cycles:
            curr, peak = tracemalloc.get_traced_memory()
            mem_samples.append({
                "cycle": i + 1,
                "current_mb": round(curr / (1024 * 1024), 3),
                "peak_mb": round(peak / (1024 * 1024), 3),
            })

    total_duration = time.perf_counter() - t_start
    final_current, final_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # Latency drift analysis: compare first 10% vs last 10%
    decile_size = max(10, len(latencies_ms) // 10)
    first_decile = latencies_ms[:decile_size]
    last_decile = latencies_ms[-decile_size:]

    avg_latency_first_decile = sum(first_decile) / len(first_decile)
    avg_latency_last_decile = sum(last_decile) / len(last_decile)
    latency_drift_factor = round(avg_latency_last_decile / max(0.0001, avg_latency_first_decile), 3)

    sorted_latencies = sorted(latencies_ms)
    total_events = cycles * batch_size
    overall_eps = total_events / max(0.0001, total_duration)

    heap_growth_mb = (final_current - initial_current) / (1024 * 1024)

    # Stability criteria:
    # 1. Zero unhandled errors
    # 2. Heap growth under 25 MB for 2500 cycles (proves no unbounded memory accumulation)
    # 3. Latency drift factor under 2.5x (proves no quadratic degradation)
    stable_memory = heap_growth_mb < 25.0
    stable_latency = latency_drift_factor < 2.5
    zero_errors = errors_encountered == 0

    soak_passed = stable_memory and stable_latency and zero_errors

    return {
        "cycles_executed": cycles,
        "batch_size": batch_size,
        "total_events": total_events,
        "total_duration_s": round(total_duration, 3),
        "throughput_eps": round(overall_eps, 2),
        "errors_encountered": errors_encountered,
        "latency_metrics": {
            "avg_ms": round(sum(latencies_ms) / len(latencies_ms), 4),
            "p50_ms": round(_percentile(sorted_latencies, 0.50), 4),
            "p95_ms": round(_percentile(sorted_latencies, 0.95), 4),
            "p99_ms": round(_percentile(sorted_latencies, 0.99), 4),
            "first_decile_avg_ms": round(avg_latency_first_decile, 4),
            "last_decile_avg_ms": round(avg_latency_last_decile, 4),
            "latency_drift_factor": latency_drift_factor,
        },
        "memory_metrics": {
            "initial_heap_mb": round(initial_current / (1024 * 1024), 3),
            "final_heap_mb": round(final_current / (1024 * 1024), 3),
            "peak_heap_mb": round(final_peak / (1024 * 1024), 3),
            "heap_growth_mb": round(heap_growth_mb, 3),
            "samples": mem_samples,
        },
        "certification_gates": {
            "zero_unhandled_errors": zero_errors,
            "bounded_heap_growth_under_25mb": stable_memory,
            "latency_drift_within_bounds": stable_latency,
        },
        "status": "CERTIFIED" if soak_passed else "FAILED",
    }


def main() -> int:
    print("=" * 75)
    print("ULPF PHASE 11: SUSTAINED SOAK & RESOURCE INTEGRITY CERTIFICATION")
    print("=" * 75)
    print(f"Platform: {platform.platform()} | Python {sys.version.split()[0]}")
    print("Executing 2,500 sustained processing cycles (25,000 events)...\n")

    results = run_soak_test(cycles=2500, batch_size=10)

    print(f"Cycles Completed:    {results['cycles_executed']}")
    print(f"Events Processed:    {results['total_events']}")
    print(f"Execution Duration:  {results['total_duration_s']}s")
    print(f"Average Throughput:  {results['throughput_eps']} eps")
    print(f"p95 Batch Latency:   {results['latency_metrics']['p95_ms']} ms")
    print(f"Latency Drift Ratio: {results['latency_metrics']['latency_drift_factor']}x")
    print(f"Peak Heap Memory:    {results['memory_metrics']['peak_heap_mb']} MB")
    print(f"Net Heap Growth:     {results['memory_metrics']['heap_growth_mb']} MB")
    print(f"Errors Encountered:  {results['errors_encountered']}")
    print(f"Soak Status:         [{results['status']}]")

    report = {
        "certification_suite": "Phase 11 — Sustained Soak & Resource Integrity Certification",
        "timestamp": datetime.now(UTC).isoformat(),
        "environment": {
            "platform": platform.platform(),
            "cpu_arch": platform.machine(),
            "python_version": sys.version.split()[0],
        },
        "results": results,
    }

    report_path = Path("reports/phase11_soak_results.json")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print("\n" + "=" * 75)
    print(f"Report written to: {report_path}")
    print("=" * 75)

    return 0 if results["status"] == "CERTIFIED" else 1


if __name__ == "__main__":
    sys.exit(main())
