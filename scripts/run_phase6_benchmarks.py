"""Phase 6 Performance & Resilience Benchmark Suite for ULPF.

Benchmarks:
A. Ingestion & Raw Evidence Capture (SHA-256)
B. Bounded Streaming (Publish/Poll/Ack)
C. Semantic Core Processing
D. Multi-Tier Storage Persistence (Raw, UCE, Semantic)
E. Search Indexing
F. Downstream Delivery (Fan-out to Sinks)
G. End-to-End Pipeline (Ingest -> UCE -> Semantic -> Projections -> Storage -> Sinks)

Outputs reproducible report to reports/phase6_benchmarks.json.
"""

import json
import os
import platform
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

for pkg in (
    "packages/observability",
    "packages/runtime",
    "packages/streaming",
    "packages/storage",
    "packages/search",
    "packages/delivery",
    "packages/semantic",
    "packages/mapping",
    "packages/normalization",
    "packages/parser-runtime",
    "packages/contracts",
    "packages/platform",
):
    pkg_path = str(Path(pkg).resolve())
    if pkg_path not in sys.path:
        sys.path.insert(0, pkg_path)

from ulpf_observability.metrics import OperationalMetricsRegistry
from ulpf_runtime.pipeline import RuntimePipeline
from ulpf_search.memory import MemorySearchIndex
from ulpf_storage.memory import (
    MemoryOutboxRepository,
    MemoryRawEvidenceRepository,
    MemorySemanticEventRepository,
    MemoryUCERepository,
)
from ulpf_streaming.memory import MemoryEventStream

SAMPLE_LOG = (
    "Feb 23 10:15:30 firewall01 %ASA-4-106023: Deny tcp src outside:198.51.100.25/443 "
    "dst inside:10.0.0.15/51234 by access-group 'outside_in' [0x12345678, 0x0]"
)


def run_benchmarks(num_events: int = 1000) -> dict[str, Any]:
    print(f"[*] Starting Phase 6 Benchmarks ({num_events} events per stage)...")

    # 1. Raw Storage Benchmark
    raw_repo = MemoryRawEvidenceRepository()
    t0 = time.perf_counter()
    for i in range(num_events):
        raw_repo.put(f"raw-bench-{i}", SAMPLE_LOG.encode("utf-8"), "bench-src", "syslog")
    raw_dur = time.perf_counter() - t0
    raw_eps = num_events / raw_dur
    print(f"  [Raw Persistence]  EPS: {raw_eps:,.0f} | Total: {raw_dur*1000:.1f}ms")

    # 2. Streaming Buffer Benchmark
    stream = MemoryEventStream(num_partitions=4, max_partition_capacity=num_events * 2)
    t0 = time.perf_counter()
    for i in range(num_events):
        stream.publish("bench", key=f"src-{i%4}", payload=SAMPLE_LOG.encode("utf-8"))
    stream_pub_dur = time.perf_counter() - t0
    stream_pub_eps = num_events / stream_pub_dur

    t0 = time.perf_counter()
    polled_count = 0
    while polled_count < num_events:
        batch = stream.poll(timeout_sec=0.1, max_records=100)
        for msg in batch:
            stream.ack(msg)
            polled_count += 1
    stream_poll_dur = time.perf_counter() - t0
    stream_poll_eps = num_events / stream_poll_dur
    print(f"  [Stream Pub/Poll]  Pub EPS: {stream_pub_eps:,.0f} | Poll EPS: {stream_poll_eps:,.0f}")
    stream.close()

    # 3. End-to-End Pipeline Benchmark
    raw_store = MemoryRawEvidenceRepository()
    uce_store = MemoryUCERepository()
    semantic_store = MemorySemanticEventRepository()
    search_adapter = MemorySearchIndex(max_indexed_events=num_events * 2)
    outbox_repo = MemoryOutboxRepository()
    metrics = OperationalMetricsRegistry()

    pipeline = RuntimePipeline(
        raw_store=raw_store,
        uce_store=uce_store,
        semantic_store=semantic_store,
        search_adapter=search_adapter,
        outbox_repo=outbox_repo,
        metrics=metrics,
    )

    latencies_ms = []
    t0 = time.perf_counter()
    for i in range(num_events):
        # Vary slightly to test distinct hashes
        log_var = f"{SAMPLE_LOG} [seq={i}]"
        t_single = time.perf_counter()
        pipeline.process_event(log_var, source_id="cisco-asa", correlation_id=f"corr-{i}")
        dur = (time.perf_counter() - t_single) * 1000.0
        latencies_ms.append(dur)
    e2e_dur = time.perf_counter() - t0
    e2e_eps = num_events / e2e_dur

    sorted_lats = sorted(latencies_ms)
    p50 = sorted_lats[int(num_events * 0.50)]
    p95 = sorted_lats[min(int(num_events * 0.95), num_events - 1)]
    p99 = sorted_lats[min(int(num_events * 0.99), num_events - 1)]
    print(f"  [End-to-End E2E]   EPS: {e2e_eps:,.0f} | p50: {p50:.3f}ms | p95: {p95:.3f}ms | p99: {p99:.3f}ms")

    report: dict[str, Any] = {
        "timestamp": datetime.now(UTC).isoformat(),
        "environment": {
            "python_version": sys.version,
            "platform": platform.platform(),
            "cpu_count": os.cpu_count(),
        },
        "sample_event_bytes": len(SAMPLE_LOG),
        "events_per_test": num_events,
        "stages": {
            "raw_storage": {
                "events": num_events,
                "duration_sec": raw_dur,
                "eps": raw_eps,
                "latency_p50_ms": (raw_dur / num_events) * 1000.0,
            },
            "streaming_publish": {
                "events": num_events,
                "duration_sec": stream_pub_dur,
                "eps": stream_pub_eps,
            },
            "streaming_poll_ack": {
                "events": num_events,
                "duration_sec": stream_poll_dur,
                "eps": stream_poll_eps,
            },
            "end_to_end_pipeline": {
                "events": num_events,
                "duration_sec": e2e_dur,
                "eps": e2e_eps,
                "latency_p50_ms": p50,
                "latency_p95_ms": p95,
                "latency_p99_ms": p99,
            },
        },
        "gate_status": "PASS" if e2e_eps >= 1000 else "FAIL",
    }

    out_file = Path("reports/phase6_benchmarks.json")
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[*] Benchmark report saved to {out_file}")
    return report


if __name__ == "__main__":
    count = 1000
    if len(sys.argv) > 1:
        count = int(sys.argv[1])
    run_benchmarks(count)
