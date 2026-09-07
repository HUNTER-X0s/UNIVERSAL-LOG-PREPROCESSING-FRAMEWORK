"""Phase 7 Performance, Scalability & Resilience Benchmark Suite for ULPF.

Benchmarks:
A. Cryptographic Authentication & Policy Authorization (JWT & RBAC checks)
B. Durable Relational Persistence (UCE, Semantic, Outbox transactions)
C. Distributed Stream & Consumer Coordination (Multi-partition publish/commit)
D. Multi-Worker Concurrent Pipeline Execution
E. Object Storage (SHA-256 integrity, put/get throughput)
F. Backup Creation & Verification Throughput
G. End-to-End Hardened Pipeline (Auth -> Ingest -> Durable UCE -> Semantic -> Search -> Outbox)

Outputs reproducible report to reports/phase7_benchmarks.json.
"""

from __future__ import annotations

import json
import os
import platform
import queue
import sys
import tempfile
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

for pkg in (
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
):
    pkg_path = str(Path(pkg).resolve())
    if pkg_path not in sys.path:
        sys.path.insert(0, pkg_path)

from ulpf_observability.metrics import OperationalMetricsRegistry
from ulpf_runtime.backup import BackupManager
from ulpf_runtime.multi_worker import MultiWorkerCoordinator
from ulpf_runtime.pipeline import RuntimePipeline
from ulpf_search.memory import MemorySearchIndex
from ulpf_security.auth import JWTAuthenticationProvider
from ulpf_security.policy import Permission, PolicyEngine
from ulpf_storage.database.relational import SQLiteDatabase
from ulpf_storage.durable_outbox import DurableOutboxRepository
from ulpf_storage.durable_semantic import DurableSemanticEventRepository
from ulpf_storage.durable_uce import DurableUCERepository
from ulpf_storage.interfaces import UCERecord
from ulpf_storage.memory import MemoryRawEvidenceRepository
from ulpf_storage.object_store import FilesystemObjectStore
from ulpf_streaming.distributed import DistributedEventStream

SAMPLE_LOG = (
    "Feb 23 10:15:30 firewall01 %ASA-4-106023: Deny tcp src outside:198.51.100.25/443 "
    "dst inside:10.0.0.15/51234 by access-group 'outside_in' [0x12345678, 0x0]"
)


def run_phase7_benchmarks(num_events: int = 500) -> dict[str, Any]:
    print(f"[*] Starting Phase 7 Production Hardening Benchmarks ({num_events} ops per stage)...")

    # 1. Security & Authentication Benchmark
    jwt_provider = JWTAuthenticationProvider("benchmark-secret-key-32chars-minimum-prod")
    token = jwt_provider.issue_token(
        subject="bench-operator",
        roles=["operator"],
        tenant_id="tenant-01",
    )
    policy_engine = PolicyEngine()
    identity = jwt_provider.authenticate(token)

    t0 = time.perf_counter()
    for _ in range(num_events):
        jwt_provider.authenticate(token)
        policy_engine.is_authorized(identity, Permission.EVENT_SEARCH, resource_tenant="tenant-01")
    auth_dur = time.perf_counter() - t0
    auth_eps = num_events / auth_dur
    print(f"  [Security Auth/RBAC]  OPS: {auth_eps:,.0f} | Total: {auth_dur*1000:.1f}ms")

    # 2. Durable Relational Storage Benchmark (SQLite WAL)
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = Path(tmp_dir) / "bench.db"
        db = SQLiteDatabase(db_path)
        uce_repo = DurableUCERepository(db)
        sem_repo = DurableSemanticEventRepository(db)
        outbox_repo = DurableOutboxRepository(db)

        t0 = time.perf_counter()
        for i in range(num_events):
            rec = UCERecord(
                uce_event_id=f"uce-bench-{i}",
                raw_event_id=f"raw-bench-{i}",
                raw_sha256="a" * 64,
                payload={"action": "DENY", "src_ip": "10.0.0.1", "dst_ip": "198.51.100.1"},
                schema_version="1.0.0",
                source_id="bench-firewall",
                captured_at=datetime.now(UTC).isoformat(),
            )
            uce_repo.put(rec)
        durable_uce_dur = time.perf_counter() - t0
        durable_uce_eps = num_events / durable_uce_dur
        print(f"  [Durable UCE Insert]  EPS: {durable_uce_eps:,.0f} | Total: {durable_uce_dur*1000:.1f}ms")

        # 3. Object Storage Benchmark
        obj_root = Path(tmp_dir) / "obj_store"
        obj_store = FilesystemObjectStore(obj_root)
        data_payload = SAMPLE_LOG.encode("utf-8")

        t0 = time.perf_counter()
        for i in range(num_events):
            obj_store.put(f"raw/events/{i}.bin", data_payload)
        obj_put_dur = time.perf_counter() - t0
        obj_put_eps = num_events / obj_put_dur

        t0 = time.perf_counter()
        for i in range(num_events):
            obj_store.get(f"raw/events/{i}.bin")
        obj_get_dur = time.perf_counter() - t0
        obj_get_eps = num_events / obj_get_dur
        print(f"  [Object Storage]      Put EPS: {obj_put_eps:,.0f} | Get EPS: {obj_get_eps:,.0f}")

        # 4. Distributed Stream Coordination
        dist_stream = DistributedEventStream(topic="bench-topic", num_partitions=4)
        partitions = dist_stream.join_consumer_group("bench-group", "bench-consumer")
        t0 = time.perf_counter()
        for i in range(num_events):
            dist_stream.publish(
                key=f"stream-event-{i}",
                payload=SAMPLE_LOG.encode("utf-8"),
                source_id=f"source-{i%4}",
            )
        stream_pub_dur = time.perf_counter() - t0
        stream_pub_eps = num_events / stream_pub_dur

        t0 = time.perf_counter()
        consumed = 0
        while consumed < num_events:
            for pid in partitions:
                batch = dist_stream.poll(
                    group_id="bench-group",
                    consumer_id="bench-consumer",
                    partition_id=pid,
                    max_records=50,
                )
                for msg in batch:
                    dist_stream.commit_offset(
                        "bench-group", "bench-consumer", pid, msg.offset + 1
                    )
                    consumed += 1
        stream_poll_dur = time.perf_counter() - t0
        stream_poll_eps = num_events / stream_poll_dur
        print(f"  [Distributed Stream]  Pub EPS: {stream_pub_eps:,.0f} | Poll/Commit EPS: {stream_poll_eps:,.0f}")

        # 5. Multi-Worker Concurrent Coordination
        work_q: queue.Queue[str] = queue.Queue()
        for i in range(num_events):
            work_q.put(f"work-evt-{i}")

        processed_count = 0
        p_lock = threading.Lock()

        def worker_handler(pid: int) -> None:
            nonlocal processed_count
            while True:
                try:
                    work_q.get_nowait()
                    with p_lock:
                        processed_count += 1
                except queue.Empty:
                    break

        worker_coord = MultiWorkerCoordinator(
            num_workers=4,
            process_fn=worker_handler,
            poll_interval_sec=0.005,
        )
        t0 = time.perf_counter()
        worker_coord.start()
        # Wait until drained
        deadline = time.monotonic() + 5.0
        while not work_q.empty() and time.monotonic() < deadline:
            time.sleep(0.01)
        worker_coord.drain(timeout_sec=2.0)
        worker_dur = time.perf_counter() - t0
        worker_eps = processed_count / max(worker_dur, 0.001)
        print(f"  [Multi-Worker Pool]   EPS: {worker_eps:,.0f} | Total: {worker_dur*1000:.1f}ms")

        # 6. Backup & Verification Benchmark
        backup_root = Path(tmp_dir) / "backups"
        backup_mgr = BackupManager(
            backup_root, encryption_password="bench-backup-password-32chars"  # noqa: S106
        )
        components = {
            "database": b"DURABLE_SQLITE_DATABASE_DUMP_BYTES" * 100,
            "profiles": b'{"source": "cisco-asa", "format": "syslog"}',
        }
        t0 = time.perf_counter()
        backup_manifest = backup_mgr.create_backup(components, schema_version=7, backup_id="bench-bk-01")
        backup_dur = time.perf_counter() - t0

        t0 = time.perf_counter()
        restored_manifest, restored_comps = backup_mgr.restore_backup("bench-bk-01")
        restore_dur = time.perf_counter() - t0
        print(f"  [Backup & Restore]    Create: {backup_dur*1000:.2f}ms | Restore & Verify: {restore_dur*1000:.2f}ms")

        # 7. End-to-End Pipeline with Durable Storage
        raw_mem = MemoryRawEvidenceRepository()
        search_idx = MemorySearchIndex(max_indexed_events=num_events * 2)
        metrics = OperationalMetricsRegistry()

        pipeline = RuntimePipeline(
            raw_store=raw_mem,
            uce_store=uce_repo,
            semantic_store=sem_repo,
            search_adapter=search_idx,
            outbox_repo=outbox_repo,
            metrics=metrics,
        )

        latencies_ms = []
        t0 = time.perf_counter()
        for i in range(num_events):
            log_var = f"{SAMPLE_LOG} [id={i}]"
            t_s = time.perf_counter()
            pipeline.process_event(log_var, source_id="cisco-asa", correlation_id=f"corr-{i}")
            latencies_ms.append((time.perf_counter() - t_s) * 1000.0)
        e2e_dur = time.perf_counter() - t0
        e2e_eps = num_events / e2e_dur

        sorted_lats = sorted(latencies_ms)
        p50 = sorted_lats[int(num_events * 0.50)]
        p95 = sorted_lats[min(int(num_events * 0.95), num_events - 1)]
        p99 = sorted_lats[min(int(num_events * 0.99), num_events - 1)]
        print(f"  [E2E Durable Pipeline] EPS: {e2e_eps:,.0f} | p50: {p50:.3f}ms | p95: {p95:.3f}ms | p99: {p99:.3f}ms")
        db.close()

    report: dict[str, Any] = {
        "timestamp": datetime.now(UTC).isoformat(),
        "phase": 7,
        "environment": {
            "python_version": sys.version,
            "platform": platform.platform(),
            "cpu_count": os.cpu_count(),
        },
        "sample_event_bytes": len(SAMPLE_LOG),
        "events_per_test": num_events,
        "stages": {
            "cryptographic_auth": {
                "operations": num_events,
                "duration_sec": auth_dur,
                "ops_per_sec": auth_eps,
            },
            "durable_uce_persistence": {
                "events": num_events,
                "duration_sec": durable_uce_dur,
                "eps": durable_uce_eps,
            },
            "object_storage_put": {
                "operations": num_events,
                "duration_sec": obj_put_dur,
                "ops_per_sec": obj_put_eps,
            },
            "object_storage_get": {
                "operations": num_events,
                "duration_sec": obj_get_dur,
                "ops_per_sec": obj_get_eps,
            },
            "distributed_stream_publish": {
                "events": num_events,
                "duration_sec": stream_pub_dur,
                "eps": stream_pub_eps,
            },
            "distributed_stream_poll_commit": {
                "events": num_events,
                "duration_sec": stream_poll_dur,
                "eps": stream_poll_eps,
            },
            "multi_worker_coordinator": {
                "events": num_events,
                "duration_sec": worker_dur,
                "eps": worker_eps,
            },
            "backup_creation": {
                "duration_sec": backup_dur,
                "backup_id": backup_manifest.backup_id,
            },
            "backup_restoration_verify": {
                "duration_sec": restore_dur,
                "verified": restored_manifest.backup_id == "bench-bk-01",
            },
            "end_to_end_durable_pipeline": {
                "events": num_events,
                "duration_sec": e2e_dur,
                "eps": e2e_eps,
                "latency_p50_ms": p50,
                "latency_p95_ms": p95,
                "latency_p99_ms": p99,
            },
        },
        "gate_status": "PASS" if e2e_eps >= 50 else "FAIL",
    }

    out_file = Path("reports/phase7_benchmarks.json")
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[*] Phase 7 Benchmark report saved to {out_file}")
    return report


if __name__ == "__main__":
    count = 500
    if len(sys.argv) > 1:
        count = int(sys.argv[1])
    run_phase7_benchmarks(count)
