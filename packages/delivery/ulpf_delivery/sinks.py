"""Downstream delivery sink implementations for ULPF Phase 6.

Enforces:
- Rule 15/16: Offline, air-gapped test and deployment support
- Rule 57/58: Isolated downstream destinations; downstream failure does not corrupt canonical store
- Rule 63/64: SIEM, OCSF, OTel, and Data Lake export capabilities
"""

import json
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ulpf_delivery.interfaces import DeliveryBatch, DeliveryResult, DeliverySink


class OCSFJsonSink(DeliverySink):
    """Sinks OCSF v1.1.0 projected events into an in-memory buffer or export stream."""

    def __init__(self) -> None:
        self._buffer: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._is_healthy = True

    @property
    def name(self) -> str:
        return "ocsf"

    def set_healthy(self, healthy: bool) -> None:
        self._is_healthy = healthy

    def health_check(self) -> bool:
        return self._is_healthy

    def deliver(self, batch: DeliveryBatch) -> DeliveryResult:
        start = time.perf_counter()
        if not self._is_healthy:
            return DeliveryResult(
                sink_name=self.name,
                batch_id=batch.batch_id,
                delivered_count=0,
                failed_count=len(batch.records),
                success=False,
                error_message="OCSF destination unavailable (unhealthy)",
                duration_ms=(time.perf_counter() - start) * 1000.0,
            )

        with self._lock:
            self._buffer.extend(batch.records)

        return DeliveryResult(
            sink_name=self.name,
            batch_id=batch.batch_id,
            delivered_count=len(batch.records),
            failed_count=0,
            success=True,
            duration_ms=(time.perf_counter() - start) * 1000.0,
        )

    def get_delivered(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._buffer)


class OTelBatchSink(DeliverySink):
    """Sinks OpenTelemetry LogRecord projected events."""

    def __init__(self) -> None:
        self._buffer: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._is_healthy = True

    @property
    def name(self) -> str:
        return "otel"

    def set_healthy(self, healthy: bool) -> None:
        self._is_healthy = healthy

    def health_check(self) -> bool:
        return self._is_healthy

    def deliver(self, batch: DeliveryBatch) -> DeliveryResult:
        start = time.perf_counter()
        if not self._is_healthy:
            return DeliveryResult(
                sink_name=self.name,
                batch_id=batch.batch_id,
                delivered_count=0,
                failed_count=len(batch.records),
                success=False,
                error_message="OTel collector unavailable",
                duration_ms=(time.perf_counter() - start) * 1000.0,
            )

        with self._lock:
            self._buffer.extend(batch.records)

        return DeliveryResult(
            sink_name=self.name,
            batch_id=batch.batch_id,
            delivered_count=len(batch.records),
            failed_count=0,
            success=True,
            duration_ms=(time.perf_counter() - start) * 1000.0,
        )

    def get_delivered(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._buffer)


class SiemMockSink(DeliverySink):
    """SIEM integration sink with controllable failure injection."""

    def __init__(self) -> None:
        self._buffer: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._is_healthy = True
        self._fail_next_n = 0

    @property
    def name(self) -> str:
        return "siem"

    def set_healthy(self, healthy: bool) -> None:
        self._is_healthy = healthy

    def inject_failure(self, count: int = 1) -> None:
        self._fail_next_n = count

    def health_check(self) -> bool:
        return self._is_healthy

    def deliver(self, batch: DeliveryBatch) -> DeliveryResult:
        start = time.perf_counter()
        if not self._is_healthy:
            return DeliveryResult(
                sink_name=self.name,
                batch_id=batch.batch_id,
                delivered_count=0,
                failed_count=len(batch.records),
                success=False,
                error_message="SIEM endpoint unreachable",
                duration_ms=(time.perf_counter() - start) * 1000.0,
            )

        if self._fail_next_n > 0:
            self._fail_next_n -= 1
            return DeliveryResult(
                sink_name=self.name,
                batch_id=batch.batch_id,
                delivered_count=0,
                failed_count=len(batch.records),
                success=False,
                error_message="SIEM ingestion endpoint returned 503 Service Unavailable",
                duration_ms=(time.perf_counter() - start) * 1000.0,
            )

        with self._lock:
            self._buffer.extend(batch.records)

        return DeliveryResult(
            sink_name=self.name,
            batch_id=batch.batch_id,
            delivered_count=len(batch.records),
            failed_count=0,
            success=True,
            duration_ms=(time.perf_counter() - start) * 1000.0,
        )

    def get_delivered(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._buffer)


class FileExportSink(DeliverySink):
    """Exports events to JSONL / NDJSON partitioned files for Data Lake / Analytics."""

    def __init__(self, output_dir: Path | str) -> None:
        self.output_dir = Path(output_dir).resolve()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    @property
    def name(self) -> str:
        return "datalake"

    def health_check(self) -> bool:
        return self.output_dir.exists()

    def deliver(self, batch: DeliveryBatch) -> DeliveryResult:
        start = time.perf_counter()
        try:
            date_str = datetime.now(UTC).strftime("%Y-%m-%d")
            target_file = self.output_dir / f"export_{date_str}_{batch.sink_name}.jsonl"

            lines = [json.dumps(r) + "\n" for r in batch.records]
            with self._lock:
                with open(target_file, "a", encoding="utf-8") as f:
                    f.writelines(lines)

            return DeliveryResult(
                sink_name=self.name,
                batch_id=batch.batch_id,
                delivered_count=len(batch.records),
                failed_count=0,
                success=True,
                duration_ms=(time.perf_counter() - start) * 1000.0,
            )
        except Exception as e:
            return DeliveryResult(
                sink_name=self.name,
                batch_id=batch.batch_id,
                delivered_count=0,
                failed_count=len(batch.records),
                success=False,
                error_message=str(e),
                duration_ms=(time.perf_counter() - start) * 1000.0,
            )
