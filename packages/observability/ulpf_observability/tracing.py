"""Lightweight in-process span tracing for ULPF Phase 6.

Enforces:
- Rule 43/44: Preserve and correlate trace_id, span_id, correlation_id without payload bloating
- Rule 47: Bounded trace retention
"""

import threading
import time
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass(frozen=True)
class TraceSpan:
    """Operational trace span representing execution of a pipeline stage."""

    trace_id: str
    span_id: str
    parent_span_id: str | None
    name: str
    start_time: str
    end_time: str
    duration_ms: float
    status: str  # OK, ERROR
    attributes: dict[str, Any] = field(default_factory=dict)


class InProcessTracer:
    """In-process tracer recording bounded pipeline stage spans."""

    def __init__(self, max_spans: int = 5000) -> None:
        self.max_spans = max_spans
        self._spans: list[TraceSpan] = []
        self._lock = threading.Lock()

    @contextmanager
    def span(
        self,
        name: str,
        trace_id: str | None = None,
        parent_span_id: str | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> Generator[str, None, None]:
        tid = trace_id or uuid.uuid4().hex
        sid = uuid.uuid4().hex[:16]
        start_ts = datetime.now(UTC).isoformat()
        t0 = time.perf_counter()
        status = "OK"
        span_attrs = dict(attributes or {})

        try:
            yield sid
        except Exception as e:
            status = "ERROR"
            span_attrs["error.type"] = type(e).__name__
            span_attrs["error.message"] = str(e)
            raise
        finally:
            dur_ms = (time.perf_counter() - t0) * 1000.0
            end_ts = datetime.now(UTC).isoformat()
            span_obj = TraceSpan(
                trace_id=tid,
                span_id=sid,
                parent_span_id=parent_span_id,
                name=name,
                start_time=start_ts,
                end_time=end_ts,
                duration_ms=dur_ms,
                status=status,
                attributes=span_attrs,
            )
            with self._lock:
                if len(self._spans) >= self.max_spans:
                    self._spans.pop(0)
                self._spans.append(span_obj)

    def get_spans(self, trace_id: str | None = None) -> list[TraceSpan]:
        with self._lock:
            if trace_id:
                return [s for s in self._spans if s.trace_id == trace_id]
            return list(self._spans)

    def clear(self) -> None:
        with self._lock:
            self._spans.clear()
