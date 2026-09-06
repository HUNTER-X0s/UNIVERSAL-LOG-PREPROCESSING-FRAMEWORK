"""Outbox pattern delivery coordinator for ULPF Phase 6.

Enforces:
- Rule 10: Do not silently acknowledge before durable handoff
- Rule 61: Outbox pattern: canonical record + delivery intent, then dispatch
- Rule 25: Explicit delivery semantics (at-least-once, retried with DLQ escalation)
"""

import threading
from datetime import UTC, datetime
from typing import Any

from ulpf_runtime.models import DeliveryIntent
from ulpf_storage.interfaces import OutboxRepository

from ulpf_delivery.interfaces import DeliveryBatch, DeliverySink


class OutboxDispatcher:
    """Dispatches pending delivery intents from the OutboxRepository to configured sinks."""

    def __init__(self, outbox_repo: OutboxRepository, sinks: dict[str, DeliverySink]) -> None:
        self.outbox_repo = outbox_repo
        self.sinks = sinks
        self._lock = threading.Lock()

    def dispatch_pending(self, limit: int = 50) -> dict[str, Any]:
        """Process pending outbox records and hand off to corresponding sinks."""
        with self._lock:
            pending = self.outbox_repo.get_pending(limit=limit)
            delivered_count = 0
            failed_count = 0
            dlq_escalated = 0

            # Group intents by sink_name for efficient batch delivery
            by_sink: dict[str, list[DeliveryIntent]] = {}
            for intent in pending:
                by_sink.setdefault(intent.sink_name, []).append(intent)

            for sink_name, intents in by_sink.items():
                sink = self.sinks.get(sink_name)
                if not sink:
                    for i in intents:
                        self.outbox_repo.mark_failed(
                            i.intent_id, f"Sink {sink_name} not registered"
                        )
                        failed_count += 1
                    continue

                batch_id = f"outbox-batch-{sink_name}-{int(datetime.now(UTC).timestamp() * 1000)}"
                batch = DeliveryBatch(
                    sink_name=sink_name,
                    records=[i.payload for i in intents],
                    batch_id=batch_id,
                )

                res = sink.deliver(batch)
                if res.success:
                    for i in intents:
                        self.outbox_repo.mark_delivered(i.intent_id)
                        delivered_count += 1
                else:
                    err = res.error_message or "Unknown sink failure"
                    for i in intents:
                        self.outbox_repo.mark_failed(i.intent_id, err)
                        failed_count += 1
                        if i.attempt_count + 1 >= i.max_attempts:
                            dlq_escalated += 1

            return {
                "processed_count": len(pending),
                "delivered_count": delivered_count,
                "failed_count": failed_count,
                "dlq_escalated": dlq_escalated,
            }
