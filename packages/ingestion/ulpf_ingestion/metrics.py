"""Small in-process intake counters with bounded dimensions only."""

from collections import Counter
from threading import Lock

from ulpf_ingestion.models import TransportProtocol


class IntakeMetrics:
    """Count capture outcomes without raw payloads or high-cardinality labels."""

    def __init__(self) -> None:
        self._counts: Counter[tuple[str, str]] = Counter()
        self._lock = Lock()

    def increment(self, outcome: str, protocol: TransportProtocol) -> None:
        """Record one bounded outcome/transport pair."""
        with self._lock:
            self._counts[(outcome, protocol.value)] += 1

    def snapshot(self) -> dict[str, int]:
        """Return stable counter names suitable for a future metrics exporter."""
        with self._lock:
            return {
                f"intake_{outcome}_total{{transport={protocol}}}": count
                for (outcome, protocol), count in sorted(self._counts.items())
            }
