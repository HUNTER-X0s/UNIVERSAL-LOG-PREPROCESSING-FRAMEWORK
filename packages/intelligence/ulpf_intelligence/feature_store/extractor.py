"""Deterministic Feature Extraction Engine for ULPF Phase 8."""

from __future__ import annotations

import math
import uuid
from datetime import UTC, datetime
from typing import Any

from ulpf_intelligence.models.events import FeatureSnapshot

FEATURE_SCHEMA_VERSION = "1.0.0"


class FeatureExtractor:
    """Computes deterministic telemetry features over a window of canonical events."""

    @classmethod
    def extract_snapshot(
        cls,
        entity_id: str,
        events: list[dict[str, Any]],
        window_seconds: int = 60,
    ) -> FeatureSnapshot:
        """Convenience method computing feature snapshot over events."""
        now = datetime.now(UTC).isoformat()
        extractor = cls()
        snap = extractor.extract_features(
            entity_id=entity_id,
            events=events,
            window_start=now,
            window_end=now,
        )
        features = dict(snap.features)
        features["unique_destinations"] = features.get("unique_destinations_count", 0.0)
        features["unique_ports"] = features.get("unique_ports_count", 0.0)
        features["payload_entropy"] = features.get("destination_entropy", 0.0)
        return FeatureSnapshot(
            snapshot_id=snap.snapshot_id,
            entity_id=snap.entity_id,
            window_start=snap.window_start,
            window_end=snap.window_end,
            features=features,
            feature_version=snap.feature_version,
            computed_at=snap.computed_at,
        )

    def extract_features(
        self,
        entity_id: str,
        events: list[dict[str, Any]],
        window_start: str,
        window_end: str,
    ) -> FeatureSnapshot:
        """Compute statistical feature metrics over the provided events."""
        if not events:
            return FeatureSnapshot(
                snapshot_id=f"feat-{uuid.uuid4().hex[:12]}",
                entity_id=entity_id,
                window_start=window_start,
                window_end=window_end,
                features={},
                feature_version=FEATURE_SCHEMA_VERSION,
                computed_at=datetime.now(UTC).isoformat(),
            )

        total_count = float(len(events))
        unique_destinations: set[str] = set()
        unique_ports: set[int] = set()
        protocol_counts: dict[str, int] = {}
        action_counts: dict[str, int] = {}
        failure_count = 0.0

        for ev in events:
            dst = ev.get("dst_ip") or ev.get("destination_ip")
            if dst:
                unique_destinations.add(str(dst))

            port = ev.get("dst_port") or ev.get("port") or ev.get("src_port")
            if port is not None:
                try:
                    unique_ports.add(int(port))
                except (ValueError, TypeError):
                    pass

            proto = str(ev.get("protocol", "UNKNOWN")).upper()
            protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

            act = str(ev.get("action", "UNKNOWN")).upper()
            action_counts[act] = action_counts.get(act, 0) + 1
            if act in ("DENY", "DROP", "REJECT", "BLOCK", "FAIL", "FAILED", "FAILURE", "ERROR"):
                failure_count += 1.0

        # Calculate Shannon entropy over destination distribution
        dest_counts: dict[str, int] = {}
        for ev in events:
            d = str(ev.get("dst_ip") or "none")
            dest_counts[d] = dest_counts.get(d, 0) + 1

        entropy = 0.0
        for cnt in dest_counts.values():
            p = cnt / total_count
            if p > 0:
                entropy -= p * math.log2(p)

        failure_rate = failure_count / total_count if total_count > 0 else 0.0
        dest_diversity = len(unique_destinations) / total_count if total_count > 0 else 0.0
        port_diversity = len(unique_ports) / total_count if total_count > 0 else 0.0

        features = {
            "event_count": total_count,
            "failure_count": failure_count,
            "failure_rate": failure_rate,
            "unique_destinations_count": float(len(unique_destinations)),
            "destination_diversity": dest_diversity,
            "unique_ports_count": float(len(unique_ports)),
            "port_diversity": port_diversity,
            "destination_entropy": entropy,
        }

        return FeatureSnapshot(
            snapshot_id=f"feat-{uuid.uuid4().hex[:12]}",
            entity_id=entity_id,
            window_start=window_start,
            window_end=window_end,
            features=features,
            feature_version=FEATURE_SCHEMA_VERSION,
            computed_at=datetime.now(UTC).isoformat(),
        )
