"""Entity Behavioral Profiler and Signal Extractor for ULPF Phase 9."""

from __future__ import annotations

import statistics
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from ulpf_advanced_intelligence.models.behavior import (
    BaselineDriftState,
    BehavioralAnomalyFinding,
    EntityBehaviorProfile,
)


class EntityBehaviorProfiler:
    """Constructs and evaluates baseline behavior profiles for hosts, users, and network entities."""

    @classmethod
    def create_initial_profile(
        cls,
        entity_id: str,
        entity_type: str,
        training_events: Sequence[dict[str, Any]],
        tenant_id: str | None = None,
    ) -> EntityBehaviorProfile:
        """Construct a baseline profile from historical training observations."""
        now_iso = datetime.now(UTC).isoformat()
        peers: set[str] = set()
        ports: set[int] = set()
        protocols: set[str] = set()
        hours: set[int] = set()
        freqs: dict[str, int] = {}

        for ev in training_events:
            dst = ev.get("dst_ip") or ev.get("destination_ip") or ev.get("target_host")
            if dst:
                peers.add(str(dst))
            port = ev.get("dst_port") or ev.get("port")
            if port is not None:
                try:
                    ports.add(int(port))
                except (ValueError, TypeError):
                    pass
            proto = str(ev.get("protocol", "TCP")).upper()
            protocols.add(proto)

            action = str(ev.get("action") or ev.get("category") or "EVENT").upper()
            freqs[action] = freqs.get(action, 0) + 1

            ts = ev.get("timestamp") or ev.get("captured_at")
            if ts:
                try:
                    dt = datetime.fromisoformat(str(ts))
                    hours.add(dt.hour)
                except (ValueError, TypeError):
                    pass

        total = float(len(training_events)) or 1.0
        normalized_freqs = {k: v / total for k, v in freqs.items()}

        return EntityBehaviorProfile(
            entity_id=entity_id,
            entity_type=entity_type,
            tenant_id=tenant_id,
            first_seen=now_iso,
            last_seen=now_iso,
            normal_hours=tuple(sorted(hours)) if hours else tuple(range(8, 19)),
            usual_peers=tuple(sorted(peers)),
            usual_ports=tuple(sorted(ports)),
            usual_protocols=tuple(sorted(protocols)) if protocols else ("TCP", "UDP"),
            baseline_frequencies=normalized_freqs,
            baseline_risk=15.0,
            drift_state=BaselineDriftState.STABLE,
            version=1,
            updated_at=now_iso,
        )

    @classmethod
    def evaluate_behavior(
        cls,
        profile: EntityBehaviorProfile,
        events: Sequence[dict[str, Any]],
    ) -> list[BehavioralAnomalyFinding]:
        """Detect behavioral shifts (rare ports, protocols, destination explosions, beaconing)."""
        findings: list[BehavioralAnomalyFinding] = []
        if not events:
            return findings

        # 1. Rare Ports
        rare_ports: set[int] = set()
        rare_port_events: list[str] = []
        for ev in events:
            p = ev.get("dst_port") or ev.get("port")
            if p is not None:
                try:
                    port_int = int(p)
                    if profile.usual_ports and port_int not in profile.usual_ports:
                        rare_ports.add(port_int)
                        rare_port_events.append(str(ev.get("event_id", "unknown")))
                except (ValueError, TypeError):
                    pass

        if rare_ports:
            findings.append(
                BehavioralAnomalyFinding(
                    anomaly_id=f"beh-{uuid.uuid4().hex[:10]}",
                    entity_id=profile.entity_id,
                    signal_type="RARE_PORT",
                    baseline_value=list(profile.usual_ports),
                    observed_value=list(rare_ports),
                    deviation=float(len(rare_ports)),
                    threshold=0.0,
                    confidence=0.85,
                    window_seconds=300,
                    evidence=tuple(rare_port_events[:10]),
                    tenant_id=profile.tenant_id,
                )
            )

        # 2. Rare Protocol
        rare_protocols: set[str] = set()
        rare_proto_events: list[str] = []
        for ev in events:
            proto = str(ev.get("protocol", "")).upper()
            if proto and profile.usual_protocols and proto not in profile.usual_protocols:
                rare_protocols.add(proto)
                rare_proto_events.append(str(ev.get("event_id", "unknown")))

        if rare_protocols:
            findings.append(
                BehavioralAnomalyFinding(
                    anomaly_id=f"beh-{uuid.uuid4().hex[:10]}",
                    entity_id=profile.entity_id,
                    signal_type="RARE_PROTOCOL",
                    baseline_value=list(profile.usual_protocols),
                    observed_value=list(rare_protocols),
                    deviation=float(len(rare_protocols)),
                    threshold=0.0,
                    confidence=0.9,
                    window_seconds=300,
                    evidence=tuple(rare_proto_events[:10]),
                    tenant_id=profile.tenant_id,
                )
            )

        # 3. Beaconing Detection (regular periodic timestamps with low variance)
        timestamps: list[float] = []
        for ev in events:
            ts = ev.get("timestamp") or ev.get("captured_at")
            if ts:
                try:
                    dt = datetime.fromisoformat(str(ts))
                    timestamps.append(dt.timestamp())
                except (ValueError, TypeError):
                    pass

        if len(timestamps) >= 4:
            timestamps.sort()
            deltas = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]
            if len(deltas) >= 3:
                mean_delta = statistics.mean(deltas)
                if mean_delta > 1.0:  # Minimum 1 sec interval
                    stdev_delta = statistics.stdev(deltas)
                    coeff_var = stdev_delta / mean_delta if mean_delta > 0 else 1.0
                    # Very low coefficient of variation (< 0.15) indicates rhythmic automated beaconing
                    if coeff_var < 0.15:
                        findings.append(
                            BehavioralAnomalyFinding(
                                anomaly_id=f"beh-{uuid.uuid4().hex[:10]}",
                                entity_id=profile.entity_id,
                                signal_type="BEACONING_ACTIVITY",
                                baseline_value={"periodic": False},
                                observed_value={"interval_mean_sec": round(mean_delta, 2), "jitter_stdev": round(stdev_delta, 2)},
                                deviation=round(1.0 - coeff_var, 4),
                                threshold=0.85,
                                confidence=0.92,
                                window_seconds=int(timestamps[-1] - timestamps[0]),
                                evidence=tuple(str(ev.get("event_id", "")) for ev in events[:5]),
                                tenant_id=profile.tenant_id,
                            )
                        )

        return findings
