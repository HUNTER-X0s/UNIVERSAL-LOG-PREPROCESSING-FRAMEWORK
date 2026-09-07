"""Mission simulation engine for Phase 10 — synthetic attack progression generator."""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field


@dataclass
class SimulatedEvent:
    """A single synthetic event produced by the simulation engine."""

    event_id: str
    timestamp: float
    event_type: str
    source_ip: str
    dest_ip: str
    user: str
    label: str       # "ATTACK" | "BENIGN"
    stage: str       # e.g., "INITIAL_ACCESS", "EXECUTION", "BENIGN_DNS"
    metadata: dict[str, object] = field(default_factory=dict)

    @property
    def is_attack(self) -> bool:
        return self.label == "ATTACK"

    @property
    def source(self) -> str:
        return self.source_ip

    @property
    def payload(self) -> dict[str, object]:
        return {"user": self.user, "stage": self.stage, "type": self.event_type}


@dataclass
class SimulationRun:
    """Result of one simulation run."""

    run_id: str
    events: list[SimulatedEvent]
    attack_event_count: int
    benign_event_count: int
    stages_simulated: list[str]
    duration_s: float

    @property
    def total_events(self) -> int:
        return len(self.events)

    @property
    def attack_events(self) -> int:
        return self.attack_event_count

    @property
    def benign_events(self) -> int:
        return self.benign_event_count

    @property
    def attack_type(self) -> str:
        return "BRUTE_FORCE"

    @property
    def seed(self) -> int:
        return 42


class MissionSimulationEngine:
    """Generates labelled synthetic attack progressions with benign background noise.

    Design principles:
    - Deterministic when seeded (reproducible for tests).
    - All data is synthetic; no real credentials or PII.
    - Benign noise is realistic (DNS, routine HTTP, auth) to avoid trivial ML bias.
    """

    def generate(
        self,
        attack_type: str = "BRUTE_FORCE",
        event_count: int = 50,
        noise_ratio: float = 0.7,
        seed: int = 42,
    ) -> SimulationRun:
        benign_count = int(event_count * noise_ratio)
        attack_count = max(1, event_count - benign_count)
        return self.simulate(
            run_id=f"sim-{attack_type.lower()}-{seed}",
            attack_event_count=attack_count,
            benign_event_count=benign_count,
            seed=seed,
        )

    _ATTACK_STAGES = [
        "INITIAL_ACCESS",
        "EXECUTION",
        "PERSISTENCE",
        "PRIVILEGE_ESCALATION",
        "LATERAL_MOVEMENT",
        "EXFILTRATION",
    ]

    _BENIGN_STAGES = ["BENIGN_DNS", "BENIGN_HTTP", "BENIGN_AUTH"]

    def simulate(
        self,
        run_id: str,
        *,
        attack_event_count: int = 30,
        benign_event_count: int = 200,
        seed: int | None = 42,
    ) -> SimulationRun:
        """Generate a simulation run with attack and benign events.

        Args:
            run_id: unique identifier for this run.
            attack_event_count: number of attack events to generate.
            benign_event_count: number of benign background events.
            seed: optional RNG seed for deterministic output.
        """
        rng = random.Random(seed)  # noqa: S311 — deterministic simulation RNG, not cryptographic
        start = time.time()
        events: list[SimulatedEvent] = []
        base_ts = time.time() - 3600.0  # start 1 hour ago

        # Generate benign background events
        for i in range(benign_event_count):
            stage = rng.choice(self._BENIGN_STAGES)
            events.append(
                SimulatedEvent(
                    event_id=f"{run_id}-benign-{i:04d}",
                    timestamp=base_ts + rng.uniform(0, 3600),
                    event_type=self._benign_event_type(stage),
                    source_ip=f"10.0.{rng.randint(1,254)}.{rng.randint(1,254)}",
                    dest_ip=f"8.8.{rng.randint(1, 8)}.{rng.randint(1, 8)}",
                    user=f"user_{rng.randint(1, 50)}",
                    label="BENIGN",
                    stage=stage,
                    metadata={"simulated": True},
                )
            )

        # Generate attack events in stage order
        attack_ts = base_ts + 1800.0  # attack starts midway
        events_per_stage = max(1, attack_event_count // len(self._ATTACK_STAGES))
        stage_order = list(self._ATTACK_STAGES)
        for stage_idx, stage in enumerate(stage_order):
            for j in range(events_per_stage):
                events.append(
                    SimulatedEvent(
                        event_id=f"{run_id}-attack-{stage_idx:02d}-{j:04d}",
                        timestamp=attack_ts + stage_idx * 60 + j * 2,
                        event_type=self._attack_event_type(stage),
                        source_ip="192.168.100.10",  # attacker pivot host
                        dest_ip=f"10.0.1.{rng.randint(1, 50)}",
                        user="attacker_svc",
                        label="ATTACK",
                        stage=stage,
                        metadata={
                            "simulated": True,
                            "mitre_tactic": stage,
                            "kill_chain_position": stage_idx + 1,
                        },
                    )
                )

        # Sort by timestamp for realistic ordering
        events.sort(key=lambda e: e.timestamp)

        return SimulationRun(
            run_id=run_id,
            events=events,
            attack_event_count=attack_event_count,
            benign_event_count=benign_event_count,
            stages_simulated=stage_order,
            duration_s=round(time.time() - start, 4),
        )

    @staticmethod
    def _benign_event_type(stage: str) -> str:
        mapping = {
            "BENIGN_DNS": "dns_query",
            "BENIGN_HTTP": "http_request",
            "BENIGN_AUTH": "auth_success",
        }
        return mapping.get(stage, "generic_event")

    @staticmethod
    def _attack_event_type(stage: str) -> str:
        mapping = {
            "INITIAL_ACCESS": "auth_failure",
            "EXECUTION": "process_exec",
            "PERSISTENCE": "scheduled_task_create",
            "PRIVILEGE_ESCALATION": "token_impersonation",
            "LATERAL_MOVEMENT": "network_connection",
            "EXFILTRATION": "file_transfer",
        }
        return mapping.get(stage, "unknown_event")
