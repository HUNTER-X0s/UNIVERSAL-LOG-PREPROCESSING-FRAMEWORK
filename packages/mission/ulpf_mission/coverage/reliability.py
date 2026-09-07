"""Source reliability calculator for Phase 10 coverage plane."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SourceReliabilityScore:
    """Reliability score for a single telemetry source."""

    source_id: str
    ingestion_continuity: float    # 0.0–1.0 — uptime fraction
    parse_success_rate: float      # 0.0–1.0
    schema_drift_penalty: float    # 0.0–1.0 (higher = worse drift)
    composite_score: float         # 0.0–100.0
    verdict: str                   # "RELIABLE" | "DEGRADED" | "UNRELIABLE"

    @property
    def is_reliable(self) -> bool:
        return self.verdict == "RELIABLE"

    @property
    def overall_score(self) -> float:
        return self.composite_score / 100.0


class SourceReliabilityCalculator:
    """Scores telemetry source reliability from ingestion telemetry."""

    # Factor weights
    _W_CONTINUITY: float = 0.50
    _W_PARSE: float = 0.35
    _W_DRIFT: float = 0.15

    def calculate(
        self,
        source_name: str,
        *,
        total_records: int,
        parse_errors: int,
        schema_violations: int,
        gap_duration_seconds: float = 0.0,
    ) -> SourceReliabilityScore:
        parsed_ok = max(0, total_records - parse_errors)
        return self.score(
            source_id=source_name,
            total_windows=10,
            windows_with_events=10 if gap_duration_seconds == 0 else 8,
            total_events=total_records,
            successfully_parsed=parsed_ok,
            schema_version_changes=min(10, int(schema_violations / max(1, total_records) * 20.0)),
        )

    def score(
        self,
        source_id: str,
        *,
        total_windows: int,
        windows_with_events: int,
        total_events: int,
        successfully_parsed: int,
        schema_version_changes: int,
    ) -> SourceReliabilityScore:
        """Compute a reliability score for a single source."""
        continuity = windows_with_events / max(1, total_windows)
        parse_rate = successfully_parsed / max(1, total_events)
        drift_penalty = min(1.0, schema_version_changes / 10.0)

        composite_raw = (
            self._W_CONTINUITY * continuity
            + self._W_PARSE * parse_rate
            - self._W_DRIFT * drift_penalty
        )
        composite = round(max(0.0, min(1.0, composite_raw)) * 100.0, 2)

        verdict = (
            "RELIABLE" if composite >= 80.0 else "DEGRADED" if composite >= 50.0 else "UNRELIABLE"
        )

        return SourceReliabilityScore(
            source_id=source_id,
            ingestion_continuity=round(continuity, 4),
            parse_success_rate=round(parse_rate, 4),
            schema_drift_penalty=round(drift_penalty, 4),
            composite_score=composite,
            verdict=verdict,
        )
