"""Security posture engine and risk trend analytics for Phase 10."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from ulpf_mission.models.posture import (
    RiskTrendRecord,
    SecurityPostureLevel,
    SecurityPostureState,
)


def _clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, value))


# ---------------------------------------------------------------------------
# SecurityPostureEngine
# ---------------------------------------------------------------------------

class SecurityPostureEngine:
    """Multi-factor deterministic posture calculator.

    All factor weights are explicit and inspectable; there are no hidden
    learned parameters. This preserves air-gap compliance.
    """

    # Factor weights (must sum to 1.0)
    _W_CRITICAL_ALERTS: float = 0.35
    _W_CAMPAIGNS: float = 0.20
    _W_ANOMALY_RATE: float = 0.20
    _W_TI_MATCHES: float = 0.15
    _W_SOURCE_HEALTH: float = 0.10

    # Thresholds for saturating individual factors
    _CRITICAL_ALERT_SAT: int = 10    # ≥10 critical alerts → factor = 1.0
    _CAMPAIGN_SAT: int = 5           # ≥5 active campaigns → factor = 1.0
    _ANOMALY_RATE_SAT: float = 0.25  # ≥25% anomaly rate → factor = 1.0
    _TI_MATCH_SAT: int = 20          # ≥20 TI matches → factor = 1.0

    def calculate(
        self,
        *,
        critical_alert_count: int,
        active_campaign_count: int,
        anomaly_event_count: int,
        total_event_count: int,
        ti_match_count: int,
        unhealthy_source_fraction: float,
    ) -> SecurityPostureState:
        """Compute a SecurityPostureState from raw telemetry counters."""
        f_alert = _clamp(critical_alert_count / max(1, self._CRITICAL_ALERT_SAT))
        f_campaign = _clamp(active_campaign_count / max(1, self._CAMPAIGN_SAT))
        anomaly_rate = anomaly_event_count / max(1, total_event_count)
        f_anomaly = _clamp(anomaly_rate / self._ANOMALY_RATE_SAT)
        f_ti = _clamp(ti_match_count / max(1, self._TI_MATCH_SAT))
        f_health = _clamp(unhealthy_source_fraction)

        raw_score = (
            self._W_CRITICAL_ALERTS * f_alert
            + self._W_CAMPAIGNS * f_campaign
            + self._W_ANOMALY_RATE * f_anomaly
            + self._W_TI_MATCHES * f_ti
            + self._W_SOURCE_HEALTH * f_health
        )
        risk_score = round(raw_score * 100.0, 2)
        level = self._score_to_level(risk_score)

        rationale = (
            f"critical_alerts={critical_alert_count} (f={f_alert:.2f}), "
            f"campaigns={active_campaign_count} (f={f_campaign:.2f}), "
            f"anomaly_rate={anomaly_rate:.2%} (f={f_anomaly:.2f}), "
            f"ti_matches={ti_match_count} (f={f_ti:.2f}), "
            f"source_health_penalty={unhealthy_source_fraction:.2f}"
        )

        recs: list[str] = []
        if f_alert >= 0.6:
            recs.append("Triage and close or escalate critical alerts immediately.")
        if f_campaign >= 0.6:
            recs.append("Investigate active campaign clusters for lateral movement.")
        if f_anomaly >= 0.6:
            recs.append("Review anomaly spikes for baseline drift or attacker activity.")
        if f_ti >= 0.6:
            recs.append("Block or quarantine assets matching active threat intel.")
        if f_health >= 0.3:
            recs.append("Restore unhealthy telemetry sources to ensure full coverage.")

        return SecurityPostureState(
            level=level,
            risk_score=risk_score,
            critical_alert_factor=round(f_alert, 4),
            campaign_volume_factor=round(f_campaign, 4),
            anomaly_rate_factor=round(f_anomaly, 4),
            ti_match_factor=round(f_ti, 4),
            source_health_factor=round(f_health, 4),
            rationale=rationale,
            recommendations=recs,
        )

    @staticmethod
    def _score_to_level(score: float) -> SecurityPostureLevel:
        if score >= 75.0:
            return SecurityPostureLevel.CRITICAL
        if score >= 50.0:
            return SecurityPostureLevel.HIGH
        if score >= 25.0:
            return SecurityPostureLevel.ELEVATED
        return SecurityPostureLevel.NORMAL


# ---------------------------------------------------------------------------
# RiskTrendAnalytics
# ---------------------------------------------------------------------------

_MAX_HOURLY_RECORDS = 168   # 7 days × 24 h
_MAX_DAILY_RECORDS = 365    # 1 year


@dataclass
class _BoundedSeries:
    max_len: int
    records: deque[RiskTrendRecord] = field(default_factory=deque)

    def append(self, record: RiskTrendRecord) -> None:
        self.records.append(record)
        while len(self.records) > self.max_len:
            self.records.popleft()

    def as_list(self) -> list[RiskTrendRecord]:
        return list(self.records)


class RiskTrendAnalytics:
    """Bounded time-series posture tracker (hourly and daily windows)."""

    def __init__(self) -> None:
        self._hourly: _BoundedSeries = _BoundedSeries(max_len=_MAX_HOURLY_RECORDS)
        self._daily: _BoundedSeries = _BoundedSeries(max_len=_MAX_DAILY_RECORDS)

    def record(self, posture: SecurityPostureState, *, counters: dict[str, int | float]) -> None:
        """Append a posture snapshot to both hourly and daily series."""
        rec = RiskTrendRecord(
            timestamp=posture.timestamp,
            posture_level=posture.level,
            risk_score=posture.risk_score,
            active_alerts=int(counters.get("critical_alert_count", 0)),
            ti_matches=int(counters.get("ti_match_count", 0)),
            anomaly_count=int(counters.get("anomaly_event_count", 0)),
        )
        self._hourly.append(rec)
        self._daily.append(rec)

    def hourly_trend(self, last_n: int = 24) -> list[RiskTrendRecord]:
        """Return at most *last_n* hourly records (newest last)."""
        recs = self._hourly.as_list()
        return recs[-last_n:]

    def daily_trend(self, last_n: int = 30) -> list[RiskTrendRecord]:
        """Return at most *last_n* daily records (newest last)."""
        recs = self._daily.as_list()
        return recs[-last_n:]

    def peak_risk_score(self, window: str = "hourly") -> float:
        """Return the maximum risk score observed in the requested window."""
        series = self._hourly.as_list() if window == "hourly" else self._daily.as_list()
        if not series:
            return 0.0
        return max(r.risk_score for r in series)

    def average_risk_score(self, window: str = "hourly") -> float:
        """Return the mean risk score in the requested window."""
        series = self._hourly.as_list() if window == "hourly" else self._daily.as_list()
        if not series:
            return 0.0
        return round(sum(r.risk_score for r in series) / len(series), 2)
