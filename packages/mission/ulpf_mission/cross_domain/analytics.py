"""Cross-domain analytics for Phase 10 — unified multi-domain telemetry analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class TelemetryDomain(str, Enum):
    """Security telemetry domain."""

    NETWORK = "NETWORK"
    IDENTITY = "IDENTITY"
    ENDPOINT = "ENDPOINT"
    APPLICATION = "APPLICATION"
    CLOUD = "CLOUD"


class DomainCoverageStatus(str, Enum):
    """Availability status for a telemetry domain.

    CRITICAL design principle: missing telemetry is NOT_AVAILABLE,
    never NO_ATTACK. Absence of evidence ≠ evidence of absence.
    """

    AVAILABLE = "AVAILABLE"
    PARTIALLY_AVAILABLE = "PARTIALLY_AVAILABLE"
    NOT_AVAILABLE = "NOT_AVAILABLE"


@dataclass
class DomainTelemetryStatus:
    """Coverage and event summary for one domain."""

    domain: TelemetryDomain
    status: DomainCoverageStatus
    event_count: int = 0
    alert_count: int = 0
    anomaly_count: int = 0
    sources: list[str] = field(default_factory=list)
    coverage_notes: str = ""


@dataclass
class CrossDomainReport:
    """Aggregated cross-domain analysis result."""

    domain_statuses: list[DomainTelemetryStatus]
    correlated_events: list[str]   # IDs of cross-domain correlated events
    blind_spots: list[TelemetryDomain]  # Domains with NOT_AVAILABLE status
    cross_domain_risk_score: float  # 0.0 – 100.0
    summary: str = ""
    recommendations: list[str] = field(default_factory=list)

    @property
    def coverage_fraction(self) -> float:
        """Fraction of domains with at least partial coverage."""
        if not self.domain_statuses:
            return 0.0
        available = sum(
            1
            for d in self.domain_statuses
            if d.status in (
                DomainCoverageStatus.AVAILABLE,
                DomainCoverageStatus.PARTIALLY_AVAILABLE,
            )
        )
        return available / len(self.domain_statuses)


class CrossDomainAnalytics:
    """Unified analysis across all five telemetry domains.

    Design contract: domains with no telemetry sources are marked NOT_AVAILABLE,
    never inferred as "clean." Downstream consumers must respect this distinction.
    """

    def analyze(
        self,
        domain_events: dict[str, list[dict[str, object]]],
    ) -> CrossDomainReport:
        """Run cross-domain analysis.

        Args:
            domain_events: mapping of domain name → list of event dicts.
                           Each event dict may have: id, alert, anomaly, source.
        """
        domain_statuses: list[DomainTelemetryStatus] = []
        blind_spots: list[TelemetryDomain] = []
        all_correlated_ids: list[str] = []
        total_risk_factors: list[float] = []

        for domain in TelemetryDomain:
            events = domain_events.get(domain.value, [])
            if not events:
                domain_statuses.append(
                    DomainTelemetryStatus(
                        domain=domain,
                        status=DomainCoverageStatus.NOT_AVAILABLE,
                        coverage_notes=(
                            "No telemetry sources registered for this domain. "
                            "Absence of events is NOT evidence of absence of threats."
                        ),
                    )
                )
                blind_spots.append(domain)
                continue

            sources: set[str] = set()
            alert_count = 0
            anomaly_count = 0
            event_ids: list[str] = []

            for ev in events:
                if src := ev.get("source"):
                    sources.add(str(src))
                if ev.get("alert"):
                    alert_count += 1
                if ev.get("anomaly"):
                    anomaly_count += 1
                if eid := ev.get("id"):
                    event_ids.append(str(eid))

            # Partial coverage when < 2 distinct sources
            status = (
                DomainCoverageStatus.AVAILABLE
                if len(sources) >= 2
                else DomainCoverageStatus.PARTIALLY_AVAILABLE
            )

            domain_statuses.append(
                DomainTelemetryStatus(
                    domain=domain,
                    status=status,
                    event_count=len(events),
                    alert_count=alert_count,
                    anomaly_count=anomaly_count,
                    sources=sorted(sources),
                )
            )

            if alert_count or anomaly_count:
                all_correlated_ids.extend(event_ids[:10])  # bounded
                risk = min(1.0, (alert_count * 10 + anomaly_count * 5) / 100.0)
                total_risk_factors.append(risk)

        # Risk score: average of domain risk factors, penalised for blind spots
        base_risk = (
            sum(total_risk_factors) / max(1, len(total_risk_factors)) * 100.0
            if total_risk_factors
            else 0.0
        )
        blind_spot_penalty = len(blind_spots) * 5.0
        cross_domain_risk = min(100.0, round(base_risk + blind_spot_penalty, 2))

        recs: list[str] = []
        for bd in blind_spots:
            recs.append(f"Deploy telemetry sources for {bd.value} domain to eliminate blind spot.")
        if cross_domain_risk >= 60.0:
            recs.append("Initiate cross-domain threat hunt across available domains.")

        summary = (
            f"{len(domain_statuses) - len(blind_spots)}/{len(domain_statuses)} domains covered. "
            f"Cross-domain risk score: {cross_domain_risk:.1f}/100. "
            f"Blind spots: {[b.value for b in blind_spots] or 'none'}."
        )

        return CrossDomainReport(
            domain_statuses=domain_statuses,
            correlated_events=list(set(all_correlated_ids)),
            blind_spots=blind_spots,
            cross_domain_risk_score=cross_domain_risk,
            summary=summary,
            recommendations=recs,
        )
