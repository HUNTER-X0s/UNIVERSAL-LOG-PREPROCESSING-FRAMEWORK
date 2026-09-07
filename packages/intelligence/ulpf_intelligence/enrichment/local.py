"""Air-gapped, Offline Local Enrichment Service for ULPF Phase 8."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from ulpf_intelligence.models.provenance import IntelligenceProvenance


class LocalEnrichmentService:
    """Provides offline enrichment from local asset registries without external network calls."""

    def __init__(self) -> None:
        # IP / subnet -> asset metadata
        self._asset_db: dict[str, dict[str, Any]] = {
            "10.0.0.1": {"hostname": "core-gw.perimeter.local", "criticality": "HIGH", "zone": "DMZ"},
            "10.0.0.15": {"hostname": "auth-srv.internal.local", "criticality": "CRITICAL", "zone": "INTERNAL"},
            "192.168.1.100": {"hostname": "workstation-01.local", "criticality": "LOW", "zone": "USER_LAN"},
        }
        # Known threat / IOC allow/block lists
        self._ioc_list: dict[str, str] = {
            "198.51.100.25": "SUSPICIOUS_EXTERNAL_PROBE",
            "203.0.113.5": "KNOWN_MALICIOUS_SCANNER",
        }

    def enrich_event(self, event_dict: dict[str, Any]) -> dict[str, Any]:
        """Attach local asset and zone context to an event without modifying original raw fields."""
        enriched = dict(event_dict)
        now_iso = datetime.now(UTC).isoformat()
        enrichment_data: dict[str, Any] = {
            "enriched_at": now_iso,
            "provenance": IntelligenceProvenance.ENRICHED.value,
        }

        src_ip = str(event_dict.get("src_ip", ""))
        dst_ip = str(event_dict.get("dst_ip", ""))

        if src_ip in self._asset_db:
            enrichment_data["src_asset"] = self._asset_db[src_ip]
        if dst_ip in self._asset_db:
            enrichment_data["dst_asset"] = self._asset_db[dst_ip]

        if src_ip in self._ioc_list:
            enrichment_data["src_ioc_classification"] = self._ioc_list[src_ip]
        if dst_ip in self._ioc_list:
            enrichment_data["dst_ioc_classification"] = self._ioc_list[dst_ip]

        enriched["_enrichment"] = enrichment_data
        return enriched

    def register_asset(self, ip: str, metadata: dict[str, Any]) -> None:
        self._asset_db[ip] = metadata
