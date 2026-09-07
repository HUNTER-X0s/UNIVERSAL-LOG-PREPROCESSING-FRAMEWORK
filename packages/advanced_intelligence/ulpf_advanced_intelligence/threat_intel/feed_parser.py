"""Air-gapped, Offline Local Threat Intelligence Feed Ingestion Parser for ULPF Phase 9."""

from __future__ import annotations

import csv
import io
import json
import uuid
from typing import Any

from ulpf_advanced_intelligence.errors import FeedIngestionError
from ulpf_advanced_intelligence.models.threat_intel import (
    ObservableType,
    ThreatIntelBundle,
    ThreatIntelConfidence,
    ThreatIntelIndicator,
    ThreatIntelRelationship,
    ThreatIntelStatus,
)


class ThreatIntelFeedParser:
    """Parses local, air-gapped Threat Intelligence feeds (JSON, NDJSON, CSV, and STIX bundles)."""

    @classmethod
    def parse_json_feed(
        cls,
        content: str,
        source: str,
        source_version: str = "1.0.0",
        tenant_id: str | None = None,
    ) -> ThreatIntelBundle:
        """Parse a JSON array or bundle containing indicators."""
        try:
            data = json.loads(content)
        except Exception as exc:
            raise FeedIngestionError(f"Malformed JSON in threat intelligence feed: {exc}") from exc

        if isinstance(data, dict) and "indicators" in data:
            raw_indicators = data["indicators"]
        elif isinstance(data, list):
            raw_indicators = data
        elif isinstance(data, dict) and "objects" in data:
            # STIX 2.1-like bundle
            return cls.parse_stix_bundle(data, source=source, tenant_id=tenant_id)
        else:
            raise FeedIngestionError("Expected JSON array or dict with 'indicators' or 'objects'")

        indicators: list[ThreatIntelIndicator] = []
        for raw in raw_indicators:
            ind = cls._parse_single_indicator(raw, source=source, source_version=source_version, tenant_id=tenant_id)
            if ind:
                indicators.append(ind)

        return ThreatIntelBundle(
            bundle_id=f"bundle-{uuid.uuid4().hex[:12]}",
            source=source,
            version=source_version,
            indicators=tuple(indicators),
        )

    @classmethod
    def parse_ndjson_feed(
        cls,
        content: str,
        source: str,
        source_version: str = "1.0.0",
        tenant_id: str | None = None,
    ) -> ThreatIntelBundle:
        """Parse newline-delimited JSON threat intelligence lines."""
        indicators: list[ThreatIntelIndicator] = []
        for line_num, line in enumerate(content.splitlines(), start=1):
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue
            try:
                raw = json.loads(line_str)
                ind = cls._parse_single_indicator(raw, source=source, source_version=source_version, tenant_id=tenant_id)
                if ind:
                    indicators.append(ind)
            except Exception as exc:
                raise FeedIngestionError(f"Malformed NDJSON at line {line_num}: {exc}") from exc

        return ThreatIntelBundle(
            bundle_id=f"bundle-{uuid.uuid4().hex[:12]}",
            source=source,
            version=source_version,
            indicators=tuple(indicators),
        )

    @classmethod
    def parse_csv_feed(
        cls,
        content: str,
        source: str,
        source_version: str = "1.0.0",
        tenant_id: str | None = None,
    ) -> ThreatIntelBundle:
        """Parse CSV threat intelligence feed with standard header inference."""
        try:
            reader = csv.DictReader(io.StringIO(content))
            indicators: list[ThreatIntelIndicator] = []
            for row in reader:
                val = row.get("value") or row.get("indicator") or row.get("observable") or ""
                val = val.strip()
                if not val:
                    continue
                type_str = row.get("type") or row.get("observable_type") or cls._infer_observable_type(val)
                obs_type = cls._to_observable_type(type_str)
                status_str = (row.get("status") or "OBSERVED").upper()
                status = ThreatIntelStatus(status_str) if status_str in ThreatIntelStatus.__members__ else ThreatIntelStatus.OBSERVED
                conf_val = float(row.get("confidence", 0.8))

                ind = ThreatIntelIndicator(
                    indicator_id=row.get("indicator_id") or f"ti-{uuid.uuid4().hex[:12]}",
                    type=obs_type,
                    normalized_value=val.lower() if obs_type in (ObservableType.DOMAIN, ObservableType.EMAIL, ObservableType.HASH) else val,
                    source=source,
                    source_version=source_version,
                    confidence=ThreatIntelConfidence(indicator_confidence=conf_val),
                    status=status,
                    valid_from=row.get("valid_from", ""),
                    valid_until=row.get("valid_until", ""),
                    tenant_id=tenant_id,
                    description=row.get("description", ""),
                )
                indicators.append(ind)

            return ThreatIntelBundle(
                bundle_id=f"bundle-{uuid.uuid4().hex[:12]}",
                source=source,
                version=source_version,
                indicators=tuple(indicators),
            )
        except Exception as exc:
            raise FeedIngestionError(f"Failed parsing CSV feed: {exc}") from exc

    @classmethod
    def parse_stix_bundle(
        cls,
        stix_dict: dict[str, Any],
        source: str,
        tenant_id: str | None = None,
    ) -> ThreatIntelBundle:
        """Parse STIX 2.1 subset format (extracting indicator and relationship objects)."""
        objects = stix_dict.get("objects", [])
        indicators: list[ThreatIntelIndicator] = []
        relationships: list[ThreatIntelRelationship] = []

        for obj in objects:
            obj_type = obj.get("type")
            if obj_type == "indicator":
                pattern = obj.get("pattern", "")
                val = cls._extract_value_from_stix_pattern(pattern) or obj.get("name", "")
                obs_type = cls._infer_observable_type(val)
                ind = ThreatIntelIndicator(
                    indicator_id=obj.get("id") or f"ti-{uuid.uuid4().hex[:12]}",
                    type=obs_type,
                    normalized_value=val.lower() if obs_type in (ObservableType.DOMAIN, ObservableType.HASH) else val,
                    source=source,
                    source_version="stix-2.1",
                    confidence=ThreatIntelConfidence(indicator_confidence=float(obj.get("confidence", 80)) / 100.0),
                    status=ThreatIntelStatus.OBSERVED,
                    valid_from=obj.get("valid_from", ""),
                    valid_until=obj.get("valid_until", ""),
                    tenant_id=tenant_id,
                    description=obj.get("description", ""),
                )
                indicators.append(ind)
            elif obj_type == "relationship":
                rel = ThreatIntelRelationship(
                    relationship_id=obj.get("id") or f"rel-{uuid.uuid4().hex[:12]}",
                    source_ref=obj.get("source_ref", ""),
                    target_ref=obj.get("target_ref", ""),
                    relationship_type=obj.get("relationship_type", "related-to"),
                )
                relationships.append(rel)

        return ThreatIntelBundle(
            bundle_id=stix_dict.get("id") or f"bundle-{uuid.uuid4().hex[:12]}",
            source=source,
            version="stix-2.1",
            indicators=tuple(indicators),
            relationships=tuple(relationships),
        )

    @classmethod
    def _parse_single_indicator(
        cls,
        raw: dict[str, Any],
        source: str,
        source_version: str,
        tenant_id: str | None,
    ) -> ThreatIntelIndicator | None:
        val = raw.get("value") or raw.get("normalized_value") or raw.get("indicator")
        if not val or not str(val).strip():
            return None
        val_str = str(val).strip()
        type_str = raw.get("type") or cls._infer_observable_type(val_str)
        obs_type = cls._to_observable_type(str(type_str))
        status_str = str(raw.get("status", "OBSERVED")).upper()
        status = ThreatIntelStatus(status_str) if status_str in ThreatIntelStatus.__members__ else ThreatIntelStatus.OBSERVED

        norm_val = val_str.lower() if obs_type in (ObservableType.DOMAIN, ObservableType.EMAIL, ObservableType.HASH) else val_str
        conf_data = raw.get("confidence")
        if isinstance(conf_data, dict):
            conf = ThreatIntelConfidence(
                source_confidence=float(conf_data.get("source_confidence", 0.8)),
                indicator_confidence=float(conf_data.get("indicator_confidence", 0.8)),
                match_confidence=float(conf_data.get("match_confidence", 1.0)),
                risk_contribution=float(conf_data.get("risk_contribution", 25.0)),
            )
        elif isinstance(conf_data, int | float):
            conf = ThreatIntelConfidence(indicator_confidence=float(conf_data))
        else:
            conf = ThreatIntelConfidence()

        tags = raw.get("tags", [])
        return ThreatIntelIndicator(
            indicator_id=str(raw.get("indicator_id") or f"ti-{uuid.uuid4().hex[:12]}"),
            type=obs_type,
            normalized_value=norm_val,
            source=source,
            source_version=source_version,
            confidence=conf,
            first_seen=str(raw.get("first_seen", "")),
            last_seen=str(raw.get("last_seen", "")),
            valid_from=str(raw.get("valid_from", "")),
            valid_until=str(raw.get("valid_until", "")),
            status=status,
            tenant_id=tenant_id,
            tags=tuple(tags) if isinstance(tags, list | tuple) else (),
            description=str(raw.get("description", "")),
        )

    @staticmethod
    def _infer_observable_type(val: str) -> ObservableType:
        """Determine likely observable category from string characteristics."""
        val = val.strip()
        if ":" in val and not val.startswith("http"):
            # Potential IPv6
            return ObservableType.IPV6
        parts = val.split(".")
        if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            return ObservableType.IPV4
        if len(val) in (32, 40, 64, 128) and all(c in "0123456789abcdefABCDEF" for c in val):
            return ObservableType.HASH
        if "@" in val:
            return ObservableType.EMAIL
        if val.startswith("http://") or val.startswith("https://"):
            return ObservableType.URL
        if "." in val and not val.endswith("."):
            return ObservableType.DOMAIN
        return ObservableType.NETWORK_ARTIFACT

    @staticmethod
    def _to_observable_type(name: str) -> ObservableType:
        norm = name.upper().replace("-", "_").replace(" ", "_")
        if norm in ("IP", "IPV4_ADDR", "IPV4"):
            return ObservableType.IPV4
        if norm in ("IPV6_ADDR", "IPV6"):
            return ObservableType.IPV6
        if norm in ("DOMAIN_NAME", "DOMAIN"):
            return ObservableType.DOMAIN
        if norm in ("SHA256", "MD5", "SHA1", "FILE_HASH", "HASH"):
            return ObservableType.HASH
        if norm in ("URL", "URI"):
            return ObservableType.URL
        for member in ObservableType:
            if member.value == norm:
                return member
        return ObservableType.NETWORK_ARTIFACT

    @staticmethod
    def _extract_value_from_stix_pattern(pattern: str) -> str:
        """Extract literal observable from STIX comparison pattern (e.g., [ipv4-addr:value = '1.2.3.4'])."""
        if "'" in pattern:
            parts = pattern.split("'")
            if len(parts) >= 2:
                return parts[1]
        if '"' in pattern:
            parts = pattern.split('"')
            if len(parts) >= 2:
                return parts[1]
        return ""
