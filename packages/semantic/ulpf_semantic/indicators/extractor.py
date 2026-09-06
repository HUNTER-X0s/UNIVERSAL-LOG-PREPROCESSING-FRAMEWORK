"""Deterministic Indicator Extractor for ULPF Phase 4 & Phase 5.

Extracts verifiable telemetry indicators (IP, Domain, URL, Hash, Email)
for threat hunting and correlation foundations with bounded complexity.
"""

import ipaddress
import re
from typing import Any

from ulpf_semantic.models import Indicator, IndicatorType

RE_DOMAIN = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
RE_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
RE_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
RE_EMAIL = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
RE_URL = re.compile(r"^https?://[a-zA-Z0-9-._~:/?#[\]@!$&'()*+,;=]{1,2048}$")

MAX_INDICATORS_PER_EVENT = 50


class IndicatorExtractor:
    """Extracts verifiable security indicators from event fields."""

    @staticmethod
    def extract_indicators(uce_event: dict[str, Any]) -> list[Indicator]:
        """Extract deterministic indicators from event fields."""
        indicators: list[Indicator] = []
        event_body = uce_event.get("event", {})
        unmapped = uce_event.get("unmapped_fields", {})

        # 1. External/Public IP indicators
        for side in ("source", "destination"):
            side_dict = event_body.get(side, {})
            if isinstance(side_dict, dict) and side_dict.get("ip"):
                ip_str = str(side_dict["ip"]).strip()
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    if not ip_obj.is_private and not ip_obj.is_loopback:
                        indicators.append(
                            Indicator(
                                indicator_type=IndicatorType.IP.value,
                                value=ip_str,
                                source=f"event.{side}.ip",
                                confidence=0.98,
                            )
                        )
                except ValueError:
                    pass

        # 2. Domain / Host indicators
        for key in ("query", "domain", "qname", "host", "hostname"):
            val = event_body.get("metadata", {}).get(key) or unmapped.get(key)
            if val and isinstance(val, str) and RE_DOMAIN.match(val):
                indicators.append(
                    Indicator(
                        indicator_type=IndicatorType.DOMAIN.value,
                        value=val.lower(),
                        source=f"field:{key}",
                        confidence=0.95,
                    )
                )

        # 3. Hash indicators (MD5, SHA1, SHA256)
        for k, v in unmapped.items():
            if isinstance(v, str):
                v_clean = v.strip()
                if RE_SHA256.match(v_clean):
                    indicators.append(
                        Indicator(
                            indicator_type=IndicatorType.HASH_SHA256.value,
                            value=v_clean.lower(),
                            source=f"unmapped.{k}",
                            confidence=1.0,
                        )
                    )
                elif RE_SHA1.match(v_clean):
                    indicators.append(
                        Indicator(
                            indicator_type=IndicatorType.HASH_SHA1.value,
                            value=v_clean.lower(),
                            source=f"unmapped.{k}",
                            confidence=0.98,
                        )
                    )
                elif RE_MD5.match(v_clean):
                    indicators.append(
                        Indicator(
                            indicator_type=IndicatorType.HASH_MD5.value,
                            value=v_clean.lower(),
                            source=f"unmapped.{k}",
                            confidence=0.95,
                        )
                    )

        # 4. Email indicators (Phase 5 Expansion)
        for k, v in unmapped.items():
            if isinstance(v, str) and "@" in v:
                v_clean = v.strip()
                if len(v_clean) <= 128 and RE_EMAIL.match(v_clean):
                    indicators.append(
                        Indicator(
                            indicator_type=IndicatorType.EMAIL.value,
                            value=v_clean.lower(),
                            source=f"unmapped.{k}",
                            confidence=0.95,
                        )
                    )

        # 5. URL indicators (Phase 5 Expansion)
        url_candidates = {**event_body, **unmapped}
        for k, v in url_candidates.items():
            if isinstance(v, str) and (v.startswith("http://") or v.startswith("https://")):
                v_clean = v.strip()
                if len(v_clean) <= 2048 and RE_URL.match(v_clean):
                    indicators.append(
                        Indicator(
                            indicator_type=IndicatorType.URL.value,
                            value=v_clean,
                            source=f"field.{k}",
                            confidence=0.95,
                        )
                    )

        return indicators[:MAX_INDICATORS_PER_EVENT]
