"""Deterministic Indicator Extractor for ULPF Phase 4.

Extracts verifiable telemetry indicators (IP, Domain, URL, Hash)
for threat hunting and correlation foundations.
"""

import ipaddress
import re
from typing import Any

from ulpf_semantic.models import Indicator, IndicatorType

RE_DOMAIN = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
RE_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")


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

        # 3. Hash indicators
        for key, val in unmapped.items():
            if isinstance(val, str):
                if RE_SHA256.match(val):
                    indicators.append(
                        Indicator(
                            indicator_type=IndicatorType.HASH_SHA256.value,
                            value=val.lower(),
                            source=f"unmapped:{key}",
                            confidence=1.0,
                        )
                    )
                elif RE_MD5.match(val):
                    indicators.append(
                        Indicator(
                            indicator_type=IndicatorType.HASH_MD5.value,
                            value=val.lower(),
                            source=f"unmapped:{key}",
                            confidence=0.95,
                        )
                    )

        return indicators
