"""Threat Intelligence Validation and Deduplication Engine for ULPF Phase 9."""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import UTC, datetime

from ulpf_advanced_intelligence.errors import ThreatIntelValidationError
from ulpf_advanced_intelligence.models.threat_intel import (
    ObservableType,
    ThreatIntelIndicator,
)

_IPV4_REGEX = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$")
_DOMAIN_REGEX = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
_HEX_HASH_REGEX = re.compile(r"^[a-fA-F0-9]{32,128}$")


class ThreatIntelValidator:
    """Validates syntax, detects duplicates, and enforces integrity of Threat Intelligence."""

    @classmethod
    def validate_indicator(cls, indicator: ThreatIntelIndicator) -> None:
        """Validate an individual indicator's structure, syntax, and time boundaries."""
        if not indicator.normalized_value:
            raise ThreatIntelValidationError(f"Indicator {indicator.indicator_id} has empty value")

        val = indicator.normalized_value

        # Syntax checks by observable type
        if indicator.type == ObservableType.IPV4:
            if not _IPV4_REGEX.match(val):
                raise ThreatIntelValidationError(f"Invalid IPv4 format: {val}")
        elif indicator.type == ObservableType.DOMAIN:
            if not _DOMAIN_REGEX.match(val):
                raise ThreatIntelValidationError(f"Invalid domain format: {val}")
        elif indicator.type == ObservableType.HASH:
            if not _HEX_HASH_REGEX.match(val):
                raise ThreatIntelValidationError(f"Invalid cryptographic hash format: {val}")

        # Validate time bounds if present
        if indicator.valid_from and indicator.valid_until:
            if indicator.valid_from > indicator.valid_until:
                raise ThreatIntelValidationError(
                    f"valid_from ({indicator.valid_from}) cannot be after valid_until ({indicator.valid_until})"
                )

    @classmethod
    def deduplicate_and_merge(
        cls,
        indicators: Sequence[ThreatIntelIndicator],
        source_precedence: dict[str, int] | None = None,
    ) -> list[ThreatIntelIndicator]:
        """Deduplicate indicators by (type, normalized_value, tenant_id).

        Higher precedence source wins when duplicates exist.
        """
        precedence = source_precedence or {"CERT_IN": 100, "NTRO_LOCAL": 90, "COMMUNITY": 50}
        grouped: dict[tuple[str, str, str | None], ThreatIntelIndicator] = {}

        for ind in indicators:
            cls.validate_indicator(ind)
            key = (ind.type.value, ind.normalized_value.lower(), ind.tenant_id)
            if key not in grouped:
                grouped[key] = ind
            else:
                existing = grouped[key]
                p_curr = precedence.get(ind.source, 10)
                p_exist = precedence.get(existing.source, 10)
                if p_curr > p_exist:
                    grouped[key] = ind

        return list(grouped.values())

    @classmethod
    def sweep_expired(
        cls,
        indicators: Sequence[ThreatIntelIndicator],
        now_iso: str | None = None,
    ) -> tuple[list[ThreatIntelIndicator], list[ThreatIntelIndicator]]:
        """Separate active indicators from expired ones."""
        now = now_iso or datetime.now(UTC).isoformat()
        active: list[ThreatIntelIndicator] = []
        expired: list[ThreatIntelIndicator] = []

        for ind in indicators:
            if ind.valid_until and ind.valid_until < now:
                expired.append(ind)
            else:
                active.append(ind)

        return active, expired
