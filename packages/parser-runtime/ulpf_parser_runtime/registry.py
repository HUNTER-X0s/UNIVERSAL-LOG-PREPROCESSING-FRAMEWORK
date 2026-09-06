"""First-class ParserRegistry managing parser lifecycle, priority, and resolution.

Adheres to:
- Spec §11: Parser Registry
- Spec §46: Parser Priority / Ambiguity
- Spec §99: Parser Registry Discovery (introspection and self-description)
- Spec §133: Parser Registry Self-Description
"""

from typing import Any

from ulpf_parser_runtime.models import (
    ParserCandidate,
    ParserMetadata,
    ParserSelection,
)
from ulpf_parser_runtime.parsers.base import BaseParser


class ParserRegistry:
    """Thread-safe, deterministic registry of all active ULPF parsers."""

    def __init__(self) -> None:
        self._parsers: dict[str, BaseParser] = {}
        self._priorities: dict[str, int] = {}

    def register(self, parser: BaseParser, priority: int = 50) -> None:
        """Register a parser instance with an explicit priority integer."""
        p_id = parser.metadata.parser_id
        self._parsers[p_id] = parser
        self._priorities[p_id] = priority

    def unregister(self, parser_id: str) -> bool:
        """Unregister a parser instance by ID."""
        if parser_id in self._parsers:
            del self._parsers[parser_id]
            self._priorities.pop(parser_id, None)
            return True
        return False

    def get(self, parser_id: str) -> BaseParser | None:
        """Retrieve parser instance by ID."""
        return self._parsers.get(parser_id)

    def list_parsers(self) -> tuple[ParserMetadata, ...]:
        """Return metadata for all registered parsers sorted deterministically by ID."""
        return tuple(self._parsers[pid].metadata for pid in sorted(self._parsers))

    def discover_candidates(
        self,
        format_name: str,
        vendor: str | None = None,
        product: str | None = None,
    ) -> tuple[ParserCandidate, ...]:
        """Discover and rank candidate parsers for given format and optional source context."""
        candidates: list[ParserCandidate] = []

        norm_fmt = format_name.lower().strip()
        norm_vnd = vendor.lower().strip() if vendor else None
        norm_prd = product.lower().strip() if product else None

        for p_id, parser in self._parsers.items():
            meta = parser.metadata
            base_priority = self._priorities.get(p_id, 50)

            # Check format compatibility
            fmts = [f.lower() for f in meta.supported_formats]
            if "*" not in fmts and norm_fmt not in fmts:
                continue

            # Calculate match quality and suitability
            vnds = [v.lower() for v in meta.supported_vendors]
            prds = [p.lower() for p in meta.supported_products]

            has_vnd_match = norm_vnd is not None and norm_vnd in vnds
            has_prd_match = norm_prd is not None and norm_prd in prds

            # Specialized parsers (with declared vendors) ONLY qualify if there's a vendor match.
            # Generic parsers (no declared vendors) always qualify for their formats.
            is_specialized = len(vnds) > 0
            if is_specialized and not has_vnd_match:
                continue

            # Priority scoring:
            # - Exact vendor + product match: +100
            # - Exact vendor match: +50
            # - Generic format parser: +10
            match_score = base_priority
            if has_vnd_match and has_prd_match:
                match_score += 100
            elif has_vnd_match:
                match_score += 50
            elif meta.tier == "A":
                match_score += 10

            suitability = min(1.0, max(0.1, match_score / 200.0))
            candidates.append(
                ParserCandidate(
                    metadata=meta,
                    priority=match_score,
                    suitability_score=suitability,
                )
            )

        # Sort candidates descending by priority, then by parser_id for deterministic order
        candidates.sort(key=lambda c: (-c.priority, c.metadata.parser_id))
        return tuple(candidates)

    def select_parser(
        self,
        format_name: str,
        vendor: str | None = None,
        product: str | None = None,
    ) -> ParserSelection | None:
        """Select the highest-ranking candidate parser for given criteria."""
        candidates = self.discover_candidates(format_name, vendor, product)
        if not candidates:
            return None

        selected = candidates[0]
        reason = (
            f"Selected parser {selected.metadata.parser_id} (tier {selected.metadata.tier}) "
            f"with priority score {selected.priority} for format '{format_name}', "
            f"vendor '{vendor or 'unspecified'}', product '{product or 'unspecified'}'"
        )
        return ParserSelection(
            selected_parser=selected.metadata,
            confidence=selected.suitability_score,
            selection_reason=reason,
            candidates=candidates,
        )

    def self_description(self) -> dict[str, Any]:
        """Return machine-readable introspection catalog of all registered capabilities."""
        parsers_info = []
        formats_set: set[str] = set()
        vendors_set: set[str] = set()

        for pid in sorted(self._parsers):
            meta = self._parsers[pid].metadata
            formats_set.update(meta.supported_formats)
            vendors_set.update(meta.supported_vendors)
            parsers_info.append(
                {
                    "parser_id": meta.parser_id,
                    "version": meta.version,
                    "tier": meta.tier,
                    "supported_formats": list(meta.supported_formats),
                    "supported_vendors": list(meta.supported_vendors),
                    "supported_products": list(meta.supported_products),
                    "priority": self._priorities.get(pid, 50),
                    "description": meta.description,
                }
            )

        return {
            "total_parsers": len(self._parsers),
            "supported_formats": sorted(formats_set),
            "supported_vendors": sorted(vendors_set),
            "parsers": parsers_info,
        }


def create_default_registry() -> ParserRegistry:
    """Create a ParserRegistry populated with all standard Tier A, B, and C parsers."""
    from ulpf_parser_runtime.parsers.cef_parser import CefParser
    from ulpf_parser_runtime.parsers.csv_parser import GenericCsvParser
    from ulpf_parser_runtime.parsers.json_parser import GenericJsonParser, NdJsonParser
    from ulpf_parser_runtime.parsers.kv_parser import KeyValueParser
    from ulpf_parser_runtime.parsers.leef_parser import LeefParser
    from ulpf_parser_runtime.parsers.specialized.cisco import CiscoSyslogParser
    from ulpf_parser_runtime.parsers.specialized.cloud_audit import CloudAuditParser
    from ulpf_parser_runtime.parsers.specialized.fortigate import FortiGateParser
    from ulpf_parser_runtime.parsers.specialized.linux_auditd import LinuxAuditdParser
    from ulpf_parser_runtime.parsers.specialized.opnsense import OPNsenseFilterlogParser
    from ulpf_parser_runtime.parsers.specialized.paloalto import PaloAltoPanOSParser
    from ulpf_parser_runtime.parsers.specialized.snort import SnortFastParser
    from ulpf_parser_runtime.parsers.specialized.suricata import SuricataEveParser
    from ulpf_parser_runtime.parsers.specialized.web_access import WebAccessLogParser
    from ulpf_parser_runtime.parsers.specialized.zeek import ZeekParser
    from ulpf_parser_runtime.parsers.syslog_rfc3164 import SyslogRFC3164Parser
    from ulpf_parser_runtime.parsers.syslog_rfc5424 import SyslogRFC5424Parser
    from ulpf_parser_runtime.parsers.w3c_parser import W3CParser
    from ulpf_parser_runtime.parsers.xml_parser import XmlParser

    reg = ParserRegistry()
    # Tier A Generic Parsers
    reg.register(GenericJsonParser(), priority=10)
    reg.register(NdJsonParser(), priority=10)
    reg.register(GenericCsvParser(), priority=10)
    reg.register(KeyValueParser(), priority=10)
    reg.register(SyslogRFC3164Parser(), priority=20)
    reg.register(SyslogRFC5424Parser(), priority=20)
    reg.register(CefParser(), priority=25)
    reg.register(LeefParser(), priority=25)
    reg.register(W3CParser(), priority=20)
    reg.register(XmlParser(), priority=15)

    # Tier B Specialized Perimeter & Security Telemetry Parsers
    reg.register(PaloAltoPanOSParser(), priority=60)
    reg.register(FortiGateParser(), priority=60)
    reg.register(CiscoSyslogParser(), priority=60)
    reg.register(SuricataEveParser(), priority=60)
    reg.register(OPNsenseFilterlogParser(), priority=60)
    reg.register(SnortFastParser(), priority=60)
    reg.register(WebAccessLogParser(), priority=50)
    reg.register(ZeekParser(), priority=60)

    # Tier C Universal Extension Parsers
    reg.register(CloudAuditParser(), priority=50)
    reg.register(LinuxAuditdParser(), priority=50)

    return reg
