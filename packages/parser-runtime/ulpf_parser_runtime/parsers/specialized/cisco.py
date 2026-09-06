"""Cisco ASA and IOS-XE syslog parser for ULPF Phase 3 (Tier B).

Parses Cisco network security syslog:
- Cisco ASA (%ASA-severity-message_id: message)
- Cisco IOS/IOS-XE (%FACILITY-severity-MNEMONIC: message)

Extracts:
- timestamp, hostname
- cisco_facility, cisco_severity, cisco_mnemonic / message_code
- connection action (built, teardown, deny, permit, drop)
- protocol (tcp, udp, icmp)
- src_interface, src_ip, src_port
- dst_interface, dst_ip, dst_port
- bytes, duration, packet count
- rule / access-list name

Adheres to:
- Spec §15: Vendor-Specific Specialized Parsers
- Spec §41: Resource Bounds
- Spec §45: Deterministic Parsing
"""

import re
import time
from typing import Any

from ulpf_parser_runtime.errors import ErrorCode, ErrorSeverity, ParseError
from ulpf_parser_runtime.framing import FramedRecord
from ulpf_parser_runtime.models import (
    Origin,
    ParseResult,
    ParserMetadata,
    ParseStatus,
)
from ulpf_parser_runtime.parsers.base import BaseParser

# Matches Cisco tag: %ASA-6-302013 or %SEC-6-IPACCESSLOGP
RE_CISCO_TAG = re.compile(r"%([A-Z0-9_]+)-(\d)-([A-Z0-9_]+):")

# Common ASA connection patterns:
# outside:198.51.100.50/54321
RE_IFACE_IP_PORT = re.compile(r"([a-zA-Z0-9_\-\.]+):([0-9a-fA-F\.\:]+)/(\d+)")

# ASA connection built/teardown
RE_BUILT = re.compile(
    r"Built\s+(?:inbound|outbound)?\s*([A-Za-z0-9]+)\s+connection\s+(\d+)\s+for\s+([^\s]+)\s+(?:\([^\)]+\)\s+)?to\s+([^\s]+)",
    re.IGNORECASE,
)
RE_TEARDOWN = re.compile(
    r"Teardown\s+([A-Za-z0-9]+)\s+connection\s+(\d+)\s+for\s+([^\s]+)\s+to\s+([^\s]+)\s+duration\s+([^\s]+)\s+bytes\s+(\d+)",
    re.IGNORECASE,
)
# Deny pattern: Deny tcp src outside:203.0.113.88/61234 dst inside:10.0.0.1/445
# by access-group "OUTSIDE-IN"

RE_DENY = re.compile(
    r"Deny\s+([A-Za-z0-9]+)\s+src\s+([^\s]+)\s+dst\s+([^\s]+)(?:\s+by\s+access-group\s+\"([^\"]+)\")?",
    re.IGNORECASE,
)


def _parse_iface_ip_port(token: str) -> tuple[str | None, str | None, str | None]:
    """Parse interface:ip/port (e.g., 'outside:198.51.100.50/54321')."""
    m = RE_IFACE_IP_PORT.search(token)
    if m:
        return m.group(1), m.group(2), m.group(3)
    # Check if just ip:port
    if ":" in token and "/" not in token:
        parts = token.split(":")
        return None, parts[0], parts[1]
    return None, token, None


class CiscoSyslogParser(BaseParser):
    """Deterministic parser for Cisco ASA and IOS-XE perimeter syslog telemetry."""

    metadata = ParserMetadata(
        parser_id="parser.cisco.asa_ios",
        version="1.0.0",
        supported_formats=("cisco_syslog", "syslog_rfc3164"),
        supported_vendors=("Cisco", "Cisco Systems"),
        supported_products=("ASA", "Adaptive Security Appliance", "IOS-XE", "PIX"),
        tier="B",
        description="Cisco ASA and IOS-XE perimeter firewall and security syslog parser",
    )

    def parse(self, record: FramedRecord) -> ParseResult:
        t0 = time.perf_counter()
        text = record.text.strip()

        tag_match = RE_CISCO_TAG.search(text)
        if not tag_match:
            err = ParseError(
                code=ErrorCode.UNKNOWN_SOURCE,
                stage="cisco_parser",
                message="No Cisco syslog tag (%FACILITY-SEV-MNEMONIC:) found",
                severity=ErrorSeverity.ERROR,
                recoverable=False,
            )
            return ParseResult(
                status=ParseStatus.FAILED,
                parser_id=self.metadata.parser_id,
                parser_version=self.metadata.version,
                format="cisco_syslog",
                extracted_fields={},
                unmapped_fields={"raw_text": text},
                unparsed_fragments=(text,),
                errors=(err,),
                duration_ms=self.measure_duration(t0),
            )

        facility = tag_match.group(1)
        severity = tag_match.group(2)
        mnemonic = tag_match.group(3)

        fields: dict[str, Any] = {
            "cisco_facility": self.make_field("cisco_facility", facility, Origin.OBSERVED),
            "cisco_severity": self.make_field("cisco_severity", int(severity), Origin.OBSERVED),
            "cisco_mnemonic": self.make_field("cisco_mnemonic", mnemonic, Origin.OBSERVED),
        }

        # Header prefix before tag (contains timestamp and host)
        header_prefix = text[: tag_match.start()].strip()
        if header_prefix:
            parts = header_prefix.split()
            if len(parts) >= 3:
                fields["timestamp"] = self.make_field(
                    "timestamp",
                    " ".join(parts[:3]),
                    Origin.OBSERVED,
                    raw_locator="cisco:header:timestamp",
                )
            if len(parts) >= 4:
                fields["hostname"] = self.make_field(
                    "hostname",
                    parts[3],
                    Origin.OBSERVED,
                    raw_locator="cisco:header:hostname",
                )

        # Body after tag:
        body = text[tag_match.end() :].strip()
        fields["message"] = self.make_field("message", body, Origin.OBSERVED)

        # Extract semantics based on mnemonic / body
        if mnemonic == "302013" or "Built" in body:
            fields["action"] = self.make_field("action", "built", Origin.DERIVED)
            m_built = RE_BUILT.search(body)
            if m_built:
                fields["protocol"] = self.make_field(
                    "protocol", m_built.group(1).lower(), Origin.OBSERVED
                )
                fields["connection_id"] = self.make_field(
                    "connection_id", m_built.group(2), Origin.OBSERVED
                )
                s_if, s_ip, s_port = _parse_iface_ip_port(m_built.group(3))
                d_if, d_ip, d_port = _parse_iface_ip_port(m_built.group(4))
                if s_if:
                    fields["src_interface"] = self.make_field(
                        "src_interface", s_if, Origin.OBSERVED
                    )
                if s_ip:
                    fields["src_ip"] = self.make_field("src_ip", s_ip, Origin.OBSERVED)
                if s_port:
                    fields["src_port"] = self.make_field("src_port", s_port, Origin.OBSERVED)
                if d_if:
                    fields["dst_interface"] = self.make_field(
                        "dst_interface", d_if, Origin.OBSERVED
                    )
                if d_ip:
                    fields["dst_ip"] = self.make_field("dst_ip", d_ip, Origin.OBSERVED)
                if d_port:
                    fields["dst_port"] = self.make_field("dst_port", d_port, Origin.OBSERVED)

        elif mnemonic == "302014" or "Teardown" in body:
            fields["action"] = self.make_field("action", "teardown", Origin.DERIVED)
            m_tear = RE_TEARDOWN.search(body)
            if m_tear:
                fields["protocol"] = self.make_field(
                    "protocol", m_tear.group(1).lower(), Origin.OBSERVED
                )
                fields["connection_id"] = self.make_field(
                    "connection_id", m_tear.group(2), Origin.OBSERVED
                )
                s_if, s_ip, s_port = _parse_iface_ip_port(m_tear.group(3))
                d_if, d_ip, d_port = _parse_iface_ip_port(m_tear.group(4))
                if s_if:
                    fields["src_interface"] = self.make_field(
                        "src_interface", s_if, Origin.OBSERVED
                    )
                if s_ip:
                    fields["src_ip"] = self.make_field("src_ip", s_ip, Origin.OBSERVED)
                if s_port:
                    fields["src_port"] = self.make_field("src_port", s_port, Origin.OBSERVED)
                if d_if:
                    fields["dst_interface"] = self.make_field(
                        "dst_interface", d_if, Origin.OBSERVED
                    )
                if d_ip:
                    fields["dst_ip"] = self.make_field("dst_ip", d_ip, Origin.OBSERVED)
                if d_port:
                    fields["dst_port"] = self.make_field("dst_port", d_port, Origin.OBSERVED)
                fields["duration"] = self.make_field("duration", m_tear.group(5), Origin.OBSERVED)
                fields["bytes"] = self.make_field("bytes", m_tear.group(6), Origin.OBSERVED)

        elif mnemonic == "106023" or "Deny" in body:
            fields["action"] = self.make_field("action", "deny", Origin.DERIVED)
            m_deny = RE_DENY.search(body)
            if m_deny:
                fields["protocol"] = self.make_field(
                    "protocol", m_deny.group(1).lower(), Origin.OBSERVED
                )
                s_if, s_ip, s_port = _parse_iface_ip_port(m_deny.group(2))
                d_if, d_ip, d_port = _parse_iface_ip_port(m_deny.group(3))
                if s_if:
                    fields["src_interface"] = self.make_field(
                        "src_interface", s_if, Origin.OBSERVED
                    )
                if s_ip:
                    fields["src_ip"] = self.make_field("src_ip", s_ip, Origin.OBSERVED)
                if s_port:
                    fields["src_port"] = self.make_field("src_port", s_port, Origin.OBSERVED)
                if d_if:
                    fields["dst_interface"] = self.make_field(
                        "dst_interface", d_if, Origin.OBSERVED
                    )
                if d_ip:
                    fields["dst_ip"] = self.make_field("dst_ip", d_ip, Origin.OBSERVED)
                if d_port:
                    fields["dst_port"] = self.make_field("dst_port", d_port, Origin.OBSERVED)
                if m_deny.group(4):
                    fields["access_group"] = self.make_field(
                        "access_group", m_deny.group(4), Origin.OBSERVED
                    )

        return ParseResult(
            status=ParseStatus.PARSED,
            parser_id=self.metadata.parser_id,
            parser_version=self.metadata.version,
            format="cisco_syslog",
            extracted_fields=fields,
            duration_ms=self.measure_duration(t0),
        )
