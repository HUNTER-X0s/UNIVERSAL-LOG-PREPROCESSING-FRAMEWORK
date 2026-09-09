"""Universal Source Intelligence Engine for ULPF Phase 13.

Workstream A: Identifies source family, vendor, device family, format,
parser candidate, schema candidate, explicit confidence, and supporting evidence.
Operates 100% deterministically and offline without external network dependencies.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class SourceIntelligenceDecision:
    """Explainable result of source intelligence analysis."""
    source_family: str          # e.g., "firewall", "edr", "cloud", "ids", "os_audit", "unknown"
    vendor: str                 # e.g., "Palo Alto Networks", "Fortinet", "Cisco", "Unknown"
    device_family: str          # e.g., "PAN-OS", "FortiGate", "ASA", "Linux Auditd", "Generic"
    detected_format: str        # e.g., "cef", "leef", "syslog_3164", "syslog_5424", "json", "kv"
    parser_candidate: str       # e.g., "PaloAltoPanOSParser", "FortiGateParser", "GenericJsonParser"
    schema_candidate: str       # e.g., "network_traffic", "authentication", "process_activity"
    confidence: float           # 0.0 to 1.0 (derived mathematically from token/structural weights)
    evidence: list[str]         # Explicit tokens, regex matches, and structural traits
    is_unknown: bool            # True if no known vendor/device signature matches above threshold
    explanation: str            # Human-readable rationale for the decision


# Signature definitions for deterministic identification
_VENDOR_SIGNATURES: list[dict[str, Any]] = [
    {
        "vendor": "Palo Alto Networks",
        "device_family": "PAN-OS",
        "source_family": "firewall",
        "parser_candidate": "PaloAltoPanOSParser",
        "schema_candidate": "network_traffic",
        "patterns": [
            (re.compile(r",TRAFFIC,"), 0.4, "header_token:TRAFFIC"),
            (re.compile(r",THREAT,"), 0.4, "header_token:THREAT"),
            (re.compile(r"\b1,\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2},\d{12,}\b"), 0.35, "panos_csv_header"),
            (re.compile(r"\bvsys\d+\b"), 0.25, "token:vsys"),
            (re.compile(r"\bPAN-OS\b", re.IGNORECASE), 0.5, "token:PAN-OS"),
        ],
    },
    {
        "vendor": "Fortinet",
        "device_family": "FortiGate",
        "source_family": "firewall",
        "parser_candidate": "FortiGateParser",
        "schema_candidate": "network_traffic",
        "patterns": [
            (re.compile(r"\bdevname=[\"']?"), 0.35, "kv_key:devname"),
            (re.compile(r"\btype=[\"']?(?:traffic|utm|event|virus)[\"']?"), 0.35, "kv_key:type"),
            (re.compile(r"\bpolicyid=\d+"), 0.25, "kv_key:policyid"),
            (re.compile(r"\bfortigate\b", re.IGNORECASE), 0.4, "token:fortigate"),
            (re.compile(r"\baction=[\"']?(?:accept|deny|close|client-rst)[\"']?"), 0.2, "kv_key:action"),
        ],
    },
    {
        "vendor": "Cisco",
        "device_family": "ASA",
        "source_family": "firewall",
        "parser_candidate": "CiscoSyslogParser",
        "schema_candidate": "network_traffic",
        "patterns": [
            (re.compile(r"%ASA-\d-\d{6}:"), 0.6, "header:cisco_asa_mnemonic"),
            (re.compile(r"\bBuilt (?:inbound|outbound) (?:TCP|UDP) connection\b"), 0.3, "cisco_conn_msg"),
            (re.compile(r"\bTeardown (?:TCP|UDP) connection\b"), 0.3, "cisco_teardown_msg"),
            (re.compile(r"\bDeny (?:tcp|udp|icmp) src\b", re.IGNORECASE), 0.3, "cisco_deny_msg"),
        ],
    },
    {
        "vendor": "Linux",
        "device_family": "Linux Auditd",
        "source_family": "os_audit",
        "parser_candidate": "LinuxAuditdParser",
        "schema_candidate": "process_activity",
        "patterns": [
            (re.compile(r"type=(?:SYSCALL|EXECVE|PATH|CWD|PROCTITLE)\b"), 0.5, "auditd_record_type"),
            (re.compile(r"msg=audit\(\d+\.\d+:\d+\):"), 0.4, "auditd_msg_header"),
            (re.compile(r"\bsyscall=\d+\b"), 0.3, "kv_key:syscall"),
            (re.compile(r"\bexe=[\"'][^\"']+[\"']"), 0.2, "kv_key:exe"),
        ],
    },
    {
        "vendor": "Suricata",
        "device_family": "Suricata EVE",
        "source_family": "ids",
        "parser_candidate": "SuricataEveParser",
        "schema_candidate": "network_alert",
        "patterns": [
            (re.compile(r"\"event_type\":\s*\"(?:alert|dns|http|tls|flow)\""), 0.5, "json_key:event_type"),
            (re.compile(r"\"alert\":\s*\{"), 0.35, "json_key:alert_object"),
            (re.compile(r"\"flow_id\":\s*\d+"), 0.25, "json_key:flow_id"),
            (re.compile(r"\bsuricata\b", re.IGNORECASE), 0.3, "token:suricata"),
        ],
    },
    {
        "vendor": "Amazon Web Services",
        "device_family": "AWS CloudTrail",
        "source_family": "cloud",
        "parser_candidate": "CloudAuditParser",
        "schema_candidate": "cloud_audit",
        "patterns": [
            (re.compile(r"\"eventVersion\":\s*\"1\.\d+\""), 0.45, "json_key:eventVersion"),
            (re.compile(r"\"userIdentity\":\s*\{"), 0.35, "json_key:userIdentity"),
            (re.compile(r"\"eventSource\":\s*\"[^\"]+\.amazonaws\.com\""), 0.4, "json_key:eventSource"),
            (re.compile(r"\"awsRegion\":"), 0.2, "json_key:awsRegion"),
        ],
    },
    {
        "vendor": "Snort",
        "device_family": "Snort Fast Alert",
        "source_family": "ids",
        "parser_candidate": "SnortFastParser",
        "schema_candidate": "network_alert",
        "patterns": [
            (re.compile(r"\[\*\*\]\s*\[\d+:\d+:\d+\]"), 0.6, "snort_gid_sid_rev"),
            (re.compile(r"\[Classification:\s*[^\]]+\]"), 0.3, "snort_classification"),
            (re.compile(r"\[Priority:\s*\d+\]"), 0.3, "snort_priority"),
        ],
    },
    {
        "vendor": "Zeek",
        "device_family": "Zeek Network Security",
        "source_family": "network_monitor",
        "parser_candidate": "ZeekParser",
        "schema_candidate": "network_traffic",
        "patterns": [
            (re.compile(r"^#fields\s+ts\s+uid\s+id\.orig_h", re.MULTILINE), 0.7, "zeek_fields_header"),
            (re.compile(r"^#types\s+time\s+string\s+addr", re.MULTILINE), 0.4, "zeek_types_header"),
        ],
    },
    {
        "vendor": "OPNsense",
        "device_family": "OPNsense filterlog",
        "source_family": "firewall",
        "parser_candidate": "OPNsenseFilterlogParser",
        "schema_candidate": "network_traffic",
        "patterns": [
            (re.compile(r"\bfilterlog(?:\[\d+\])?:\s*\d+,\d+,"), 0.6, "opnsense_filterlog_prefix"),
        ],
    },
    {
        "vendor": "W3C / Web",
        "device_family": "Combined Web Access",
        "source_family": "web",
        "parser_candidate": "WebAccessLogParser",
        "schema_candidate": "http_request",
        "patterns": [
            (re.compile(r'"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+\S+\s+HTTP/[12]\.[01]"\s+\d{3}\s+\d+'), 0.6, "http_request_line"),
            (re.compile(r'\[\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\]'), 0.3, "clf_timestamp"),
        ],
    },
]


class UniversalSourceIntelligenceEngine:
    """Analyzes raw and semi-structured telemetry to determine source lineage and format."""

    @classmethod
    def identify_format(cls, text: str) -> str:
        """Determines the wire/encoding format of the raw payload."""
        stripped = text.strip()
        if stripped.startswith("{") and stripped.endswith("}"):
            try:
                json.loads(stripped)
                return "json"
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

        if "CEF:0" in stripped or "CEF: 0" in stripped or stripped.startswith("CEF:"):
            return "cef"
        if "LEEF:1.0" in stripped or "LEEF:2.0" in stripped or stripped.startswith("LEEF:"):
            return "leef"
        if stripped.startswith("<") and ">" in stripped[:8]:
            if re.match(r"^<\d+>1\s", stripped):
                return "syslog_5424"
            return "syslog_3164"
        if "=" in stripped and " " in stripped and not stripped.startswith("{"):
            return "kv"
        if "," in stripped and ('"' in stripped or len(stripped.split(",")) > 5):
            return "csv"
        if stripped.startswith("<?xml") or (stripped.startswith("<") and stripped.endswith(">")):
            return "xml"
        if "#fields" in stripped or "\t" in stripped:
            return "tsv"
        return "generic_text"

    @classmethod
    def analyze(cls, raw_payload: str | bytes) -> SourceIntelligenceDecision:
        """Independently determine vendor, format, parser candidate, and explicit confidence."""
        if isinstance(raw_payload, bytes):
            text = raw_payload.decode("utf-8", errors="replace")
        else:
            text = str(raw_payload)

        detected_fmt = cls.identify_format(text)
        best_match: dict[str, Any] | None = None
        highest_score = 0.0
        collected_evidence: list[str] = [f"format:{detected_fmt}"]

        # Test against vendor signature bank
        for sig in _VENDOR_SIGNATURES:
            sig_score = 0.0
            sig_evidence: list[str] = []
            for pattern, weight, desc in sig["patterns"]:
                if pattern.search(text):
                    sig_score += weight
                    sig_evidence.append(desc)

            # Cap confidence at 0.999
            calculated_confidence = min(0.999, sig_score)
            if calculated_confidence > highest_score:
                highest_score = calculated_confidence
                best_match = sig
                collected_evidence = sig_evidence + [f"format:{detected_fmt}"]

        # Decision Threshold: >= 0.40 confidence qualifies as recognized vendor
        if best_match and highest_score >= 0.40:
            vendor = best_match["vendor"]
            device_family = best_match["device_family"]
            source_family = best_match["source_family"]
            parser = best_match["parser_candidate"]
            schema = best_match["schema_candidate"]
            is_unknown = False
            explanation = (
                f"Classified as {vendor} {device_family} ({source_family}) with confidence "
                f"{highest_score:.3f} supported by evidence: {', '.join(collected_evidence)}."
            )
        else:
            # Fallback to generic format handling
            format_to_parser = {
                "json": "GenericJsonParser",
                "cef": "CefParser",
                "leef": "LeefParser",
                "syslog_3164": "SyslogRFC3164Parser",
                "syslog_5424": "SyslogRFC5424Parser",
                "kv": "KeyValueParser",
                "csv": "GenericCsvParser",
                "xml": "XmlParser",
                "tsv": "GenericCsvParser",
            }
            parser = format_to_parser.get(detected_fmt, "GenericTextParser")
            vendor = "Unknown"
            device_family = "Generic / Unrecognized"
            source_family = "unclassified"
            schema = "generic_telemetry"
            highest_score = round(max(0.15, min(0.35, len(text.strip()) / 500.0)), 2)
            is_unknown = True
            explanation = (
                f"Unrecognized vendor signature. Detected structural format '{detected_fmt}'. "
                f"Assigned generic candidate {parser} with base confidence {highest_score:.2f}. "
                f"Recommended for guided onboarding review."
            )

        return SourceIntelligenceDecision(
            source_family=source_family,
            vendor=vendor,
            device_family=device_family,
            detected_format=detected_fmt,
            parser_candidate=parser,
            schema_candidate=schema,
            confidence=round(highest_score, 3),
            evidence=collected_evidence,
            is_unknown=is_unknown,
            explanation=explanation,
        )
