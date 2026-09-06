"""Specialized (Tier B & Tier C) telemetry parsers for ULPF Phase 3."""

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

__all__ = [
    "CiscoSyslogParser",
    "CloudAuditParser",
    "FortiGateParser",
    "LinuxAuditdParser",
    "OPNsenseFilterlogParser",
    "PaloAltoPanOSParser",
    "SnortFastParser",
    "SuricataEveParser",
    "WebAccessLogParser",
    "ZeekParser",
]
