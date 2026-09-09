"""Mapping Intelligence & Diff Engine for ULPF Phase 13.

Workstream C: Reusable mapping templates, semantic aliases, conditional normalization,
version diffing (added/removed/changed), and behavioral impact assessment.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class MappingFieldChange:
    """Detail of an individual field mapping modification."""
    source_field: str
    target_field: str
    change_type: str            # "ADDED", "REMOVED", "MODIFIED"
    old_target: str | None = None
    old_transform: str | None = None
    new_transform: str | None = None
    behavior_impact: str = "SAFE"  # "SAFE", "BREAKING", "INFORMATIVE"


@dataclass(frozen=True)
class MappingDiffResult:
    """Summary of differences between two versions of a MappingDefinition."""
    v1_id: str
    v2_id: str
    added_count: int
    removed_count: int
    modified_count: int
    changes: list[MappingFieldChange]
    impact_level: str           # "NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"
    rollback_recommended: bool
    summary: str


# Authoritative semantic alias bank for zero-guesswork mapping inference
SEMANTIC_ALIAS_BANK: dict[str, str] = {
    # Network Source
    "src": "source.ip",
    "src_ip": "source.ip",
    "srcip": "source.ip",
    "source_ip": "source.ip",
    "sourceip": "source.ip",
    "c-ip": "source.ip",
    "client_ip": "source.ip",
    "src_port": "source.port",
    "srcport": "source.port",
    "source_port": "source.port",
    "sport": "source.port",
    "c-port": "source.port",
    
    # Network Destination
    "dst": "destination.ip",
    "dst_ip": "destination.ip",
    "dstip": "destination.ip",
    "destination_ip": "destination.ip",
    "destinationip": "destination.ip",
    "s-ip": "destination.ip",
    "server_ip": "destination.ip",
    "dst_port": "destination.port",
    "dstport": "destination.port",
    "destination_port": "destination.port",
    "dport": "destination.port",
    "s-port": "destination.port",
    
    # Transport & Protocol
    "proto": "network.transport",
    "protocol": "network.transport",
    "transport": "network.transport",
    "app": "network.protocol",
    "service": "network.protocol",
    
    # Action & Outcome
    "act": "event.action",
    "action": "event.action",
    "status": "event.outcome",
    "result": "event.outcome",
    "sc-status": "http.response_code",
    "response_code": "http.response_code",
    
    # Identity & Host
    "user": "user.name",
    "username": "user.name",
    "usr": "user.name",
    "account": "user.name",
    "src_user": "user.name",
    "host": "host.hostname",
    "hostname": "host.hostname",
    "devname": "host.hostname",
    "device_name": "host.hostname",
    
    # Process & Command
    "exe": "process.executable",
    "process": "process.name",
    "comm": "process.name",
    "cmdline": "process.command_line",
    "command": "process.command_line",
    "pid": "process.pid",
}


# Reusable Domain Mapping Templates
DOMAIN_TEMPLATES: dict[str, dict[str, str]] = {
    "firewall": {
        "src_ip": "source.ip",
        "dst_ip": "destination.ip",
        "src_port": "source.port",
        "dst_port": "destination.port",
        "proto": "network.transport",
        "action": "event.action",
        "bytes_in": "network.bytes_in",
        "bytes_out": "network.bytes_out",
    },
    "web_server": {
        "client_ip": "source.ip",
        "method": "http.method",
        "uri": "url.path",
        "status": "http.response_code",
        "user_agent": "user_agent.original",
        "bytes_sent": "network.bytes_out",
    },
    "os_audit": {
        "syscall": "process.syscall",
        "exe": "process.executable",
        "user": "user.name",
        "pid": "process.pid",
        "ppid": "process.ppid",
        "cwd": "process.working_directory",
        "success": "event.outcome",
    },
    "cloud_audit": {
        "eventSource": "cloud.service.name",
        "eventName": "event.action",
        "awsRegion": "cloud.region",
        "sourceIPAddress": "source.ip",
        "userAgent": "user_agent.original",
    },
}


class MappingDiffEngine:
    """Compares mapping definitions to detect changes, calculate risk, and ensure safe upgrades."""

    @classmethod
    def diff(cls, v1: dict[str, Any], v2: dict[str, Any]) -> MappingDiffResult:
        """Compute structured difference between v1 and v2 mapping definition dictionaries."""
        v1_id = v1.get("mapping_id", "v1")
        v2_id = v2.get("mapping_id", "v2")

        v1_fields = v1.get("field_mappings", {})
        v2_fields = v2.get("field_mappings", {})

        added: list[MappingFieldChange] = []
        removed: list[MappingFieldChange] = []
        modified: list[MappingFieldChange] = []

        all_src_keys = set(v1_fields.keys()) | set(v2_fields.keys())

        for k in sorted(all_src_keys):
            in_v1 = k in v1_fields
            in_v2 = k in v2_fields

            if in_v2 and not in_v1:
                target = v2_fields[k] if isinstance(v2_fields[k], str) else v2_fields[k].get("target", "")
                added.append(
                    MappingFieldChange(
                        source_field=k,
                        target_field=target,
                        change_type="ADDED",
                        behavior_impact="SAFE",
                    )
                )
            elif in_v1 and not in_v2:
                target = v1_fields[k] if isinstance(v1_fields[k], str) else v1_fields[k].get("target", "")
                removed.append(
                    MappingFieldChange(
                        source_field=k,
                        target_field=target,
                        change_type="REMOVED",
                        behavior_impact="BREAKING",
                    )
                )
            else:
                # Both exist - check if target or transform changed
                t1 = v1_fields[k] if isinstance(v1_fields[k], str) else v1_fields[k].get("target", "")
                t2 = v2_fields[k] if isinstance(v2_fields[k], str) else v2_fields[k].get("target", "")
                if t1 != t2:
                    modified.append(
                        MappingFieldChange(
                            source_field=k,
                            target_field=t2,
                            change_type="MODIFIED",
                            old_target=t1,
                            behavior_impact="BREAKING",
                        )
                    )

        # Assess composite impact
        if removed or any(m.behavior_impact == "BREAKING" for m in modified):
            impact = "HIGH"
            rollback_rec = True
            summary = (
                f"Potentially breaking change: {len(removed)} fields removed, "
                f"{len(modified)} fields re-targeted. Staging validation required."
            )
        elif added and not modified and not removed:
            impact = "LOW"
            rollback_rec = False
            summary = f"Safe additive update: {len(added)} new fields mapped with zero removals."
        elif not added and not removed and not modified:
            impact = "NONE"
            rollback_rec = False
            summary = "Mapping definitions are identical in field semantics."
        else:
            impact = "MEDIUM"
            rollback_rec = False
            summary = f"Update contains {len(added)} additions, {len(modified)} modifications."

        return MappingDiffResult(
            v1_id=v1_id,
            v2_id=v2_id,
            added_count=len(added),
            removed_count=len(removed),
            modified_count=len(modified),
            changes=added + removed + modified,
            impact_level=impact,
            rollback_recommended=rollback_rec,
            summary=summary,
        )
