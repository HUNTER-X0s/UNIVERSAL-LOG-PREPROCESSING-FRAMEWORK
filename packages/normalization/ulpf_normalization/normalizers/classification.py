"""Event classification normalizer for ULPF Phase 3.

Infers and normalizes event category, type, and class:
- category: network, security, audit, system, web, identity
- type: flow, alert, firewall, access, authentication, syscall
- class: perimeter_firewall_traffic, network_ids_alert, web_access_log, etc.

Adheres to:
- Spec §30: Semantic Classification Taxonomy
- Spec §33: Universal Canonical Event (UCE) Schema
"""

from typing import Any


def classify_event(
    extracted_fields: dict[str, Any],
    parser_id: str,
    vendor: str | None = None,
) -> tuple[str, str, str]:
    """Determine (category, type, class) for an event based on parser, vendor, and fields."""
    p_id = parser_id.lower()
    vnd = (vendor or "").lower()

    # 1. IDS / IPS Alert
    if "alert" in p_id or "snort" in p_id or "suricata" in p_id:
        event_type = (
            extracted_fields.get("event_type", {}).get("value")
            if isinstance(extracted_fields.get("event_type"), dict)
            else extracted_fields.get("event_type")
        )
        if (
            event_type == "alert"
            or "signature" in extracted_fields
            or "alert.signature" in extracted_fields
        ):
            return "security", "alert", "network_ids_alert"
        if event_type == "flow":
            return "network", "flow", "network_flow_record"
        if event_type == "dns":
            return "network", "query", "dns_lookup_event"

    # 2. Perimeter Firewalls (Palo Alto, Fortinet, Cisco, OPNsense, Checkpoint)
    if any(
        fw in p_id or fw in vnd
        for fw in ("paloalto", "fortinet", "cisco", "opnsense", "checkpoint")
    ):
        return "security", "firewall", "perimeter_firewall_event"

    # 3. Web Access (Apache, NGINX, IIS, W3C)
    if "web" in p_id or "w3c" in p_id or "access" in p_id or "status_code" in extracted_fields:
        return "web", "access", "web_access_log"

    # 4. Network Flow (Zeek conn, VPC flow)
    if "zeek" in p_id or "vpc_flow" in p_id:
        return "network", "flow", "network_flow_record"

    # 5. Cloud Audit / Control Plane
    if "cloud" in p_id or "audit" in p_id:
        return "audit", "control_plane", "cloud_audit_activity"

    # 6. Linux Auditd
    if "auditd" in p_id:
        return "system", "audit", "kernel_syscall_audit"

    # 7. Syslog Generic
    if "syslog" in p_id:
        return "system", "log", "system_syslog_event"

    return "system", "generic", "unclassified_event"
