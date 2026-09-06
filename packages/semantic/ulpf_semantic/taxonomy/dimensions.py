"""Universal Analytics Dimensions and Aggregation Keys for ULPF Phase 4.

Defines standard dimensional attributes and deterministic aggregation keys
enabling searching, filtering, and future correlation across all log domains.
"""

from typing import Any


def extract_aggregation_keys(
    event_dict: dict[str, Any],
    vendor: str | None = None,
    product: str | None = None,
) -> dict[str, str]:
    """Extract standard deterministic aggregation keys for grouping, metrics, and analytics."""
    keys: dict[str, str] = {}

    src = event_dict.get("source", {})
    if isinstance(src, dict) and src.get("ip"):
        keys["source_ip"] = str(src["ip"])

    dst = event_dict.get("destination", {})
    if isinstance(dst, dict) and dst.get("ip"):
        keys["destination_ip"] = str(dst["ip"])

    net = event_dict.get("network", {})
    if isinstance(net, dict) and net.get("protocol"):
        keys["protocol"] = str(net["protocol"]).upper()

    identity = event_dict.get("identity", {})
    if isinstance(identity, dict):
        user_info = identity.get("user", {})
        if isinstance(user_info, dict) and user_info.get("name"):
            keys["user"] = str(user_info["name"])

    device = event_dict.get("device", {})
    if isinstance(device, dict) and device.get("hostname"):
        keys["host"] = str(device["hostname"])

    if vendor:
        keys["vendor"] = vendor
    if product:
        keys["product"] = product

    return keys
