"""Deterministic Entity Extraction and Normalization for ULPF Phase 4.

Extracts normalized entities (IP, Host, User, Device, Container, Cloud Resource)
preserving both original values and normalized representations.
"""

import ipaddress
from typing import Any

from ulpf_semantic.models import Entity, EntityType


class EntityExtractor:
    """Extracts typed, normalized entities from UCE records."""

    @staticmethod
    def extract_entities(uce_event: dict[str, Any]) -> list[Entity]:
        """Extract all identifiable entities from a UCE event."""
        entities: list[Entity] = []
        event_body = uce_event.get("event", {})
        unmapped = uce_event.get("unmapped_fields", {})

        # 1. Source IP
        src = event_body.get("source", {})
        if isinstance(src, dict) and src.get("ip"):
            raw_ip = str(src["ip"]).strip()
            norm_ip = EntityExtractor._normalize_ip(raw_ip)
            entities.append(
                Entity(
                    entity_id=f"ent:ip:{norm_ip or raw_ip}",
                    entity_type=EntityType.IP.value,
                    value=raw_ip,
                    normalized_value=norm_ip,
                    role="source",
                    attributes={"port": src.get("port")} if src.get("port") else {},
                    confidence=1.0 if norm_ip else 0.8,
                )
            )

        # 2. Destination IP
        dst = event_body.get("destination", {})
        if isinstance(dst, dict) and dst.get("ip"):
            raw_ip = str(dst["ip"]).strip()
            norm_ip = EntityExtractor._normalize_ip(raw_ip)
            entities.append(
                Entity(
                    entity_id=f"ent:ip:{norm_ip or raw_ip}",
                    entity_type=EntityType.IP.value,
                    value=raw_ip,
                    normalized_value=norm_ip,
                    role="destination",
                    attributes={"port": dst.get("port")} if dst.get("port") else {},
                    confidence=1.0 if norm_ip else 0.8,
                )
            )

        # 3. User Identity
        identity = event_body.get("identity", {})
        if isinstance(identity, dict):
            user_info = identity.get("user", {})
            if isinstance(user_info, dict) and user_info.get("name"):
                user_name = str(user_info["name"]).strip()
                entities.append(
                    Entity(
                        entity_id=f"ent:user:{user_name.lower()}",
                        entity_type=EntityType.USER.value,
                        value=user_name,
                        normalized_value=user_name.lower(),
                        role="actor",
                        attributes=user_info,
                        confidence=0.95,
                    )
                )

        # 4. Host / Device
        device = event_body.get("device", {})
        if isinstance(device, dict) and device.get("hostname"):
            hostname = str(device["hostname"]).strip()
            entities.append(
                Entity(
                    entity_id=f"ent:host:{hostname.lower()}",
                    entity_type=EntityType.HOST.value,
                    value=hostname,
                    normalized_value=hostname.lower(),
                    role="system",
                    attributes=device,
                    confidence=0.95,
                )
            )

        # 5. Cloud Resource (from unmapped / cloud audit)
        cloud_res = (
            unmapped.get("resourceId")
            or unmapped.get("recipientAccountId")
            or unmapped.get("awsRegion")
        )
        if cloud_res:
            entities.append(
                Entity(
                    entity_id=f"ent:cloud_res:{str(cloud_res)[:64]}",
                    entity_type=EntityType.CLOUD_RESOURCE.value,
                    value=str(cloud_res),
                    normalized_value=str(cloud_res).strip().lower(),
                    role="target_resource",
                    confidence=0.90,
                )
            )

        return entities

    @staticmethod
    def _normalize_ip(ip_str: str) -> str | None:
        """Validate and canonically format IPv4/IPv6 addresses."""
        try:
            addr = ipaddress.ip_address(ip_str)
            return str(addr)
        except ValueError:
            return None
