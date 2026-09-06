"""Deterministic Entity Extraction and Normalization for ULPF Phase 4 & Phase 5.

Extracts normalized entities (IP, Host, User, Device, Process, File, Domain,
URL, Container, Database, Service, Cloud Resource) preserving both original
values and normalized representations with bounded complexity.
"""

import ipaddress
from typing import Any

from ulpf_semantic.models import Entity, EntityType

MAX_ENTITIES_PER_EVENT = 50


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
        src_ip = None
        if isinstance(src, dict) and src.get("ip"):
            src_ip = str(src["ip"]).strip()
        elif event_body.get("src_ip"):
            src_ip = str(event_body["src_ip"]).strip()
        elif event_body.get("source_ip"):
            src_ip = str(event_body["source_ip"]).strip()

        if src_ip:
            norm_ip = EntityExtractor._normalize_ip(src_ip)
            src_attr = (
                {"port": src.get("port")} if isinstance(src, dict) and src.get("port") else {}
            )
            entities.append(
                Entity(
                    entity_id=f"ent:ip:{norm_ip or src_ip}",
                    entity_type=EntityType.IP.value,
                    value=src_ip,
                    normalized_value=norm_ip,
                    role="source",
                    attributes=src_attr,
                    confidence=1.0 if norm_ip else 0.8,
                )
            )

        # 2. Destination IP
        dst = event_body.get("destination", {})
        dst_ip = None
        if isinstance(dst, dict) and dst.get("ip"):
            dst_ip = str(dst["ip"]).strip()
        elif event_body.get("dst_ip"):
            dst_ip = str(event_body["dst_ip"]).strip()
        elif event_body.get("dest_ip"):
            dst_ip = str(event_body["dest_ip"]).strip()

        if dst_ip:
            norm_ip = EntityExtractor._normalize_ip(dst_ip)
            dst_attr = (
                {"port": dst.get("port")} if isinstance(dst, dict) and dst.get("port") else {}
            )
            entities.append(
                Entity(
                    entity_id=f"ent:ip:{norm_ip or dst_ip}",
                    entity_type=EntityType.IP.value,
                    value=dst_ip,
                    normalized_value=norm_ip,
                    role="destination",
                    attributes=dst_attr,
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

        # 6. Process Entity (Phase 5 Expansion)
        proc_val = (
            unmapped.get("process")
            or unmapped.get("process_name")
            or unmapped.get("image")
            or unmapped.get("exe")
            or event_body.get("process_name")
            or event_body.get("process")
        )
        if proc_val:
            p_str = str(proc_val).strip()
            entities.append(
                Entity(
                    entity_id=f"ent:process:{p_str.lower()[:64]}",
                    entity_type=EntityType.PROCESS.value,
                    value=p_str,
                    normalized_value=p_str.lower(),
                    role="process",
                    confidence=0.90,
                )
            )

        # 7. File Entity (Phase 5 Expansion)
        file_val = (
            unmapped.get("file_name")
            or unmapped.get("filename")
            or unmapped.get("filepath")
            or event_body.get("file_name")
            or event_body.get("filename")
        )
        if file_val:
            f_str = str(file_val).strip()
            entities.append(
                Entity(
                    entity_id=f"ent:file:{f_str.lower()[:64]}",
                    entity_type=EntityType.FILE.value,
                    value=f_str,
                    normalized_value=f_str.lower(),
                    role="file",
                    confidence=0.90,
                )
            )

        # 8. Domain Entity (Phase 5 Expansion)
        domain_val = (
            unmapped.get("domain")
            or unmapped.get("query")
            or event_body.get("domain")
            or event_body.get("query")
        )
        if domain_val and "." in str(domain_val):
            d_str = str(domain_val).strip().lower()
            entities.append(
                Entity(
                    entity_id=f"ent:domain:{d_str[:64]}",
                    entity_type=EntityType.DOMAIN.value,
                    value=d_str,
                    normalized_value=d_str,
                    role="target_domain",
                    confidence=0.90,
                )
            )

        # 9. URL Entity (Phase 5 Expansion)
        url_val = (
            unmapped.get("url")
            or unmapped.get("uri")
            or unmapped.get("target_url")
            or event_body.get("target_url")
            or event_body.get("url")
            or event_body.get("uri")
        )
        if url_val and ("http://" in str(url_val) or "https://" in str(url_val)):
            u_str = str(url_val).strip()
            entities.append(
                Entity(
                    entity_id=f"ent:url:{u_str[:64]}",
                    entity_type=EntityType.URL.value,
                    value=u_str,
                    normalized_value=u_str,
                    role="url",
                    confidence=0.90,
                )
            )

        # 10. Container Entity (Phase 5 Expansion)
        cont_val = unmapped.get("container_id") or unmapped.get("container_name")
        if cont_val:
            c_str = str(cont_val).strip()
            entities.append(
                Entity(
                    entity_id=f"ent:container:{c_str[:64]}",
                    entity_type=EntityType.CONTAINER.value,
                    value=c_str,
                    normalized_value=c_str.lower(),
                    role="container",
                    confidence=0.90,
                )
            )

        # Bound total entities to prevent graph explosion
        return entities[:MAX_ENTITIES_PER_EVENT]

    @staticmethod
    def _normalize_ip(ip_str: str) -> str | None:
        """Validate and canonically format IPv4/IPv6 addresses."""
        try:
            addr = ipaddress.ip_address(ip_str)
            return str(addr)
        except ValueError:
            return None
