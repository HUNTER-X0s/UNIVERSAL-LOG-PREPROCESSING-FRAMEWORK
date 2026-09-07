"""Authorization policy engine and role-to-permission definitions for ULPF Phase 7.

Enforces:
- Rule 6: Least privilege evaluation
- Rule 7: Strict role-permission matrix
- Rule 8: Horizontal cross-source/tenant isolation
- Rule 16: No anonymous administrative access
"""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Permission(StrEnum):
    """Fine-grained operational and governance permissions."""

    EVENT_READ = "event.read"
    EVENT_SEARCH = "event.search"
    EVENT_INGEST = "event.ingest"
    RAW_READ = "raw.read"
    UCE_READ = "uce.read"
    SEMANTIC_READ = "semantic.read"
    DLQ_READ = "dlq.read"
    DLQ_REPLAY = "dlq.replay"
    REPLAY_EXECUTE = "replay.execute"
    MAPPING_READ = "mapping.read"
    MAPPING_APPROVE = "mapping.approve"
    MAPPING_ACTIVATE = "mapping.activate"
    MAPPING_ROLLBACK = "mapping.rollback"
    CONFIG_READ = "config.read"
    CONFIG_MODIFY = "config.modify"
    RETENTION_MODIFY = "retention.modify"
    ADMIN_MANAGE = "admin.manage"
    INTELLIGENCE_READ = "intelligence.read"
    INTELLIGENCE_HUNT = "intelligence.hunt"
    INTELLIGENCE_INVESTIGATE = "intelligence.investigate"
    DETECTION_MANAGE = "detection.manage"
    RULE_REVIEW = "rule.review"
    RULE_ACTIVATE = "rule.activate"
    CASE_WRITE = "case.write"


@dataclass(frozen=True)
class IdentityContext:
    """Authenticated identity payload containing verified claims."""

    subject: str
    issuer: str
    roles: set[str] = field(default_factory=set)
    permissions: set[str] = field(default_factory=set)
    tenant_id: str | None = None
    auth_method: str = "unknown"
    attributes: dict[str, Any] = field(default_factory=dict)


# Default Role -> Permissions Matrix
ROLE_PERMISSIONS_MATRIX: dict[str, set[Permission]] = {
    "viewer": {
        Permission.EVENT_READ,
        Permission.EVENT_SEARCH,
        Permission.RAW_READ,
        Permission.UCE_READ,
        Permission.SEMANTIC_READ,
        Permission.MAPPING_READ,
        Permission.INTELLIGENCE_READ,
    },
    "operator": {
        Permission.EVENT_READ,
        Permission.EVENT_SEARCH,
        Permission.RAW_READ,
        Permission.UCE_READ,
        Permission.SEMANTIC_READ,
        Permission.DLQ_READ,
        Permission.DLQ_REPLAY,
        Permission.REPLAY_EXECUTE,
        Permission.MAPPING_READ,
        Permission.INTELLIGENCE_READ,
        Permission.INTELLIGENCE_INVESTIGATE,
    },
    "analyst": {
        Permission.EVENT_READ,
        Permission.EVENT_SEARCH,
        Permission.RAW_READ,
        Permission.UCE_READ,
        Permission.SEMANTIC_READ,
        Permission.INTELLIGENCE_READ,
        Permission.INTELLIGENCE_HUNT,
        Permission.INTELLIGENCE_INVESTIGATE,
        Permission.CASE_WRITE,
    },
    "threat-hunter": {
        Permission.EVENT_READ,
        Permission.EVENT_SEARCH,
        Permission.RAW_READ,
        Permission.UCE_READ,
        Permission.SEMANTIC_READ,
        Permission.INTELLIGENCE_READ,
        Permission.INTELLIGENCE_HUNT,
        Permission.INTELLIGENCE_INVESTIGATE,
        Permission.RULE_REVIEW,
        Permission.CASE_WRITE,
    },
    "detection-engineer": {
        Permission.EVENT_READ,
        Permission.EVENT_SEARCH,
        Permission.INTELLIGENCE_READ,
        Permission.INTELLIGENCE_HUNT,
        Permission.DETECTION_MANAGE,
        Permission.RULE_REVIEW,
        Permission.RULE_ACTIVATE,
    },
    "ingest-service": {
        Permission.EVENT_INGEST,
    },
    "mapping-reviewer": {
        Permission.MAPPING_READ,
        Permission.MAPPING_APPROVE,
    },
    "mapping-admin": {
        Permission.MAPPING_READ,
        Permission.MAPPING_APPROVE,
        Permission.MAPPING_ACTIVATE,
        Permission.MAPPING_ROLLBACK,
    },
    "platform-admin": {
        # Full operational authority
        Permission.EVENT_READ,
        Permission.EVENT_SEARCH,
        Permission.EVENT_INGEST,
        Permission.RAW_READ,
        Permission.UCE_READ,
        Permission.SEMANTIC_READ,
        Permission.DLQ_READ,
        Permission.DLQ_REPLAY,
        Permission.REPLAY_EXECUTE,
        Permission.MAPPING_READ,
        Permission.MAPPING_APPROVE,
        Permission.MAPPING_ACTIVATE,
        Permission.MAPPING_ROLLBACK,
        Permission.CONFIG_READ,
        Permission.CONFIG_MODIFY,
        Permission.RETENTION_MODIFY,
        Permission.ADMIN_MANAGE,
        Permission.INTELLIGENCE_READ,
        Permission.INTELLIGENCE_HUNT,
        Permission.INTELLIGENCE_INVESTIGATE,
        Permission.DETECTION_MANAGE,
        Permission.RULE_REVIEW,
        Permission.RULE_ACTIVATE,
        Permission.CASE_WRITE,
    },
}


class PolicyEngine:
    """Evaluates fine-grained authorization policies and tenant isolation boundaries."""

    def __init__(
        self,
        custom_role_matrix: dict[str, set[Permission]] | None = None,
    ) -> None:
        self._matrix = custom_role_matrix or ROLE_PERMISSIONS_MATRIX

    def get_effective_permissions(self, identity: IdentityContext) -> set[str]:
        """Calculates all effective permissions granted by explicit claims and roles."""
        perms = set(identity.permissions)
        for role in identity.roles:
            if role in self._matrix:
                perms.update(p.value for p in self._matrix[role])
        return perms

    def is_authorized(
        self,
        identity: IdentityContext,
        required_permission: Permission,
        resource_tenant: str | None = None,
    ) -> bool:
        """Determines if the identity has the required permission and matches resource tenancy.

        Enforces:
        - Permission presence
        - Horizontal tenant isolation: if caller has a specific tenant_id, they cannot access
          resources belonging to a different tenant unless they have platform-admin role.
        """
        # Horizontal tenant boundary check
        if identity.tenant_id is not None and resource_tenant is not None:
            if identity.tenant_id != resource_tenant and "platform-admin" not in identity.roles:
                return False

        effective = self.get_effective_permissions(identity)
        return required_permission.value in effective

    def has_permission(
        self,
        identity: IdentityContext,
        permission: Permission,
        resource_tenant: str | None = None,
    ) -> bool:
        """Alias for is_authorized with a simpler parameter name."""
        return self.is_authorized(identity, permission, resource_tenant)
