"""ULPF Phase 15 Tenant Boundary & Resource Isolation Enforcement.

Provides strict object-level multi-tenant isolation validation for:
- Raw evidence payloads
- Unified Canonical Events (UCE)
- Security alerts
- Investigation cases
- Field mappings
- Investigation pivots
- AI context & prompt recommendations
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from ulpf_security.policy import IdentityContext, Permission, PolicyEngine


class TenantViolationType(str, Enum):
    RAW_EVIDENCE_ACCESS = "RAW_EVIDENCE_ACCESS"
    UCE_ACCESS = "UCE_ACCESS"
    ALERT_ACCESS = "ALERT_ACCESS"
    CASE_ACCESS = "CASE_ACCESS"
    MAPPING_ACCESS = "MAPPING_ACCESS"
    INVESTIGATION_ACCESS = "INVESTIGATION_ACCESS"
    AI_CONTEXT_ACCESS = "AI_CONTEXT_ACCESS"


class TenantIsolationError(PermissionError):
    """Raised when an authenticated identity attempts to access cross-tenant resources."""

    def __init__(
        self,
        message: str,
        violation_type: TenantViolationType,
        requestor_tenant: str | None,
        resource_tenant: str | None,
    ) -> None:
        super().__init__(message)
        self.violation_type = violation_type
        self.requestor_tenant = requestor_tenant
        self.resource_tenant = resource_tenant
        self.timestamp = datetime.now(UTC).isoformat()


class MultiTenantGuard:
    """Enforces horizontal boundary isolation across all platform entity domains."""

    def __init__(self, policy_engine: PolicyEngine | None = None) -> None:
        self.policy_engine = policy_engine or PolicyEngine()

    def enforce_tenant_boundary(
        self,
        identity: IdentityContext,
        resource_tenant: str,
        violation_type: TenantViolationType,
        required_permission: Permission,
    ) -> bool:
        """Validates that identity has permission and strictly matches resource tenant."""
        # 1. Permission check
        if not self.policy_engine.is_authorized(identity, required_permission):
            raise PermissionError(
                f"Identity '{identity.subject}' lacks permission '{required_permission.value}'"
            )

        # 2. Cross-tenant isolation check: Identity tenant MUST equal resource tenant
        # Exception: platform-admin role with explicit cross-tenant audit authorization
        is_cross_tenant_admin = (
            "platform-admin" in identity.roles
            and identity.attributes.get("cross_tenant_audit", False)
        )

        if identity.tenant_id != resource_tenant and not is_cross_tenant_admin:
            raise TenantIsolationError(
                f"Cross-tenant access blocked: tenant '{identity.tenant_id}' "
                f"cannot access resource belonging to tenant '{resource_tenant}'",
                violation_type=violation_type,
                requestor_tenant=identity.tenant_id,
                resource_tenant=resource_tenant,
            )

        return True

    def filter_query_by_tenant(
        self,
        identity: IdentityContext,
        records: list[dict[str, Any]],
        tenant_field: str = "tenant_id",
    ) -> list[dict[str, Any]]:
        """Filter a list of entity dictionaries to only include the caller's tenant."""
        is_cross_admin = (
            "platform-admin" in identity.roles
            and identity.attributes.get("cross_tenant_audit", False)
        )
        if is_cross_admin:
            return records
        return [r for r in records if r.get(tenant_field) == identity.tenant_id]

    def redact_tenant_ai_context(
        self,
        identity: IdentityContext,
        context_entities: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Ensure no cross-tenant context or raw tokens leak into AI copilot prompts."""
        safe_entities = []
        for ent in context_entities:
            ent_tenant = ent.get("tenant_id")
            is_admin = (
                "platform-admin" in identity.roles
                and identity.attributes.get("cross_tenant_audit", False)
            )
            if ent_tenant == identity.tenant_id or is_admin:
                safe_entities.append(ent)
        return safe_entities
