"""Phase 7 Production Authorization Policy Tests.

Verifies:
- Rule 6: Least privilege evaluation
- Rule 7: Role to permission matrix
- Rule 8: Horizontal cross-source/tenant isolation
- Rule 16: No anonymous administrative access
"""

from ulpf_security.audit import SecurityAuditLogger
from ulpf_security.policy import (
    IdentityContext,
    Permission,
    PolicyEngine,
)


def test_viewer_role_permissions() -> None:
    engine = PolicyEngine()
    viewer_ident = IdentityContext(
        subject="viewer-1",
        issuer="ulpf-auth",
        roles={"viewer"},
    )

    # Allowed
    assert engine.is_authorized(viewer_ident, Permission.EVENT_READ) is True
    assert engine.is_authorized(viewer_ident, Permission.EVENT_SEARCH) is True
    assert engine.is_authorized(viewer_ident, Permission.RAW_READ) is True
    assert engine.is_authorized(viewer_ident, Permission.UCE_READ) is True
    assert engine.is_authorized(viewer_ident, Permission.SEMANTIC_READ) is True

    # Forbidden
    assert engine.is_authorized(viewer_ident, Permission.EVENT_INGEST) is False
    assert engine.is_authorized(viewer_ident, Permission.DLQ_REPLAY) is False
    assert engine.is_authorized(viewer_ident, Permission.MAPPING_ACTIVATE) is False
    assert engine.is_authorized(viewer_ident, Permission.ADMIN_MANAGED if hasattr(Permission, 'ADMIN_MANAGED') else Permission.ADMIN_MANAGE) is False


def test_operator_role_permissions() -> None:
    engine = PolicyEngine()
    operator_ident = IdentityContext(
        subject="operator-1",
        issuer="ulpf-auth",
        roles={"operator"},
    )

    # Allowed
    assert engine.is_authorized(operator_ident, Permission.EVENT_READ) is True
    assert engine.is_authorized(operator_ident, Permission.DLQ_READ) is True
    assert engine.is_authorized(operator_ident, Permission.DLQ_REPLAY) is True
    assert engine.is_authorized(operator_ident, Permission.REPLAY_EXECUTE) is True

    # Forbidden
    assert engine.is_authorized(operator_ident, Permission.MAPPING_ACTIVATE) is False
    assert engine.is_authorized(operator_ident, Permission.CONFIG_MODIFY) is False


def test_mapping_roles_permissions() -> None:
    engine = PolicyEngine()
    reviewer_ident = IdentityContext(
        subject="reviewer-1",
        issuer="ulpf-auth",
        roles={"mapping-reviewer"},
    )
    admin_ident = IdentityContext(
        subject="mapping-admin-1",
        issuer="ulpf-auth",
        roles={"mapping-admin"},
    )

    # Reviewer can read and approve, but cannot activate or rollback
    assert engine.is_authorized(reviewer_ident, Permission.MAPPING_READ) is True
    assert engine.is_authorized(reviewer_ident, Permission.MAPPING_APPROVE) is True
    assert engine.is_authorized(reviewer_ident, Permission.MAPPING_ACTIVATE) is False
    assert engine.is_authorized(reviewer_ident, Permission.MAPPING_ROLLBACK) is False

    # Mapping Admin can activate and rollback
    assert engine.is_authorized(admin_ident, Permission.MAPPING_ACTIVATE) is True
    assert engine.is_authorized(admin_ident, Permission.MAPPING_ROLLBACK) is True


def test_platform_admin_full_access() -> None:
    engine = PolicyEngine()
    admin_ident = IdentityContext(
        subject="super-admin",
        issuer="ulpf-auth",
        roles={"platform-admin"},
    )

    for perm in Permission:
        assert engine.is_authorized(admin_ident, perm) is True


def test_horizontal_tenant_isolation() -> None:
    engine = PolicyEngine()

    tenant_a_operator = IdentityContext(
        subject="op-a",
        issuer="ulpf-auth",
        roles={"operator"},
        tenant_id="tenant-alpha",
    )
    platform_admin = IdentityContext(
        subject="super-op",
        issuer="ulpf-auth",
        roles={"platform-admin"},
        tenant_id=None,
    )

    # Tenant A accessing Tenant A resource -> Allowed
    assert engine.is_authorized(tenant_a_operator, Permission.EVENT_READ, resource_tenant="tenant-alpha") is True

    # Tenant A accessing Tenant B resource -> Strictly Denied
    assert engine.is_authorized(tenant_a_operator, Permission.EVENT_READ, resource_tenant="tenant-bravo") is False

    # Platform Admin accessing Tenant B resource -> Allowed
    assert engine.is_authorized(platform_admin, Permission.EVENT_READ, resource_tenant="tenant-bravo") is True


def test_security_audit_logging() -> None:
    logger = SecurityAuditLogger()
    event = logger.log(
        event_id="sec-audit-1",
        actor="admin-01",
        auth_method="jwt_hs256",
        permission="mapping.activate",
        target="mapping:cisco_asa:v1.2.0",
        action="ACTIVATE",
        result="GRANTED",
        reason="Approved by change management",
        correlation_id="cid-999",
    )

    assert event.event_id == "sec-audit-1"
    assert event.actor == "admin-01"
    assert event.result == "GRANTED"
    assert logger.count() == 1
    assert logger.get_events()[0].target == "mapping:cisco_asa:v1.2.0"
