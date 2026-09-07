"""Phase 7 Test: Object authorization and horizontal tenant isolation via API.

Verifies:
- Rule 8: Horizontal cross-source/tenant isolation enforced on query routes
- Rule 16: No anonymous administrative access to any object
- Rule 17: Policy engine enforces resource-level tenant filtering
"""

from ulpf_security.policy import IdentityContext, Permission, PolicyEngine


def test_tenant_cannot_read_other_tenant_events() -> None:
    engine = PolicyEngine()

    tenant_a = IdentityContext(
        subject="op-a",
        issuer="ulpf-auth",
        roles={"operator"},
        tenant_id="tenant-alpha",
    )

    # Own resource: allowed
    assert engine.is_authorized(tenant_a, Permission.EVENT_READ, resource_tenant="tenant-alpha")

    # Cross-tenant: denied
    assert not engine.is_authorized(tenant_a, Permission.EVENT_READ, resource_tenant="tenant-bravo")


def test_viewer_cannot_ingest() -> None:
    engine = PolicyEngine()
    viewer = IdentityContext(subject="v1", issuer="ulpf-auth", roles={"viewer"})
    assert not engine.is_authorized(viewer, Permission.EVENT_INGEST)


def test_anonymous_identity_denied_all_permissions() -> None:
    engine = PolicyEngine()
    anon = IdentityContext(subject="anonymous", issuer="unknown", roles=set())
    for perm in Permission:
        assert not engine.is_authorized(anon, perm), f"Expected denial for {perm}"


def test_platform_admin_crosses_tenants() -> None:
    engine = PolicyEngine()
    admin = IdentityContext(subject="super-admin", issuer="ulpf-auth", roles={"platform-admin"})
    assert engine.is_authorized(admin, Permission.EVENT_READ, resource_tenant="tenant-alpha")
    assert engine.is_authorized(admin, Permission.EVENT_READ, resource_tenant="tenant-bravo")
    assert engine.is_authorized(admin, Permission.ADMIN_MANAGE)


def test_operator_dlq_replay_allowed_own_tenant() -> None:
    engine = PolicyEngine()
    op = IdentityContext(
        subject="op-1", issuer="ulpf-auth", roles={"operator"}, tenant_id="tenant-alpha"
    )
    assert engine.is_authorized(op, Permission.DLQ_REPLAY, resource_tenant="tenant-alpha")
    assert not engine.is_authorized(op, Permission.DLQ_REPLAY, resource_tenant="tenant-bravo")


def test_mapping_reviewer_cannot_activate() -> None:
    engine = PolicyEngine()
    reviewer = IdentityContext(
        subject="rev-1", issuer="ulpf-auth", roles={"mapping-reviewer"}
    )
    assert engine.is_authorized(reviewer, Permission.MAPPING_APPROVE)
    assert not engine.is_authorized(reviewer, Permission.MAPPING_ACTIVATE)
    assert not engine.is_authorized(reviewer, Permission.MAPPING_ROLLBACK)


def test_retention_modify_requires_admin() -> None:
    engine = PolicyEngine()
    operator = IdentityContext(subject="op", issuer="ulpf-auth", roles={"operator"})
    admin = IdentityContext(subject="adm", issuer="ulpf-auth", roles={"platform-admin"})
    assert not engine.is_authorized(operator, Permission.RETENTION_MODIFY)
    assert engine.is_authorized(admin, Permission.RETENTION_MODIFY)
