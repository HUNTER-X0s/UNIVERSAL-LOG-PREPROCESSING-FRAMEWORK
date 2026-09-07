"""Phase 7 Test: Query Authorization Controls.

Verifies:
- Rule 6/7: Query permissions are enforced per role
- Rule 8: Queries are tenant-isolated
- Rule 16: Anonymous/no-auth queries are rejected
"""

import pytest
from ulpf_security.policy import IdentityContext, Permission, PolicyEngine


@pytest.fixture()
def engine() -> PolicyEngine:
    return PolicyEngine()


def test_viewer_can_search_events(engine: PolicyEngine) -> None:
    viewer = IdentityContext(subject="v1", issuer="ulpf-auth", roles={"viewer"})
    assert engine.is_authorized(viewer, Permission.EVENT_SEARCH)


def test_viewer_can_read_uce(engine: PolicyEngine) -> None:
    viewer = IdentityContext(subject="v1", issuer="ulpf-auth", roles={"viewer"})
    assert engine.is_authorized(viewer, Permission.UCE_READ)


def test_viewer_can_read_semantic(engine: PolicyEngine) -> None:
    viewer = IdentityContext(subject="v1", issuer="ulpf-auth", roles={"viewer"})
    assert engine.is_authorized(viewer, Permission.SEMANTIC_READ)


def test_viewer_cannot_read_mapping_details(engine: PolicyEngine) -> None:
    viewer = IdentityContext(subject="v1", issuer="ulpf-auth", roles={"viewer"})
    # Viewers can read mappings (read-only)
    assert engine.is_authorized(viewer, Permission.MAPPING_READ)
    # But cannot approve or activate
    assert not engine.is_authorized(viewer, Permission.MAPPING_APPROVE)
    assert not engine.is_authorized(viewer, Permission.MAPPING_ACTIVATE)


def test_query_tenant_isolation_for_viewer(engine: PolicyEngine) -> None:
    viewer = IdentityContext(
        subject="v1", issuer="ulpf-auth", roles={"viewer"}, tenant_id="tenant-A"
    )
    # Own tenant: allowed
    assert engine.is_authorized(viewer, Permission.EVENT_SEARCH, resource_tenant="tenant-A")
    # Foreign tenant: denied
    assert not engine.is_authorized(viewer, Permission.EVENT_SEARCH, resource_tenant="tenant-B")


def test_anonymous_cannot_query(engine: PolicyEngine) -> None:
    anon = IdentityContext(subject="anon", issuer="unknown", roles=set())
    assert not engine.is_authorized(anon, Permission.EVENT_SEARCH)
    assert not engine.is_authorized(anon, Permission.UCE_READ)
    assert not engine.is_authorized(anon, Permission.SEMANTIC_READ)


def test_operator_can_query_all_read_permissions(engine: PolicyEngine) -> None:
    operator = IdentityContext(
        subject="op-1", issuer="ulpf-auth", roles={"operator"}, tenant_id="tenant-A"
    )
    for perm in [
        Permission.EVENT_READ,
        Permission.EVENT_SEARCH,
        Permission.UCE_READ,
        Permission.SEMANTIC_READ,
        Permission.RAW_READ,
        Permission.DLQ_READ,
        Permission.MAPPING_READ,
    ]:
        assert engine.is_authorized(operator, perm, resource_tenant="tenant-A"), \
            f"Operator should have {perm} on own tenant"


def test_config_read_requires_admin(engine: PolicyEngine) -> None:
    operator = IdentityContext(subject="op", issuer="ulpf-auth", roles={"operator"})
    admin = IdentityContext(subject="adm", issuer="ulpf-auth", roles={"platform-admin"})
    assert not engine.is_authorized(operator, Permission.CONFIG_READ)
    assert engine.is_authorized(admin, Permission.CONFIG_READ)
