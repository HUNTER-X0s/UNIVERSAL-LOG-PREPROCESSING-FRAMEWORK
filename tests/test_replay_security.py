"""Phase 7 Test: Replay Security Controls.

Verifies:
- Rule 16: Unauthorized replay attempts are rejected with 403
- Rule 8: Replay permission scoped to tenant (tenant isolation)
- Rule 7: Only operator/platform-admin can execute replay
"""

import pytest
from ulpf_security.policy import IdentityContext, Permission, PolicyEngine


@pytest.fixture()
def engine() -> PolicyEngine:
    return PolicyEngine()


def test_viewer_cannot_replay(engine: PolicyEngine) -> None:
    viewer = IdentityContext(subject="v1", issuer="ulpf-auth", roles={"viewer"})
    assert not engine.is_authorized(viewer, Permission.REPLAY_EXECUTE)


def test_operator_can_replay_own_tenant(engine: PolicyEngine) -> None:
    op = IdentityContext(
        subject="op-1", issuer="ulpf-auth", roles={"operator"}, tenant_id="tenant-A"
    )
    assert engine.is_authorized(op, Permission.REPLAY_EXECUTE, resource_tenant="tenant-A")


def test_operator_cannot_replay_other_tenant(engine: PolicyEngine) -> None:
    op = IdentityContext(
        subject="op-1", issuer="ulpf-auth", roles={"operator"}, tenant_id="tenant-A"
    )
    assert not engine.is_authorized(op, Permission.REPLAY_EXECUTE, resource_tenant="tenant-B")


def test_platform_admin_can_replay_any_tenant(engine: PolicyEngine) -> None:
    admin = IdentityContext(subject="sa", issuer="ulpf-auth", roles={"platform-admin"})
    assert engine.is_authorized(admin, Permission.REPLAY_EXECUTE, resource_tenant="any-tenant")


def test_anonymous_cannot_replay(engine: PolicyEngine) -> None:
    anon = IdentityContext(subject="anon", issuer="unknown", roles=set())
    assert not engine.is_authorized(anon, Permission.REPLAY_EXECUTE)


def test_mapping_reviewer_cannot_replay(engine: PolicyEngine) -> None:
    reviewer = IdentityContext(
        subject="rev-1", issuer="ulpf-auth", roles={"mapping-reviewer"}
    )
    assert not engine.is_authorized(reviewer, Permission.REPLAY_EXECUTE)


def test_dlq_replay_requires_operator_or_admin(engine: PolicyEngine) -> None:
    viewer = IdentityContext(subject="v", issuer="ulpf-auth", roles={"viewer"})
    operator = IdentityContext(subject="o", issuer="ulpf-auth", roles={"operator"})
    admin = IdentityContext(subject="a", issuer="ulpf-auth", roles={"platform-admin"})

    assert not engine.is_authorized(viewer, Permission.DLQ_REPLAY)
    assert engine.is_authorized(operator, Permission.DLQ_REPLAY)
    assert engine.is_authorized(admin, Permission.DLQ_REPLAY)
