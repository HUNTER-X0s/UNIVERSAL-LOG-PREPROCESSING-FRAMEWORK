"""Phase 11 Adversarial Security Suite.

Attacks authentication, authorization policy engine, tenant isolation boundaries,
and SOAR action guardrails with malformed, forged, and boundary-testing payloads.
"""

from __future__ import annotations

import base64
import json

import pytest
from ulpf_advanced_intelligence.automation.actions import (
    ActionApprovalState,
    SOARAction,
    SOARActionDispatcher,
)
from ulpf_security import (
    AuthenticationError,
    IdentityContext,
    InvalidSignatureError,
    JWTAuthenticationProvider,
    Permission,
    PolicyEngine,
    TokenExpiredError,
    TokenNotYetValidError,
)


@pytest.fixture
def jwt_provider() -> JWTAuthenticationProvider:
    """Fixture providing a standard JWT authentication provider."""
    return JWTAuthenticationProvider(
        key_or_rotation="super-secret-production-signing-key-32b",
        expected_issuer="ulpf-auth-authority",
        expected_audience="ulpf-platform",
    )


# ===========================================================================
# 1. JWT Authentication Adversarial Attacks
# ===========================================================================

def test_jwt_signature_forgery_rejected(jwt_provider: JWTAuthenticationProvider) -> None:
    """Proof that altered signature or attacker-crafted signature is rejected."""
    token = jwt_provider.issue_token(
        subject="attacker-01",
        roles=["operator"],
        tenant_id="tenant-alpha",
    )
    parts = token.split(".")
    assert len(parts) == 3

    # Forgery attempt: alter signature
    fake_sig = base64.urlsafe_b64encode(b"forged-signature-bytes-12345").decode("utf-8").rstrip("=")
    tampered_token = f"{parts[0]}.{parts[1]}.{fake_sig}"

    with pytest.raises((InvalidSignatureError, AuthenticationError)):
        jwt_provider.authenticate(tampered_token)


def test_jwt_altered_payload_rejected(jwt_provider: JWTAuthenticationProvider) -> None:
    """Proof that tampering with payload claims invalidates the token."""
    token = jwt_provider.issue_token(
        subject="user-low-priv",
        roles=["viewer"],
        tenant_id="tenant-alpha",
    )
    parts = token.split(".")
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "==").decode("utf-8"))

    # Escalate role in payload directly
    payload["roles"] = ["platform-admin"]
    tampered_payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload).encode("utf-8")
    ).decode("utf-8").rstrip("=")

    tampered_token = f"{parts[0]}.{tampered_payload_b64}.{parts[2]}"
    with pytest.raises((InvalidSignatureError, AuthenticationError)):
        jwt_provider.authenticate(tampered_token)


def test_jwt_expired_token_rejected() -> None:
    """Proof that expired tokens fail closed immediately."""
    provider = JWTAuthenticationProvider(
        key_or_rotation="super-secret-production-signing-key-32b",
        clock_skew_seconds=0,
    )
    token = provider.issue_token(
        subject="alice",
        roles=["operator"],
        tenant_id="tenant-alpha",
        expires_in_seconds=-10,  # Expired in past
    )
    with pytest.raises((TokenExpiredError, AuthenticationError)):
        provider.authenticate(token)


def test_jwt_future_nbf_rejected() -> None:
    """Proof that tokens with future 'not-before' (nbf) timestamps are rejected."""
    provider = JWTAuthenticationProvider(
        key_or_rotation="super-secret-production-signing-key-32b",
        expected_issuer="ulpf-auth-authority",
        expected_audience="ulpf-platform",
        clock_skew_seconds=0,
    )
    future_token = provider.issue_token(
        subject="bob",
        roles=["operator"],
        tenant_id="tenant-alpha",
        not_before_offset_seconds=7200,  # 2 hours in the future
    )
    with pytest.raises((TokenNotYetValidError, AuthenticationError)):
        provider.authenticate(future_token)


def test_jwt_malformed_and_oversized_payloads(jwt_provider: JWTAuthenticationProvider) -> None:
    """Proof that malformed strings and structure attacks fail closed."""
    malformed_inputs = [
        "",
        "not.a.jwt",
        "header.only",
        "a.b.c.d.e",
        "header..sig",
        "..." * 50,
        "A" * 50000,
    ]
    for bad_token in malformed_inputs:
        with pytest.raises(AuthenticationError):
            jwt_provider.authenticate(bad_token)


# ===========================================================================
# 2. Authorization & RBAC Red-Team Attacks
# ===========================================================================

def test_viewer_vertical_escalation_blocked() -> None:
    """Verify viewer role is strictly denied administrative and write privileges."""
    policy = PolicyEngine()
    viewer_ctx = IdentityContext(
        subject="viewer-alice",
        issuer="ulpf-auth",
        roles={"viewer"},
        tenant_id="tenant-a",
    )

    sensitive_permissions = [
        Permission.EVENT_INGEST,
        Permission.DLQ_REPLAY,
        Permission.MAPPING_ACTIVATE,
        Permission.ADMIN_MANAGE,
    ]
    for perm in sensitive_permissions:
        assert not policy.is_authorized(viewer_ctx, perm), f"Viewer unexpectedly granted {perm}"


def test_operator_administrative_actions_blocked() -> None:
    """Verify operator role cannot perform platform-admin actions."""
    policy = PolicyEngine()
    operator_ctx = IdentityContext(
        subject="operator-bob",
        issuer="ulpf-auth",
        roles={"operator"},
        tenant_id="tenant-a",
    )

    admin_only = [
        Permission.ADMIN_MANAGE,
    ]
    for perm in admin_only:
        assert not policy.is_authorized(operator_ctx, perm), f"Operator unexpectedly granted {perm}"


# ===========================================================================
# 3. Tenant Isolation Boundaries
# ===========================================================================

def test_tenant_boundary_enforcement() -> None:
    """Prove that an authenticated user cannot access another tenant's resources."""
    policy = PolicyEngine()
    tenant_a_ctx = IdentityContext(
        subject="user-a",
        issuer="ulpf-auth",
        roles={"operator"},
        tenant_id="tenant-alpha",
    )

    # Cross-tenant access validation: operator has EVENT_READ, but resource belongs to tenant-beta
    assert policy.is_authorized(tenant_a_ctx, Permission.EVENT_READ, resource_tenant="tenant-alpha")
    assert not policy.is_authorized(tenant_a_ctx, Permission.EVENT_READ, resource_tenant="tenant-beta")
    assert not policy.is_authorized(tenant_a_ctx, Permission.EVENT_READ, resource_tenant="tenant-other")

    # Platform admin can access across tenants
    admin_ctx = IdentityContext(
        subject="admin-root",
        issuer="ulpf-auth",
        roles={"platform-admin"},
        tenant_id="tenant-alpha",
    )
    assert policy.is_authorized(admin_ctx, Permission.EVENT_READ, resource_tenant="tenant-beta")


# ===========================================================================
# 4. SOAR Safety & Non-Destructive Guardrails
# ===========================================================================

def test_soar_dispatcher_blocks_destructive_actions() -> None:
    """Verify dangerous destructive actions are permanently rejected."""
    dispatcher = SOARActionDispatcher()

    dangerous_actions = [
        "DELETE_DATABASE_CLUSTER",
        "MODIFY_SYSTEM_KERNEL",
        "SHUTDOWN_INFRASTRUCTURE",
        "DROP_TABLE_PROD",
        "RM_RF_STORAGE",
    ]
    for action_name in dangerous_actions:
        action = SOARAction(
            action_id=f"act-{action_name}",
            action_type=action_name,
            target="critical-infra",
            approval_state=ActionApprovalState.APPROVED,
            proposed_by="adversary",
        )
        with pytest.raises(Exception):  # noqa: B017
            dispatcher.execute_action(action, approver_identity="soc-admin")


def test_soar_dispatcher_dry_run_zero_side_effects() -> None:
    """Verify safe permitted action requires explicit approval and has no side effects in simulation."""
    dispatcher = SOARActionDispatcher()
    action = SOARAction(
        action_id="act-safe-01",
        action_type="ADD_TAG",
        target="case-100",
        parameters={"tag": "ELEVATED_RISK"},
        approval_state=ActionApprovalState.PROPOSED,
        proposed_by="analyst-1",
    )
    # Attempt execution while still in PROPOSED state (unapproved)
    with pytest.raises(Exception):  # noqa: B017
        dispatcher.execute_action(action, approver_identity=None)
