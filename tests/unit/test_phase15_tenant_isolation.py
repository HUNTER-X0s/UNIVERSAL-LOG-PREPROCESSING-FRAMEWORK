"""Phase 15 Negative Unit Tests for Milestone E: Tenant Isolation."""

import pytest
from ulpf_security.policy import IdentityContext, Permission, PolicyEngine
from ulpf_security.tenant_isolation import (
    MultiTenantGuard,
    TenantIsolationError,
    TenantViolationType,
)


@pytest.fixture
def tenant_guard() -> MultiTenantGuard:
    return MultiTenantGuard()


@pytest.fixture
def tenant_a_analyst() -> IdentityContext:
    return IdentityContext(
        subject="analyst_alice",
        issuer="ulpf-idp",
        roles={"analyst"},
        tenant_id="tenant-alpha",
    )


@pytest.fixture
def tenant_b_analyst() -> IdentityContext:
    return IdentityContext(
        subject="analyst_bob",
        issuer="ulpf-idp",
        roles={"analyst"},
        tenant_id="tenant-bravo",
    )


def test_tenant_a_cannot_access_tenant_b_raw_evidence(tenant_guard, tenant_a_analyst):
    """Negative test: Tenant A cannot read Tenant B raw evidence."""
    with pytest.raises(TenantIsolationError) as exc_info:
        tenant_guard.enforce_tenant_boundary(
            identity=tenant_a_analyst,
            resource_tenant="tenant-bravo",
            violation_type=TenantViolationType.RAW_EVIDENCE_ACCESS,
            required_permission=Permission.RAW_READ,
        )
    err = exc_info.value
    assert err.violation_type == TenantViolationType.RAW_EVIDENCE_ACCESS
    assert err.requestor_tenant == "tenant-alpha"
    assert err.resource_tenant == "tenant-bravo"


def test_tenant_a_cannot_access_tenant_b_uce(tenant_guard, tenant_a_analyst):
    """Negative test: Tenant A cannot read Tenant B UCE records."""
    with pytest.raises(TenantIsolationError) as exc_info:
        tenant_guard.enforce_tenant_boundary(
            identity=tenant_a_analyst,
            resource_tenant="tenant-bravo",
            violation_type=TenantViolationType.UCE_ACCESS,
            required_permission=Permission.UCE_READ,
        )
    assert exc_info.value.violation_type == TenantViolationType.UCE_ACCESS


def test_tenant_a_cannot_access_tenant_b_alerts(tenant_guard, tenant_a_analyst):
    """Negative test: Tenant A cannot query Tenant B alerts."""
    with pytest.raises(TenantIsolationError) as exc_info:
        tenant_guard.enforce_tenant_boundary(
            identity=tenant_a_analyst,
            resource_tenant="tenant-bravo",
            violation_type=TenantViolationType.ALERT_ACCESS,
            required_permission=Permission.EVENT_READ,
        )
    assert exc_info.value.violation_type == TenantViolationType.ALERT_ACCESS


def test_tenant_a_cannot_access_tenant_b_cases(tenant_guard, tenant_a_analyst):
    """Negative test: Tenant A cannot modify or write Tenant B cases."""
    with pytest.raises(TenantIsolationError) as exc_info:
        tenant_guard.enforce_tenant_boundary(
            identity=tenant_a_analyst,
            resource_tenant="tenant-bravo",
            violation_type=TenantViolationType.CASE_ACCESS,
            required_permission=Permission.CASE_WRITE,
        )
    assert exc_info.value.violation_type == TenantViolationType.CASE_ACCESS


def test_tenant_a_cannot_access_tenant_b_mappings(tenant_guard):
    """Negative test: Tenant A mapping-admin cannot modify Tenant B mappings."""
    tenant_a_mapping_admin = IdentityContext(
        subject="admin_a",
        issuer="ulpf-idp",
        roles={"mapping-admin"},
        tenant_id="tenant-alpha",
    )
    with pytest.raises(TenantIsolationError) as exc_info:
        tenant_guard.enforce_tenant_boundary(
            identity=tenant_a_mapping_admin,
            resource_tenant="tenant-bravo",
            violation_type=TenantViolationType.MAPPING_ACCESS,
            required_permission=Permission.MAPPING_APPROVE,
        )
    assert exc_info.value.violation_type == TenantViolationType.MAPPING_ACCESS


def test_tenant_a_cannot_access_tenant_b_investigations(tenant_guard, tenant_a_analyst):
    """Negative test: Tenant A cannot pivot or investigate Tenant B entity records."""
    with pytest.raises(TenantIsolationError) as exc_info:
        tenant_guard.enforce_tenant_boundary(
            identity=tenant_a_analyst,
            resource_tenant="tenant-bravo",
            violation_type=TenantViolationType.INVESTIGATION_ACCESS,
            required_permission=Permission.INTELLIGENCE_INVESTIGATE,
        )
    assert exc_info.value.violation_type == TenantViolationType.INVESTIGATION_ACCESS


def test_tenant_a_ai_context_filtering(tenant_guard, tenant_a_analyst):
    """Negative test: AI context does not leak Tenant B entities to Tenant A."""
    mixed_entities = [
        {"entity_id": "host-alpha-1", "tenant_id": "tenant-alpha", "ip": "10.1.0.5"},
        {"entity_id": "host-bravo-secret", "tenant_id": "tenant-bravo", "ip": "10.2.0.99"},
        {"entity_id": "db-bravo", "tenant_id": "tenant-bravo", "ip": "10.2.0.100"},
    ]
    redacted = tenant_guard.redact_tenant_ai_context(tenant_a_analyst, mixed_entities)
    assert len(redacted) == 1
    assert redacted[0]["entity_id"] == "host-alpha-1"
    assert not any(e.get("tenant_id") == "tenant-bravo" for e in redacted)


def test_authorized_same_tenant_access_succeeds(tenant_guard, tenant_a_analyst):
    """Positive test: Tenant A analyst successfully accesses Tenant A resources."""
    assert tenant_guard.enforce_tenant_boundary(
        identity=tenant_a_analyst,
        resource_tenant="tenant-alpha",
        violation_type=TenantViolationType.RAW_EVIDENCE_ACCESS,
        required_permission=Permission.RAW_READ,
    ) is True
