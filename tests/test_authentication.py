"""Phase 7 Production Authentication Tests.

Verifies:
- Rule 4: Pluggable production authentication boundary
- Rule 9: Authentication failure handling (expired, tampered, wrong issuer/aud)
- Rule 13: Key rotation support
- Rule 17: No client-controlled trust headers accepted without cryptographic verification
"""

import time

import pytest
from ulpf_security.auth import (
    JWTAuthenticationProvider,
    MTLSAuthenticationProvider,
    SignedProxyAuthenticationProvider,
)
from ulpf_security.errors import (
    AuthenticationError,
    InvalidSignatureError,
    TokenExpiredError,
    TokenNotYetValidError,
)
from ulpf_security.secrets import KeyRotationManager


def test_jwt_valid_authentication() -> None:
    provider = JWTAuthenticationProvider(key_or_rotation="super-secret-production-key-256")
    token = provider.issue_token(
        subject="sec-analyst-01",
        roles=["operator"],
        tenant_id="tenant-alpha",
        expires_in_seconds=300,
    )

    identity = provider.authenticate(token)
    assert identity.subject == "sec-analyst-01"
    assert "operator" in identity.roles
    assert identity.tenant_id == "tenant-alpha"
    assert identity.auth_method == "jwt_hs256"


def test_jwt_expired_token() -> None:
    provider = JWTAuthenticationProvider(
        key_or_rotation="super-secret-production-key-256",
        clock_skew_seconds=0,
    )
    # Issue a token already expired
    token = provider.issue_token(
        subject="expired-user",
        expires_in_seconds=-10,
    )

    with pytest.raises(TokenExpiredError):
        provider.authenticate(token)


def test_jwt_not_yet_valid_token() -> None:
    provider = JWTAuthenticationProvider(
        key_or_rotation="super-secret-production-key-256",
        clock_skew_seconds=0,
    )
    # Token valid only in the future
    token = provider.issue_token(
        subject="future-user",
        expires_in_seconds=600,
        not_before_offset_seconds=120,
    )

    with pytest.raises(TokenNotYetValidError):
        provider.authenticate(token)


def test_jwt_tampered_payload() -> None:
    provider = JWTAuthenticationProvider(key_or_rotation="super-secret-production-key-256")
    token = provider.issue_token(subject="user-1", roles=["viewer"])
    header, payload, sig = token.split(".")

    # Tamper payload (e.g. elevate to platform-admin)
    tampered_payload = payload[:-4] + "AAAA"
    tampered_token = f"{header}.{tampered_payload}.{sig}"

    with pytest.raises((InvalidSignatureError, AuthenticationError)):
        provider.authenticate(tampered_token)


def test_jwt_invalid_signature() -> None:
    provider1 = JWTAuthenticationProvider(key_or_rotation="key-one-12345")
    provider2 = JWTAuthenticationProvider(key_or_rotation="key-two-67890")

    token = provider1.issue_token(subject="user-1")
    with pytest.raises(InvalidSignatureError):
        provider2.authenticate(token)


def test_jwt_wrong_issuer_and_audience() -> None:
    provider = JWTAuthenticationProvider(
        key_or_rotation="secret-key",
        expected_issuer="correct-issuer",
        expected_audience="correct-aud",
    )

    bad_iss_token = provider.issue_token(subject="u1", extra_claims={"iss": "rogue-authority"})
    with pytest.raises(AuthenticationError, match="Invalid issuer"):
        provider.authenticate(bad_iss_token)

    bad_aud_token = provider.issue_token(subject="u1", extra_claims={"aud": "rogue-system"})
    with pytest.raises(AuthenticationError, match="Invalid audience"):
        provider.authenticate(bad_aud_token)


def test_jwt_key_rotation() -> None:
    rotation = KeyRotationManager(
        active_key_id="v1",
        keys={"v1": "initial-secret-key-1"},
    )
    provider = JWTAuthenticationProvider(key_or_rotation=rotation)

    # Issue token with v1
    token_v1 = provider.issue_token(subject="user-v1")
    assert provider.authenticate(token_v1).subject == "user-v1"

    # Rotate to v2 while keeping v1
    rotation.rotate_to_new_key(new_key_id="v2", new_key_value="new-rotated-secret-2", keep_previous=True)

    # Both old token and new token authenticate successfully during rotation window
    assert provider.authenticate(token_v1).subject == "user-v1"

    token_v2 = provider.issue_token(subject="user-v2")
    assert provider.authenticate(token_v2).subject == "user-v2"

    # Now drop v1 key completely
    rotation.rotate_to_new_key(new_key_id="v3", new_key_value="third-secret-3", keep_previous=False)
    with pytest.raises(AuthenticationError):
        provider.authenticate(token_v1)


def test_mtls_authentication() -> None:
    provider = MTLSAuthenticationProvider(
        trusted_issuers=["ULPF-Internal-CA"],
        role_mapping={"admin-operator": {"platform-admin"}},
    )

    # Valid cert
    cert_good = {
        "common_name": "admin-operator",
        "issuer": "ULPF-Internal-CA",
        "not_before": "2020-01-01T00:00:00Z",
        "not_after": "2030-01-01T00:00:00Z",
    }
    ident = provider.authenticate(b"", cert_info=cert_good)
    assert ident.subject == "admin-operator"
    assert "platform-admin" in ident.roles

    # Untrusted issuer
    cert_bad_ca = dict(cert_good, issuer="Rogue-CA")
    with pytest.raises(AuthenticationError, match="not in trusted CA list"):
        provider.authenticate(b"", cert_info=cert_bad_ca)

    # Expired cert
    cert_expired = dict(cert_good, not_after="2022-01-01T00:00:00Z")
    with pytest.raises(AuthenticationError, match="expired"):
        provider.authenticate(b"", cert_info=cert_expired)


def test_signed_proxy_authentication() -> None:
    import hashlib
    import hmac

    gw_key = "gateway-shared-key-for-test"
    provider = SignedProxyAuthenticationProvider(
        shared_gateway_secret=gw_key, max_clock_skew_seconds=30
    )

    now = int(time.time())
    subject = "network-admin-01"
    roles = "operator,viewer"
    cid = "req-uuid-123"

    payload = f"{subject}|{roles}|{now}|{cid}".encode()
    valid_sig = hmac.new(gw_key.encode("utf-8"), payload, hashlib.sha256).hexdigest()

    # Valid signature passes
    ident = provider.authenticate(
        valid_sig,
        subject=subject,
        roles=roles,
        timestamp=str(now),
        correlation_id=cid,
    )
    assert ident.subject == subject
    assert "operator" in ident.roles
    assert ident.auth_method == "signed_proxy"

    # Spoofed role without valid signature fails (Finding F-P6-AUTH-01 defense)
    with pytest.raises(InvalidSignatureError):
        provider.authenticate(
            valid_sig,
            subject=subject,
            roles="platform-admin",  # Tampered
            timestamp=str(now),
            correlation_id=cid,
        )

    # Stale timestamp fails replay defense
    with pytest.raises(AuthenticationError, match="out of bounds"):
        provider.authenticate(
            valid_sig,
            subject=subject,
            roles=roles,
            timestamp=str(now - 100),
            correlation_id=cid,
        )
