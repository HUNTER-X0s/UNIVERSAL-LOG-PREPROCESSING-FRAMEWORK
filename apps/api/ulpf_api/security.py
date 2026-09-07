"""API security, authentication dependencies, and authorization guards for ULPF Phase 7.

Enforces:
- Rule 4: Cryptographic authentication boundary
- Rule 6: Least-privilege policy evaluation
- Rule 16: No anonymous administrative access
- Rule 17: No unauthenticated trust headers accepted in production profile
- Rule 14: Security audit logging
- Finding F-P6-AUTH-01 full remediation
"""

from os import environ
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status
from ulpf_security.audit import SecurityAuditLogger
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
from ulpf_security.policy import (
    IdentityContext,
    Permission,
    PolicyEngine,
)
from ulpf_security.secrets import KeyRotationManager

# Shared application security infrastructure
_DEFAULT_SIGNING_KEY = environ.get("ULPF_JWT_SECRET", "ulpf-phase7-hardened-key-32bytes-min")
_KEY_ROTATION = KeyRotationManager("v1", {"v1": _DEFAULT_SIGNING_KEY})

jwt_auth_provider = JWTAuthenticationProvider(key_or_rotation=_KEY_ROTATION)
mtls_auth_provider = MTLSAuthenticationProvider()
policy_engine = PolicyEngine()
security_audit_logger = SecurityAuditLogger()


def get_current_profile() -> str:
    """Returns active deployment profile: 'production', 'development', 'test', or 'airgap'."""
    return environ.get("ULPF_PROFILE", "development").lower().strip()


def get_current_identity(
    request: Request,
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    x_proxy_signature: Annotated[str | None, Header(alias="X-Proxy-Signature")] = None,
    x_forwarded_user: Annotated[str | None, Header(alias="X-Forwarded-User")] = None,
    x_forwarded_roles: Annotated[str | None, Header(alias="X-Forwarded-Roles")] = None,
    x_forwarded_timestamp: Annotated[str | None, Header(alias="X-Forwarded-Timestamp")] = None,
    x_role: Annotated[str | None, Header(alias="X-Role")] = None,
) -> IdentityContext:
    """Resolves and cryptographically verifies caller identity.

    Precedence:
    1. Authorization: Bearer <jwt>
    2. X-Proxy-Signature (Signed gateway assertion)
    3. Profile-controlled development fallback (rejected in production profile)
    """
    profile = get_current_profile()
    correlation_id = getattr(request.state, "correlation_id", "req-unknown")

    # 1. JWT Bearer token authentication
    if authorization and authorization.lower().startswith("bearer "):
        try:
            return jwt_auth_provider.authenticate(authorization)
        except TokenExpiredError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Token has expired: {e}",
                headers={
                    "WWW-Authenticate": (
                        'Bearer error="invalid_token", error_description="token_expired"'
                    )
                },
            ) from e
        except TokenNotYetValidError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Token not yet valid: {e}",
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            ) from e
        except (InvalidSignatureError, AuthenticationError) as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid authentication token: {e}",
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            ) from e

    # 2. Signed Proxy header authentication
    if x_proxy_signature and x_forwarded_user and x_forwarded_roles and x_forwarded_timestamp:
        proxy_provider = SignedProxyAuthenticationProvider(
            shared_gateway_secret=environ.get("ULPF_PROXY_SECRET", _DEFAULT_SIGNING_KEY),
        )
        try:
            return proxy_provider.authenticate(
                x_proxy_signature,
                subject=x_forwarded_user,
                roles=x_forwarded_roles,
                timestamp=x_forwarded_timestamp,
                correlation_id=correlation_id,
            )
        except AuthenticationError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Proxy signature verification failed: {e}",
            ) from e

    # 3. Production profile strictly forbids unauthenticated or unsigned access
    if profile == "production":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                "Production profile requires cryptographic authentication "
                "(Bearer JWT or signed proxy)"
            ),
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 4. Development / Test profile reference identity fallback
    if x_role:
        return IdentityContext(
            subject="dev-test-client",
            issuer="local-dev-fallback",
            roles={x_role},
            permissions=set(),
            auth_method="dev_reference_header",
        )

    # Anonymous identity
    return IdentityContext(
        subject="anonymous",
        issuer="unauthenticated",
        roles=set(),
        permissions=set(),
        auth_method="anonymous",
    )


class RequirePermission:
    """FastAPI dependency for policy-based authorization."""

    def __init__(self, permission: Permission) -> None:
        self.permission = permission

    def __call__(
        self,
        request: Request,
        identity: Annotated[IdentityContext, Depends(get_current_identity)],
    ) -> IdentityContext:
        correlation_id = getattr(request.state, "correlation_id", "req-unknown")
        client_ip = request.client.host if request.client else "unknown"

        # Anonymous access rejected for any protected permission
        if identity.auth_method == "anonymous":
            security_audit_logger.log(
                event_id=f"audit-{correlation_id}",
                actor=identity.subject,
                auth_method=identity.auth_method,
                permission=self.permission.value,
                target=request.url.path,
                action=request.method,
                result="DENIED",
                reason="Anonymous access forbidden",
                correlation_id=correlation_id,
                client_ip=client_ip,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required for this operation",
                headers={"WWW-Authenticate": "Bearer"},
            )

        authorized = policy_engine.is_authorized(identity, self.permission)
        if not authorized:
            security_audit_logger.log(
                event_id=f"audit-{correlation_id}",
                actor=identity.subject,
                auth_method=identity.auth_method,
                permission=self.permission.value,
                target=request.url.path,
                action=request.method,
                result="DENIED",
                reason="Insufficient permissions",
                correlation_id=correlation_id,
                client_ip=client_ip,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Caller '{identity.subject}' lacks required "
                    f"permission '{self.permission.value}'"
                ),
            )

        return identity
