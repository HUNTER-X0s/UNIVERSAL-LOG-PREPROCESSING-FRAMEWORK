"""ULPF Security Package - Phase 7 Production Hardening.

Provides:
- Cryptographic authentication (JWT, mTLS, Signed Proxy)
- Least-privilege authorization policy engine
- Secret management and key rotation
- Immutable security audit logging
"""

from ulpf_security.audit import SecurityAuditEvent, SecurityAuditLogger
from ulpf_security.auth import (
    AuthenticationProvider,
    JWTAuthenticationProvider,
    MTLSAuthenticationProvider,
    SignedProxyAuthenticationProvider,
)
from ulpf_security.errors import (
    AuthenticationError,
    AuthorizationError,
    InvalidSignatureError,
    SecretNotFoundError,
    SecurityConfigurationError,
    SecurityError,
    TokenExpiredError,
    TokenNotYetValidError,
)
from ulpf_security.policy import (
    ROLE_PERMISSIONS_MATRIX,
    IdentityContext,
    Permission,
    PolicyEngine,
)
from ulpf_security.secrets import (
    EnvironmentSecretManager,
    FileSecretManager,
    KeyRotationManager,
    SecretManager,
)

__all__ = [
    "AuthenticationError",
    "AuthenticationProvider",
    "AuthorizationError",
    "EnvironmentSecretManager",
    "FileSecretManager",
    "IdentityContext",
    "InvalidSignatureError",
    "JWTAuthenticationProvider",
    "KeyRotationManager",
    "MTLSAuthenticationProvider",
    "Permission",
    "PolicyEngine",
    "ROLE_PERMISSIONS_MATRIX",
    "SecretManager",
    "SecretNotFoundError",
    "SecurityAuditEvent",
    "SecurityAuditLogger",
    "SecurityConfigurationError",
    "SecurityError",
    "SignedProxyAuthenticationProvider",
    "TokenExpiredError",
    "TokenNotYetValidError",
]
