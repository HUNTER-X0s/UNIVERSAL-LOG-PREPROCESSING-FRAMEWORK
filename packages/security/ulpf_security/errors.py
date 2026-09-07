"""Security error definitions for ULPF Phase 7.

Enforces:
- Rule 14: No hardcoded credentials
- Rule 16: No anonymous administrative access
- Rule 17: No client-controlled trust headers accepted as authenticated identity
- Fail-closed security exceptions
"""

from typing import Any


class SecurityError(Exception):
    """Base exception for all security and authorization failures."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class AuthenticationError(SecurityError):
    """Raised when authentication credentials cannot be verified or are missing."""


class TokenExpiredError(AuthenticationError):
    """Raised when an authentication token has passed its expiration time."""


class TokenNotYetValidError(AuthenticationError):
    """Raised when an authentication token is used before its 'not before' (nbf) time."""


class InvalidSignatureError(AuthenticationError):
    """Raised when cryptographic signature verification fails."""


class AuthorizationError(SecurityError):
    """Raised when an authenticated caller lacks required permission for a resource."""


class SecretNotFoundError(SecurityError):
    """Raised when a required secret or key cannot be resolved."""


class SecurityConfigurationError(SecurityError):
    """Raised when unsafe security configuration is detected in a production profile."""
