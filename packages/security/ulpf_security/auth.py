"""Authentication providers and token verification engine for ULPF Phase 7.

Enforces:
- Rule 4: Pluggable production authentication boundary
- Rule 5: Standard AuthenticationProvider abstraction
- Rule 9: Strict failure handling (401 vs 403)
- Rule 17: No client-controlled trust headers accepted without cryptographic verification
- Zero third-party dependencies (pure standard library cryptography)
"""

import base64
import hashlib
import hmac
import json
import time
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Any

from ulpf_security.errors import (
    AuthenticationError,
    InvalidSignatureError,
    TokenExpiredError,
    TokenNotYetValidError,
)
from ulpf_security.policy import IdentityContext
from ulpf_security.secrets import KeyRotationManager


class AuthenticationProvider(ABC):
    """Abstract authentication boundary interface."""

    @abstractmethod
    def authenticate(self, credentials: str | bytes, **kwargs: Any) -> IdentityContext:
        """Verify credentials and return verified IdentityContext, or raise AuthenticationError."""


def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _base64url_decode(segment: str) -> bytes:
    padding = 4 - (len(segment) % 4)
    if padding != 4:
        segment += "=" * padding
    return base64.urlsafe_b64decode(segment.encode("ascii"))


class JWTAuthenticationProvider(AuthenticationProvider):
    """Production JWT authentication provider using HMAC-SHA256 with key rotation support."""

    def __init__(
        self,
        key_or_rotation: str | KeyRotationManager,
        expected_issuer: str | list[str] | None = "ulpf-auth-authority",
        expected_audience: str | list[str] | None = "ulpf-platform",
        clock_skew_seconds: int = 5,
    ) -> None:
        if isinstance(key_or_rotation, str):
            self.key_manager = KeyRotationManager("default", {"default": key_or_rotation})
        else:
            self.key_manager = key_or_rotation

        self.expected_issuers = (
            [expected_issuer] if isinstance(expected_issuer, str) else (expected_issuer or [])
        )
        self.expected_audiences = (
            [expected_audience] if isinstance(expected_audience, str) else (expected_audience or [])
        )
        self.clock_skew_seconds = clock_skew_seconds

    def issue_token(
        self,
        subject: str,
        roles: list[str] | set[str] | None = None,
        permissions: list[str] | set[str] | None = None,
        tenant_id: str | None = None,
        expires_in_seconds: int = 3600,
        not_before_offset_seconds: int = 0,
        extra_claims: dict[str, Any] | None = None,
        key_id: str | None = None,
    ) -> str:
        """Issues a signed HS256 JWT for testing, service-to-service auth, or token grant."""
        kid, key = (
            (key_id, self.key_manager.get_verification_key(key_id))
            if key_id
            else self.key_manager.get_active_key()
        )

        now = int(time.time())
        header = {"alg": "HS256", "typ": "JWT", "kid": kid}
        payload: dict[str, Any] = {
            "sub": subject,
            "iss": self.expected_issuers[0] if self.expected_issuers else "ulpf-auth-authority",
            "aud": self.expected_audiences[0] if self.expected_audiences else "ulpf-platform",
            "iat": now,
            "exp": now + expires_in_seconds,
            "nbf": now + not_before_offset_seconds,
            "roles": list(roles or []),
            "permissions": list(permissions or []),
        }
        if tenant_id:
            payload["tenant_id"] = tenant_id
        if extra_claims:
            payload.update(extra_claims)

        header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
        encoded_header = _base64url_encode(header_bytes)
        payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        encoded_payload = _base64url_encode(payload_bytes)
        signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")

        sig = hmac.new(key.encode("utf-8"), signing_input, hashlib.sha256).digest()
        encoded_sig = _base64url_encode(sig)

        return f"{encoded_header}.{encoded_payload}.{encoded_sig}"

    def authenticate(self, credentials: str | bytes, **kwargs: Any) -> IdentityContext:
        """Verifies JWT format, signature, expiration, audience, issuer, and claims."""
        if isinstance(credentials, bytes):
            credentials = credentials.decode("utf-8")

        raw_token = credentials.strip()
        if raw_token.lower().startswith("bearer "):
            raw_token = raw_token[7:].strip()

        parts = raw_token.split(".")
        if len(parts) != 3:
            raise AuthenticationError(
                "Malformed JWT token format; expected header.payload.signature"
            )

        raw_header, raw_payload, raw_sig = parts

        try:
            header = json.loads(_base64url_decode(raw_header))
            payload = json.loads(_base64url_decode(raw_payload))
            sig_bytes = _base64url_decode(raw_sig)
        except Exception as e:
            raise AuthenticationError(f"Failed to decode token segments: {e}") from e

        # 1. Algorithm check (Strictly reject 'none' or unsupported alg)
        alg = header.get("alg")
        if alg != "HS256":
            raise AuthenticationError(
                f"Unsupported or unsafe algorithm '{alg}'; strictly require HS256"
            )

        # 2. Key ID resolution
        kid = header.get("kid") or self.key_manager.active_key_id
        try:
            key = self.key_manager.get_verification_key(kid)
        except Exception as e:
            raise AuthenticationError(f"Unknown signing key id '{kid}': {e}") from e

        # 3. Signature verification with constant-time compare
        signing_input = f"{raw_header}.{raw_payload}".encode("ascii")
        expected_sig = hmac.new(key.encode("utf-8"), signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(sig_bytes, expected_sig):
            raise InvalidSignatureError("Token signature verification failed")

        now = int(time.time())

        # 4. Expiration check
        exp = payload.get("exp")
        if exp is not None and now > (exp + self.clock_skew_seconds):
            raise TokenExpiredError(f"Token expired at {exp} (current time {now})")

        # 5. Not-before check
        nbf = payload.get("nbf")
        if nbf is not None and now < (nbf - self.clock_skew_seconds):
            raise TokenNotYetValidError(f"Token not valid before {nbf} (current time {now})")

        # 6. Issuer verification
        if self.expected_issuers:
            iss = payload.get("iss")
            if iss not in self.expected_issuers:
                raise AuthenticationError(
                    f"Invalid issuer '{iss}'; expected one of {self.expected_issuers}"
                )

        # 7. Audience verification
        if self.expected_audiences:
            aud = payload.get("aud")
            aud_list = [aud] if isinstance(aud, str) else (aud or [])
            if not any(a in self.expected_audiences for a in aud_list):
                raise AuthenticationError(
                    f"Invalid audience '{aud}'; expected one of {self.expected_audiences}"
                )

        # 8. Subject presence
        sub = payload.get("sub")
        if not sub:
            raise AuthenticationError("Token payload missing required 'sub' claim")

        roles = set(payload.get("roles") or [])
        permissions = set(payload.get("permissions") or [])
        tenant_id = payload.get("tenant_id")

        return IdentityContext(
            subject=sub,
            issuer=str(payload.get("iss", "unknown")),
            roles=roles,
            permissions=permissions,
            tenant_id=tenant_id,
            auth_method="jwt_hs256",
            attributes=payload,
        )


class MTLSAuthenticationProvider(AuthenticationProvider):
    """Validates mutual TLS client certificate claims."""

    def __init__(
        self,
        trusted_issuers: list[str] | None = None,
        role_mapping: dict[str, set[str]] | None = None,
    ) -> None:
        self.trusted_issuers = trusted_issuers or ["ULPF-Internal-CA"]
        self.role_mapping = role_mapping or {
            "ingest-worker": {"ingest-service"},
            "admin-operator": {"platform-admin"},
            "sec-auditor": {"viewer"},
        }

    def authenticate(self, credentials: str | bytes, **kwargs: Any) -> IdentityContext:
        """Validates dictionary of parsed certificate fields passed by TLS terminator or socket."""
        cert_info = kwargs.get("cert_info")
        if not cert_info or not isinstance(cert_info, dict):
            raise AuthenticationError("No client certificate details provided")

        cn = cert_info.get("common_name")
        issuer = cert_info.get("issuer")
        not_after = cert_info.get("not_after")
        not_before = cert_info.get("not_before")

        if not cn:
            raise AuthenticationError("Client certificate missing Common Name (CN)")

        if issuer and issuer not in self.trusted_issuers:
            raise AuthenticationError(
                f"Client certificate issuer '{issuer}' is not in trusted CA list"
            )

        now_iso = datetime.now(UTC).isoformat()
        if not_after and now_iso > not_after:
            raise AuthenticationError(f"Client certificate expired on {not_after}")
        if not_before and now_iso < not_before:
            raise AuthenticationError(
                f"Client certificate not yet valid until {not_before}"
            )

        roles = set(self.role_mapping.get(cn, {"viewer"}))
        return IdentityContext(
            subject=cn,
            issuer=str(issuer or "mTLS"),
            roles=roles,
            permissions=set(),
            auth_method="mtls",
            attributes=cert_info,
        )


class SignedProxyAuthenticationProvider(AuthenticationProvider):
    """Cryptographically verifies identity assertions passed by upstream reverse proxies/gateways.

    Solves Finding F-P6-AUTH-01: Header claims (X-User, X-Role) MUST be accompanied by
    an HMAC-SHA256 signature in X-Proxy-Signature over:
    '{subject}|{roles_comma_separated}|{timestamp_unix}|{correlation_id}'.
    """

    def __init__(
        self,
        shared_gateway_secret: str,
        max_clock_skew_seconds: int = 60,
    ) -> None:
        self.secret = shared_gateway_secret
        self.max_clock_skew = max_clock_skew_seconds

    def authenticate(self, credentials: str | bytes, **kwargs: Any) -> IdentityContext:
        subject = kwargs.get("subject")
        roles_header = kwargs.get("roles")
        timestamp_str = kwargs.get("timestamp")
        correlation_id = kwargs.get("correlation_id", "")
        signature = str(credentials).strip()

        if not subject or not roles_header or not timestamp_str or not signature:
            raise AuthenticationError(
                "Missing required proxy authentication headers for verified identity"
            )

        try:
            req_time = int(timestamp_str)
        except ValueError as e:
            raise AuthenticationError(f"Invalid timestamp in proxy auth header: {e}") from e

        now = int(time.time())
        if abs(now - req_time) > self.max_clock_skew:
            raise AuthenticationError(
                "Upstream proxy request timestamp out of bounds (replay guard)"
            )

        roles = {r.strip() for r in roles_header.split(",") if r.strip()}

        # Verify HMAC signature
        payload_to_sign = f"{subject}|{roles_header}|{timestamp_str}|{correlation_id}".encode()
        expected_sig = hmac.new(
            self.secret.encode("utf-8"), payload_to_sign, hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(signature, expected_sig):
            raise InvalidSignatureError(
                "Upstream proxy cryptographic signature mismatch; rejected spoofed headers"
            )

        return IdentityContext(
            subject=subject,
            issuer="trusted-upstream-gateway",
            roles=roles,
            permissions=set(),
            auth_method="signed_proxy",
            attributes={"proxy_timestamp": req_time, "correlation_id": correlation_id},
        )
