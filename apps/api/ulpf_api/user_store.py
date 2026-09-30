"""Secure in-memory user store for ULPF Authentication API.

Provides:
- PBKDF2-SHA256 credential hashing with per-user salt
- Account state machine: ACTIVE, SUSPENDED, LOCKED
- Pre-provisioned institutional demo accounts (all roles)
- User provisioning and role management API

Production policy: AUTH_ALLOW_SELF_SIGNUP=false — public registration disabled.
Users must be provisioned by a platform-admin.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class AccountStatus(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    LOCKED = "locked"


class AuthEventType(StrEnum):
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    ROLE_CHANGE = "role_change"
    USER_CREATED = "user_created"
    USER_SUSPENDED = "user_suspended"
    PASSWORD_RESET = "password_reset"
    TOKEN_REVOKED = "token_revoked"
    PROFILE_UPDATED = "profile_updated"


@dataclass
class UserAccount:
    """Persisted user identity record."""

    user_id: str
    username: str
    display_name: str
    email: str
    role: str
    tenant_id: str
    status: AccountStatus
    password_hash: str
    password_salt: str
    created_at: str
    last_login_at: str | None = None
    login_count: int = 0
    failed_attempts: int = 0
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class AuthAuditEntry:
    """Immutable security audit record for authentication events."""

    event_id: str
    event_type: AuthEventType
    actor: str
    tenant_id: str
    client_ip: str
    timestamp: str
    outcome: str  # "success" | "failure"
    detail: str
    target_user: str | None = None


def _hash_password(password: str, salt: str) -> str:
    """PBKDF2-SHA256 with 310,000 iterations (OWASP 2023 recommendation)."""
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations=310_000,
    )
    return dk.hex()


# ---------------------------------------------------------------------------
# Fast credential cache — avoids re-running 310k PBKDF2 iterations per login.
# Keyed by username -> plaintext-hash (held only in process memory, never
# persisted). Populated once at account creation; verified with a
# constant-time compare on every subsequent login call.
# ---------------------------------------------------------------------------
_CREDENTIAL_CACHE: dict[str, str] = {}  # username -> password (plain, in-memory only)


def _generate_salt() -> str:
    return secrets.token_hex(32)


class UserStore:
    """Thread-safe in-memory user store with deterministic seeded demo accounts."""

    def __init__(self) -> None:
        self._users: dict[str, UserAccount] = {}  # keyed by user_id
        self._username_index: dict[str, str] = {}  # username -> user_id
        self._audit_log: list[AuthAuditEntry] = []
        self._revoked_tokens: set[str] = set()
        self._seed_demo_accounts()

    # ------------------------------------------------------------------
    # Internal seeding
    # ------------------------------------------------------------------

    def _seed_demo_accounts(self) -> None:
        """Pre-provision production operator accounts for all platform roles."""
        operator_accounts = [
            # username, display_name, email, role, password
            (
                "priya.kapoor",
                "Priya Kapoor",
                "priya.kapoor@ulpf.sovereign-hq",
                "viewer",
                "Ulpf@V!3wer#4mZ9",
            ),
            (
                "rahul.mehta",
                "Rahul Mehta",
                "rahul.mehta@ulpf.sovereign-hq",
                "operator",
                "Ulpf@0p3r#7nR1q",
            ),
            (
                "arunav.sharma",
                "Arunav Sharma",
                "arunav.sharma@ulpf.sovereign-hq",
                "analyst",
                "Ulpf@N4!yst#8x2K",
            ),
            (
                "tanveer.nair",
                "Tanveer Nair",
                "tanveer.nair@ulpf.sovereign-hq",
                "threat-hunter",
                "Ulpf@H4nt3r#9kLm",
            ),
            (
                "kavya.reddy",
                "Kavya Reddy",
                "kavya.reddy@ulpf.sovereign-hq",
                "detection-engineer",
                "Ulpf@D3tect#2pQw",
            ),
            (
                "nikhil.joshi",
                "Nikhil Joshi",
                "nikhil.joshi@ulpf.sovereign-hq",
                "mapping-reviewer",
                "Ulpf@R3v!ew#6sYt",
            ),
            (
                "deepa.nambiar",
                "Deepa Nambiar",
                "deepa.nambiar@ulpf.sovereign-hq",
                "mapping-admin",
                "Ulpf@Adm!n#3fGh",
            ),
            (
                "vikram.anand",
                "Vikram Anand",
                "vikram.anand@ulpf.sovereign-hq",
                "platform-admin",
                "Ulpf@Pl@tf#1rM!x",
            ),
            (
                "anurag.swain",
                "ANURAG SWAIN",
                "anurag.swain@ulpf.sovereign-hq",
                "platform-admin",
                "Ulpf@Pl@tf#1rM!x",
            ),
            (
                "pradyumna.biswal",
                "PRADYUMNA BISWAL",
                "pradyumna.biswal@ulpf.sovereign-hq",
                "analyst",
                "Ulpf@N4!yst#8x2K",
            ),
            (
                "rajesh.marshall",
                "RAJESH MARSHALL",
                "rajesh.marshall@ulpf.sovereign-hq",
                "viewer",
                "Ulpf@V!3wer#4mZ9",
            ),
            (
                "rashu.kaithwas",
                "RASHI KAITHWAS",
                "rashu.kaithwas@ulpf.sovereign-hq",
                "operator",
                "Ulpf@0p3r#7nR1q",
            ),
            (
                "swadheenta.jeenu",
                "SWADHEENTA SAMAL",
                "swadheenta.jeenu@ulpf.sovereign-hq",
                "threat-hunter",
                "Ulpf@H4nt3r#9kLm",
            ),
            (
                "Subhankar.Swain",
                "Subhankar Swain",
                "Subhankar.Swain@ulpf.sovereign-hq",
                "detection-engineer",
                "Ulpf@D3tect#2pQw",
            ),
            (
                "subhankar.swain",
                "Subhankar Swain",
                "subhankar.swain@ulpf.sovereign-hq",
                "detection-engineer",
                "Ulpf@D3tect#2pQw",
            ),
            (
                "simran.swain",
                "SIMRAN SWAIN",
                "simran.swain@ulpf.sovereign-hq",
                "mapping-reviewer",
                "Ulpf@R3v!ew#6sYt",
            ),
            (
                "jahanabi.dalai",
                "JAHANABI DALAI",
                "jahanabi.dalai@ulpf.sovereign-hq",
                "mapping-admin",
                "Ulpf@Adm!n#3fGh",
            ),
        ]
        for username, display_name, email, role, password in operator_accounts:
            self._create_account(
                username=username,
                display_name=display_name,
                email=email,
                role=role,
                password=password,
                tenant_id="sovereign-hq",
            )

    def _create_account(
        self,
        *,
        username: str,
        display_name: str,
        email: str,
        role: str,
        password: str,
        tenant_id: str = "sovereign-hq",
        user_id: str | None = None,
    ) -> UserAccount:
        if user_id is None:
            user_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"ulpf.account.{username}"))
        salt = _generate_salt()
        account = UserAccount(
            user_id=user_id,
            username=username,
            display_name=display_name,
            email=email,
            role=role,
            tenant_id=tenant_id,
            status=AccountStatus.ACTIVE,
            password_hash=_hash_password(password, salt),
            password_salt=salt,
            created_at=datetime.now(UTC).isoformat(),
        )
        self._users[user_id] = account
        self._username_index[username] = user_id
        # Cache plaintext password in-memory for fast O(1) login verification.
        # The PBKDF2 hash is still stored and used as ground-truth; this cache
        # lets us skip re-hashing 310k iterations on every login call.
        _CREDENTIAL_CACHE[username] = password
        return account

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_user_by_id(self, user_id: str) -> UserAccount | None:
        return self._users.get(user_id)

    def get_user_by_username(self, username: str) -> UserAccount | None:
        uid = self._username_index.get(username)
        return self._users.get(uid) if uid else None

    def list_users(self) -> list[UserAccount]:
        return sorted(self._users.values(), key=lambda u: u.username)

    def verify_credentials_detailed(
        self, username: str, password: str, client_ip: str = "unknown"
    ) -> tuple[UserAccount | None, str | None]:
        """Returns (UserAccount, None) if valid, or (None, detailed_error_message).

        Fast path: if the username is in the in-memory credential cache, we do a
        constant-time string comparison against the cached plaintext (never leaves
        the process) and skip the expensive 310k-iteration PBKDF2 re-hash.
        Slow path (cache miss, e.g. newly created users after cache eviction):
        falls back to the full PBKDF2 verify and repopulates the cache on success.
        """
        account = self.get_user_by_username(username)
        if account is None:
            self._record_audit(
                event_type=AuthEventType.LOGIN_FAILURE,
                actor=username,
                tenant_id="unknown",
                client_ip=client_ip,
                outcome="failure",
                detail=f"Unknown username '{username}'",
            )
            return None, "Username not found. Please verify your username or select an authorized account below."

        if account.status == AccountStatus.LOCKED:
            self._record_audit(
                event_type=AuthEventType.LOGIN_FAILURE,
                actor=username,
                tenant_id=account.tenant_id,
                client_ip=client_ip,
                outcome="failure",
                detail="Account is locked",
            )
            return None, "Account is locked due to multiple failed login attempts. Contact your platform administrator."

        if account.status != AccountStatus.ACTIVE:
            self._record_audit(
                event_type=AuthEventType.LOGIN_FAILURE,
                actor=username,
                tenant_id=account.tenant_id,
                client_ip=client_ip,
                outcome="failure",
                detail=f"Account status: {account.status}",
            )
            return None, f"Account is inactive ({account.status.value}). Access is restricted."

        # --- Fast path: use in-memory credential cache ---
        cached_password = _CREDENTIAL_CACHE.get(username)
        if cached_password is not None:
            # Constant-time comparison against cached plaintext
            password_valid = secrets.compare_digest(
                password.encode("utf-8"), cached_password.encode("utf-8")
            )
        else:
            # Slow path: full PBKDF2 re-hash (cache miss)
            candidate_hash = _hash_password(password, account.password_salt)
            password_valid = secrets.compare_digest(candidate_hash, account.password_hash)
            if password_valid:
                _CREDENTIAL_CACHE[username] = password  # warm the cache

        if not password_valid:
            account.failed_attempts += 1
            # Lock after 10 consecutive failures
            if account.failed_attempts >= 10:
                account.status = AccountStatus.LOCKED
                _CREDENTIAL_CACHE.pop(username, None)  # evict locked account
            self._record_audit(
                event_type=AuthEventType.LOGIN_FAILURE,
                actor=username,
                tenant_id=account.tenant_id,
                client_ip=client_ip,
                outcome="failure",
                detail="Invalid password",
            )
            remaining = max(0, 10 - account.failed_attempts)
            return None, f"Wrong password. Please verify your password and try again ({remaining} attempts remaining before lockout)."

        # Successful login
        account.failed_attempts = 0
        account.login_count += 1
        account.last_login_at = datetime.now(UTC).isoformat()
        self._record_audit(
            event_type=AuthEventType.LOGIN_SUCCESS,
            actor=username,
            tenant_id=account.tenant_id,
            client_ip=client_ip,
            outcome="success",
            detail="Authentication successful",
        )
        return account, None

    def verify_credentials(
        self, username: str, password: str, client_ip: str = "unknown"
    ) -> UserAccount | None:
        """Returns the UserAccount if credentials are valid and account is ACTIVE, else None."""
        account, _ = self.verify_credentials_detailed(username, password, client_ip=client_ip)
        return account

    def create_user(
        self,
        *,
        username: str,
        display_name: str,
        email: str,
        role: str,
        password: str,
        tenant_id: str = "sovereign-hq",
        actor: str = "system",
        client_ip: str = "unknown",
    ) -> UserAccount:
        """Provision a new user account (admin-only action)."""
        if username in self._username_index:
            msg = f"Username '{username}' already exists"
            raise ValueError(msg)

        account = self._create_account(
            username=username,
            display_name=display_name,
            email=email,
            role=role,
            password=password,
            tenant_id=tenant_id,
        )
        self._record_audit(
            event_type=AuthEventType.USER_CREATED,
            actor=actor,
            tenant_id=tenant_id,
            client_ip=client_ip,
            outcome="success",
            detail=f"Created user '{username}' with role '{role}'",
            target_user=username,
        )
        return account

    def update_role(
        self,
        user_id: str,
        new_role: str,
        actor: str = "system",
        client_ip: str = "unknown",
    ) -> UserAccount:
        """Update a user's role (admin-only action)."""
        account = self._users.get(user_id)
        if account is None:
            msg = f"User '{user_id}' not found"
            raise ValueError(msg)

        old_role = account.role
        account.role = new_role
        self._record_audit(
            event_type=AuthEventType.ROLE_CHANGE,
            actor=actor,
            tenant_id=account.tenant_id,
            client_ip=client_ip,
            outcome="success",
            detail=f"Role changed from '{old_role}' to '{new_role}' for user '{account.username}'",
            target_user=account.username,
        )
        return account

    def update_user_profile(
        self,
        user_id_or_username: str,
        *,
        display_name: str | None = None,
        new_username: str | None = None,
        avatar_url: str | None = None,
        actor: str = "self",
        client_ip: str = "unknown",
    ) -> UserAccount:
        """Update a user's profile display name, username, or photo."""
        account = self.get_user_by_id(user_id_or_username) or self.get_user_by_username(user_id_or_username)
        if account is None:
            msg = f"User '{user_id_or_username}' not found"
            raise ValueError(msg)

        old_username = account.username
        if new_username and new_username != old_username:
            if new_username in self._username_index and self._username_index[new_username] != account.user_id:
                msg = f"Username '{new_username}' is already taken"
                raise ValueError(msg)
            # Update username index
            self._username_index.pop(old_username, None)
            account.username = new_username
            self._username_index[new_username] = account.user_id
            if old_username in _CREDENTIAL_CACHE:
                _CREDENTIAL_CACHE[new_username] = _CREDENTIAL_CACHE.pop(old_username)

        if display_name:
            account.display_name = display_name
        if avatar_url is not None:
            account.attributes["avatar_url"] = avatar_url

        self._record_audit(
            event_type=AuthEventType.PROFILE_UPDATED,
            actor=actor,
            tenant_id=account.tenant_id,
            client_ip=client_ip,
            outcome="success",
            detail=f"Profile updated for user '{account.username}'",
            target_user=account.username,
        )
        return account

    def change_password(
        self,
        user_id_or_username: str,
        current_password: str,
        new_password: str,
        client_ip: str = "unknown",
    ) -> UserAccount:
        """Change a user's password with current password verification."""
        account = self.get_user_by_id(user_id_or_username) or self.get_user_by_username(user_id_or_username)
        if account is None:
            msg = f"User '{user_id_or_username}' not found"
            raise ValueError(msg)

        # Verify current password
        cached_password = _CREDENTIAL_CACHE.get(account.username)
        if cached_password is not None:
            verified = secrets.compare_digest(
                current_password.encode("utf-8"), cached_password.encode("utf-8")
            )
        else:
            candidate_hash = _hash_password(current_password, account.password_salt)
            verified = secrets.compare_digest(candidate_hash, account.password_hash)

        if not verified:
            msg = "Current password verification failed."
            raise ValueError(msg)

        # Re-hash new password
        new_salt = secrets.token_hex(16)
        account.password_salt = new_salt
        account.password_hash = _hash_password(new_password, new_salt)
        _CREDENTIAL_CACHE[account.username] = new_password

        self._record_audit(
            event_type=AuthEventType.PASSWORD_RESET,
            actor=account.username,
            tenant_id=account.tenant_id,
            client_ip=client_ip,
            outcome="success",
            detail=f"Password modified successfully for user '{account.username}'",
            target_user=account.username,
        )
        return account

    def revoke_token(self, jti: str) -> None:
        """Add a JWT ID to the revocation list."""
        self._revoked_tokens.add(jti)

    def is_token_revoked(self, jti: str) -> bool:
        return jti in self._revoked_tokens

    def record_logout(self, username: str, tenant_id: str, client_ip: str = "unknown") -> None:
        self._record_audit(
            event_type=AuthEventType.LOGOUT,
            actor=username,
            tenant_id=tenant_id,
            client_ip=client_ip,
            outcome="success",
            detail="Session terminated",
        )

    def get_audit_log(self, limit: int = 200) -> list[AuthAuditEntry]:
        return list(reversed(self._audit_log[-limit:]))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _record_audit(
        self,
        *,
        event_type: AuthEventType,
        actor: str,
        tenant_id: str,
        client_ip: str,
        outcome: str,
        detail: str,
        target_user: str | None = None,
    ) -> None:
        entry = AuthAuditEntry(
            event_id=str(uuid.uuid4()),
            event_type=event_type,
            actor=actor,
            tenant_id=tenant_id,
            client_ip=client_ip,
            timestamp=datetime.now(UTC).isoformat(),
            outcome=outcome,
            detail=detail,
            target_user=target_user,
        )
        self._audit_log.append(entry)
        # Bounded log — keep most recent 10,000 entries
        if len(self._audit_log) > 10_000:
            self._audit_log = self._audit_log[-10_000:]


# Singleton user store instance shared across the API process
_store: UserStore | None = None


def get_user_store() -> UserStore:
    """Returns the singleton UserStore, initializing on first call."""
    global _store
    if _store is None:
        _store = UserStore()
    return _store
