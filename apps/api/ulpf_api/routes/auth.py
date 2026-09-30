"""Authentication API router for ULPF.

Mounted at /api/v1/auth — provides:
  POST /login        — Authenticate username + password → JWT session token
  GET  /me           — Resolve active Bearer token → verified IdentityContext
  POST /logout       — Invalidate session, emit audit event
  GET  /users        — List all platform users (requires admin.manage)
  POST /users        — Create a new user (requires admin.manage)
  PUT  /users/{uid}/role — Update user role (requires admin.manage)
  GET  /roles        — Return all registered roles and permission matrix
  GET  /audit        — Return security audit log for auth events

Backend authoritative: all token issuance uses JWTAuthenticationProvider;
all authorization uses PolicyEngine with the ROLE_PERMISSIONS_MATRIX.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from ulpf_api.security import (
    get_current_identity,
    jwt_auth_provider,
    policy_engine,
    security_audit_logger,
)
from ulpf_api.user_store import AccountStatus, get_user_store
from ulpf_security.policy import ROLE_PERMISSIONS_MATRIX, IdentityContext, Permission

router = APIRouter(prefix="/auth", tags=["Authentication"])

# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=128)
    password: str = Field(..., min_length=1, max_length=256)


class LoginResponse(BaseModel):
    token: str
    token_type: str = "Bearer"
    expires_in: int
    user_id: str
    username: str
    display_name: str
    role: str
    permissions: list[str]
    tenant_id: str


class MeResponse(BaseModel):
    subject: str
    issuer: str
    roles: list[str]
    permissions: list[str]
    tenant_id: str | None
    auth_method: str
    username: str | None = None
    display_name: str | None = None


class UserResponse(BaseModel):
    user_id: str
    username: str
    display_name: str
    email: str
    role: str
    status: str
    tenant_id: str
    created_at: str
    last_login_at: str | None
    login_count: int


class CreateUserRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9._\-]+$")
    display_name: str = Field(..., min_length=2, max_length=128)
    email: str = Field(..., min_length=5, max_length=256)
    role: str = Field(..., min_length=2, max_length=64)
    password: str = Field(..., min_length=8, max_length=256)
    tenant_id: str = Field(default="sovereign-hq", min_length=1, max_length=64)


class UpdateRoleRequest(BaseModel):
    role: str = Field(..., min_length=2, max_length=64)


class RoleInfo(BaseModel):
    role: str
    description: str
    permissions: list[str]


class AuditEntryResponse(BaseModel):
    event_id: str
    event_type: str
    actor: str
    tenant_id: str
    client_ip: str
    timestamp: str
    outcome: str
    detail: str
    target_user: str | None


class ProfileUpdateRequest(BaseModel):
    display_name: str | None = None
    username: str | None = None
    avatar_url: str | None = None


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=256)
    new_password: str = Field(..., min_length=6, max_length=256)


# ---------------------------------------------------------------------------
# Role descriptions (human-facing metadata)
# ---------------------------------------------------------------------------

_ROLE_DESCRIPTIONS: dict[str, str] = {
    "viewer": "Read-only observation of events, UCE records, and semantic data",
    "operator": "Operations & Ingest — manages replay, DLQ, and pipeline operations",
    "analyst": "Security intelligence analysis — hunting, investigations, and case management",
    "threat-hunter": "Advanced threat hunting with rule review authority",
    "detection-engineer": "Detection rule authoring, review, and activation",
    "ingest-service": "Service-to-service ingest credential (non-human, automated)",
    "mapping-reviewer": "Parser mapping review and approval authority",
    "mapping-admin": "Parser mapping governance — approve, activate, and rollback",
    "platform-admin": "Full administrative authority across all platform domains",
}

# ---------------------------------------------------------------------------
# Allowed roles for user provisioning
# ---------------------------------------------------------------------------

_PROVISIONED_ROLES = set(ROLE_PERMISSIONS_MATRIX.keys())

# ---------------------------------------------------------------------------
# Helper: require admin.manage permission
# ---------------------------------------------------------------------------


def _require_admin(identity: IdentityContext) -> None:
    """Raise 403 if the caller does not have admin.manage permission."""
    if not policy_engine.is_authorized(identity, Permission.ADMIN_MANAGE):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Caller '{identity.subject}' lacks required permission "
                f"'{Permission.ADMIN_MANAGE.value}'"
            ),
        )


# ---------------------------------------------------------------------------
# POST /auth/login
# ---------------------------------------------------------------------------


@router.post("/login", response_model=LoginResponse, summary="Authenticate and obtain JWT token")
async def login(request: Request, body: LoginRequest) -> LoginResponse:
    """Authenticates username + password; issues a signed HS256 JWT."""
    store = get_user_store()
    client_ip = request.client.host if request.client else "unknown"

    account, error_message = store.verify_credentials_detailed(
        body.username, body.password, client_ip=client_ip
    )
    if account is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=error_message or "Authentication failed. Invalid credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Calculate effective permissions from role
    role_permissions = ROLE_PERMISSIONS_MATRIX.get(account.role, set())
    permission_list = sorted(p.value for p in role_permissions)

    # Issue signed JWT token (1 hour expiry by default)
    expires_in = 3600
    token = jwt_auth_provider.issue_token(
        subject=account.user_id,
        roles=[account.role],
        permissions=permission_list,
        tenant_id=account.tenant_id,
        expires_in_seconds=expires_in,
        extra_claims={
            "username": account.username,
            "display_name": account.display_name,
            "email": account.email,
        },
    )

    security_audit_logger.log(
        event_id=f"login-{account.user_id}",
        actor=account.username,
        auth_method="password",
        permission="auth.login",
        target="/api/v1/auth/login",
        action="POST",
        result="ALLOWED",
        reason="Credentials verified",
        correlation_id="",
        client_ip=client_ip,
    )

    return LoginResponse(
        token=token,
        token_type="Bearer",
        expires_in=expires_in,
        user_id=account.user_id,
        username=account.username,
        display_name=account.display_name,
        role=account.role,
        permissions=permission_list,
        tenant_id=account.tenant_id,
    )


# ---------------------------------------------------------------------------
# GET /auth/me
# ---------------------------------------------------------------------------


@router.get("/me", response_model=MeResponse, summary="Get verified caller identity")
async def get_me(
    identity: Annotated[IdentityContext, Depends(get_current_identity)],
) -> MeResponse:
    """Returns the verified IdentityContext for the current Bearer token."""
    if identity.auth_method == "anonymous":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    effective_perms = policy_engine.get_effective_permissions(identity)
    store = get_user_store()
    account = store.get_user_by_id(identity.subject) or store.get_user_by_username(identity.subject)
    resolved_username = account.username if account else identity.subject
    resolved_display_name = account.display_name if account else identity.subject

    return MeResponse(
        subject=identity.subject,
        issuer=identity.issuer,
        roles=sorted(identity.roles),
        permissions=sorted(effective_perms),
        tenant_id=identity.tenant_id,
        auth_method=identity.auth_method,
        username=resolved_username,
        display_name=resolved_display_name,
    )


# ---------------------------------------------------------------------------
# POST /auth/logout
# ---------------------------------------------------------------------------


@router.post("/logout", summary="Terminate session and emit audit event")
async def logout(
    request: Request,
    identity: Annotated[IdentityContext, Depends(get_current_identity)],
) -> dict[str, str]:
    """Invalidates the session token and records a logout audit event."""
    if identity.auth_method == "anonymous":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No active session to terminate",
        )
    store = get_user_store()
    client_ip = request.client.host if request.client else "unknown"

    # Extract JTI if present and add to revocation list
    jti = identity.attributes.get("jti") or identity.subject
    store.revoke_token(jti)

    username = identity.attributes.get("username", identity.subject)
    tenant_id = identity.tenant_id or "unknown"
    store.record_logout(username=username, tenant_id=tenant_id, client_ip=client_ip)

    return {"message": "Session terminated successfully"}


# ---------------------------------------------------------------------------
# GET /auth/users
# ---------------------------------------------------------------------------


@router.get("/users", response_model=list[UserResponse], summary="List all platform users")
async def list_users(
    identity: Annotated[IdentityContext, Depends(get_current_identity)],
) -> list[UserResponse]:
    """Lists all provisioned platform users. Requires admin.manage permission."""
    _require_admin(identity)
    store = get_user_store()
    return [
        UserResponse(
            user_id=u.user_id,
            username=u.username,
            display_name=u.display_name,
            email=u.email,
            role=u.role,
            status=u.status.value,
            tenant_id=u.tenant_id,
            created_at=u.created_at,
            last_login_at=u.last_login_at,
            login_count=u.login_count,
        )
        for u in store.list_users()
    ]


# ---------------------------------------------------------------------------
# POST /auth/users
# ---------------------------------------------------------------------------


@router.post(
    "/users",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new platform user",
)
async def create_user(
    request: Request,
    body: CreateUserRequest,
    identity: Annotated[IdentityContext, Depends(get_current_identity)],
) -> UserResponse:
    """Creates a new platform user. Requires admin.manage permission."""
    _require_admin(identity)

    if body.role not in _PROVISIONED_ROLES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid role '{body.role}'. Must be one of: {sorted(_PROVISIONED_ROLES)}",
        )

    store = get_user_store()
    client_ip = request.client.host if request.client else "unknown"
    actor = identity.attributes.get("username", identity.subject)

    try:
        account = store.create_user(
            username=body.username,
            display_name=body.display_name,
            email=body.email,
            role=body.role,
            password=body.password,
            tenant_id=body.tenant_id,
            actor=actor,
            client_ip=client_ip,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        ) from e

    return UserResponse(
        user_id=account.user_id,
        username=account.username,
        display_name=account.display_name,
        email=account.email,
        role=account.role,
        status=account.status.value,
        tenant_id=account.tenant_id,
        created_at=account.created_at,
        last_login_at=account.last_login_at,
        login_count=account.login_count,
    )


# ---------------------------------------------------------------------------
# PUT /auth/users/{user_id}/role
# ---------------------------------------------------------------------------


@router.put(
    "/users/{user_id}/role",
    response_model=UserResponse,
    summary="Update a user's role",
)
async def update_user_role(
    user_id: str,
    body: UpdateRoleRequest,
    request: Request,
    identity: Annotated[IdentityContext, Depends(get_current_identity)],
) -> UserResponse:
    """Updates the role assigned to a user. Requires admin.manage permission."""
    _require_admin(identity)

    if body.role not in _PROVISIONED_ROLES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid role '{body.role}'. Must be one of: {sorted(_PROVISIONED_ROLES)}",
        )

    store = get_user_store()
    client_ip = request.client.host if request.client else "unknown"
    actor = identity.attributes.get("username", identity.subject)

    try:
        account = store.update_role(
            user_id=user_id,
            new_role=body.role,
            actor=actor,
            client_ip=client_ip,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e

    return UserResponse(
        user_id=account.user_id,
        username=account.username,
        display_name=account.display_name,
        email=account.email,
        role=account.role,
        status=account.status.value,
        tenant_id=account.tenant_id,
        created_at=account.created_at,
        last_login_at=account.last_login_at,
        login_count=account.login_count,
    )


# ---------------------------------------------------------------------------
# GET /auth/roles
# ---------------------------------------------------------------------------


@router.get("/roles", response_model=list[RoleInfo], summary="List all roles and permissions")
async def list_roles() -> list[RoleInfo]:
    """Returns all registered roles, descriptions, and fine-grained permissions."""
    result = []
    for role, perms in sorted(ROLE_PERMISSIONS_MATRIX.items()):
        result.append(
            RoleInfo(
                role=role,
                description=_ROLE_DESCRIPTIONS.get(role, "No description available"),
                permissions=sorted(p.value for p in perms),
            )
        )
    return result


# ---------------------------------------------------------------------------
# GET /auth/audit
# ---------------------------------------------------------------------------


@router.get(
    "/audit",
    response_model=list[AuditEntryResponse],
    summary="Get authentication security audit log",
)
async def get_audit_log(
    identity: Annotated[IdentityContext, Depends(get_current_identity)],
    limit: int = 100,
) -> list[AuditEntryResponse]:
    """Returns recent authentication audit events. Requires admin.manage permission."""
    _require_admin(identity)
    store = get_user_store()
    entries = store.get_audit_log(limit=min(limit, 500))
    return [
        AuditEntryResponse(
            event_id=e.event_id,
            event_type=e.event_type.value,
            actor=e.actor,
            tenant_id=e.tenant_id,
            client_ip=e.client_ip,
            timestamp=e.timestamp,
            outcome=e.outcome,
            detail=e.detail,
            target_user=e.target_user,
        )
        for e in entries
    ]


# ---------------------------------------------------------------------------
# PATCH /auth/profile
# ---------------------------------------------------------------------------


@router.patch(
    "/profile",
    response_model=UserResponse,
    summary="Update current user profile",
)
async def update_profile(
    request: Request,
    body: ProfileUpdateRequest,
    identity: Annotated[IdentityContext, Depends(get_current_identity)],
) -> UserResponse:
    """Update active user profile (display name, username, avatar photo)."""
    store = get_user_store()
    # Multi-tier lookup: subject UUID (stable across renames), username claim, or subject as username
    username_claim = identity.attributes.get("username")
    account = (
        store.get_user_by_id(identity.subject)
        or (store.get_user_by_username(username_claim) if username_claim else None)
        or store.get_user_by_username(identity.subject)
    )
    user_lookup = account.user_id if account else identity.subject
    client_ip = request.client.host if request.client else "unknown"
    actor = identity.attributes.get("username", identity.subject)

    try:
        account = store.update_user_profile(
            user_id_or_username=user_lookup,
            display_name=body.display_name,
            new_username=body.username,
            avatar_url=body.avatar_url,
            actor=actor,
            client_ip=client_ip,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e

    return UserResponse(
        user_id=account.user_id,
        username=account.username,
        display_name=account.display_name,
        email=account.email,
        role=account.role,
        status=account.status.value,
        tenant_id=account.tenant_id,
        created_at=account.created_at,
        last_login_at=account.last_login_at,
        login_count=account.login_count,
    )


# ---------------------------------------------------------------------------
# POST /auth/change-password
# ---------------------------------------------------------------------------


@router.post(
    "/change-password",
    summary="Change current user password",
)
async def change_password_endpoint(
    request: Request,
    body: PasswordChangeRequest,
    identity: Annotated[IdentityContext, Depends(get_current_identity)],
) -> dict[str, Any]:
    """Change authenticated user password with current password verification."""
    store = get_user_store()
    client_ip = request.client.host if request.client else "unknown"

    username_claim = identity.attributes.get("username")
    account = (
        store.get_user_by_id(identity.subject)
        or (store.get_user_by_username(username_claim) if username_claim else None)
        or store.get_user_by_username(identity.subject)
    )
    user_lookup = account.user_id if account else identity.subject

    try:
        store.change_password(
            user_id_or_username=user_lookup,
            current_password=body.current_password,
            new_password=body.new_password,
            client_ip=client_ip,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e

    return {"status": "success", "message": "Password modified successfully"}
