/**
 * ULPF Authentication & RBAC Type Definitions
 *
 * Strictly typed interfaces that mirror the backend security model:
 *   - ulpf_security.policy.Permission (StrEnum)
 *   - ulpf_security.policy.ROLE_PERMISSIONS_MATRIX
 *   - ulpf_api.routes.auth (LoginResponse, UserResponse, etc.)
 */

// ---------------------------------------------------------------------------
// Permissions — mirrors ulpf_security.policy.Permission
// ---------------------------------------------------------------------------

export type Permission =
  | 'event.read'
  | 'event.search'
  | 'event.ingest'
  | 'raw.read'
  | 'uce.read'
  | 'semantic.read'
  | 'dlq.read'
  | 'dlq.replay'
  | 'replay.execute'
  | 'mapping.read'
  | 'mapping.approve'
  | 'mapping.activate'
  | 'mapping.rollback'
  | 'config.read'
  | 'config.modify'
  | 'retention.modify'
  | 'admin.manage'
  | 'intelligence.read'
  | 'intelligence.hunt'
  | 'intelligence.investigate'
  | 'detection.manage'
  | 'rule.review'
  | 'rule.activate'
  | 'case.write';

// ---------------------------------------------------------------------------
// Roles — mirrors ROLE_PERMISSIONS_MATRIX keys
// ---------------------------------------------------------------------------

export type Role =
  | 'viewer'
  | 'operator'
  | 'analyst'
  | 'threat-hunter'
  | 'detection-engineer'
  | 'ingest-service'
  | 'mapping-reviewer'
  | 'mapping-admin'
  | 'platform-admin';

// ---------------------------------------------------------------------------
// User model
// ---------------------------------------------------------------------------

export interface User {
  userId: string;
  username: string;
  displayName: string;
  email: string;
  role: Role;
  tenantId: string;
  status: 'active' | 'suspended' | 'locked';
  createdAt: string;
  lastLoginAt: string | null;
  loginCount: number;
  avatarUrl?: string | null;
}

// ---------------------------------------------------------------------------
// Auth session (stored in React context)
// ---------------------------------------------------------------------------

export interface AuthSession {
  token: string;
  tokenType: string;
  expiresIn: number;
  issuedAt: number; // unix timestamp
  user: User;
  permissions: Permission[];
}

// ---------------------------------------------------------------------------
// Login credentials
// ---------------------------------------------------------------------------

export interface LoginCredentials {
  username: string;
  password: string;
}

// ---------------------------------------------------------------------------
// API response shapes (match backend Pydantic schemas)
// ---------------------------------------------------------------------------

export interface LoginResponseDTO {
  token: string;
  token_type: string;
  expires_in: number;
  user_id: string;
  username: string;
  display_name: string;
  role: string;
  permissions: string[];
  tenant_id: string;
}

export interface MeResponseDTO {
  subject: string;
  issuer: string;
  roles: string[];
  permissions: string[];
  tenant_id: string | null;
  auth_method: string;
  username?: string;
  display_name?: string;
}

export interface UserDTO {
  user_id: string;
  username: string;
  display_name: string;
  email: string;
  role: string;
  status: string;
  tenant_id: string;
  created_at: string;
  last_login_at: string | null;
  login_count: number;
}

export interface RoleInfoDTO {
  role: string;
  description: string;
  permissions: string[];
}

export interface AuditEntryDTO {
  event_id: string;
  event_type: string;
  actor: string;
  tenant_id: string;
  client_ip: string;
  timestamp: string;
  outcome: string;
  detail: string;
  target_user: string | null;
}

export interface CreateUserRequest {
  username: string;
  display_name: string;
  email: string;
  role: string;
  password: string;
  tenant_id?: string;
}

export interface UpdateRoleRequest {
  role: string;
}

// ---------------------------------------------------------------------------
// Auth context interface
// ---------------------------------------------------------------------------

export interface AuthContextValue {
  /** Authenticated user or null if no session */
  user: User | null;
  /** Active role or null */
  role: Role | null;
  /** Set of effective permissions */
  permissions: Set<Permission>;
  /** Current tenant ID */
  tenantId: string;
  /** Whether user is authenticated and session is valid */
  isAuthenticated: boolean;
  /** Whether initial auth check is in progress */
  isLoading: boolean;
  /** Authentication error message if last login failed */
  loginError: string | null;
  /** Login with username and password */
  login: (credentials: LoginCredentials) => Promise<void>;
  /** Clear session and redirect to /login */
  logout: () => void;
  /** Check if user has a specific permission */
  hasPermission: (permission: Permission) => boolean;
  /** Check if user has a specific role */
  hasRole: (role: Role) => boolean;
  /** Check if user can access a tenant */
  canAccessTenant: (tenantId: string) => boolean;
  /** Current raw JWT token for API calls */
  token: string | null;
  /** Update user profile (display name, username, avatar photo) */
  updateUserProfile: (updates: Partial<User>) => Promise<{ success: boolean; error?: string }>;
  /** Change user password */
  changePassword: (currentPassword: string, newPassword: string) => Promise<{ success: boolean; error?: string }>;
}

// ---------------------------------------------------------------------------
// Authorized platform accounts (for role-selector on login page — not public-facing)
// ---------------------------------------------------------------------------

export interface AuthorizedAccount {
  username: string;
  displayName: string;
  role: Role;
  department: string;
}

export const AUTHORIZED_ACCOUNTS: AuthorizedAccount[] = [
  {
    username: 'arunav.sharma',
    displayName: 'Arunav Sharma',
    role: 'analyst',
    department: 'Security Intelligence',
  },
  {
    username: 'priya.kapoor',
    displayName: 'Priya Kapoor',
    role: 'viewer',
    department: 'Read-Only Access',
  },
  {
    username: 'rahul.mehta',
    displayName: 'Rahul Mehta',
    role: 'operator',
    department: 'Operations & Ingest',
  },
  {
    username: 'tanveer.nair',
    displayName: 'Tanveer Nair',
    role: 'threat-hunter',
    department: 'Threat Intelligence',
  },
  {
    username: 'anurag.swain',
    displayName: 'ANURAG SWAIN',
    role: 'platform-admin',
    department: 'Platform Administration',
  },
];

