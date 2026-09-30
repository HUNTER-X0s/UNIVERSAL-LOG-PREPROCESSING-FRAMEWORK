/**
 * Typed API client for ULPF Auth endpoints.
 *
 * All requests include the Bearer token from session storage.
 * Base URL is read from VITE_API_BASE_URL or defaults to http://localhost:8000/api/v1
 */

import type {
  AuditEntryDTO,
  CreateUserRequest,
  LoginCredentials,
  LoginResponseDTO,
  MeResponseDTO,
  RoleInfoDTO,
  UpdateRoleRequest,
  UserDTO,
} from '../auth/auth.types';

const API_BASE = (import.meta as any).env?.VITE_API_BASE_URL ?? 'http://localhost:8000/api/v1';

// ---------------------------------------------------------------------------
// HTTP helper
// ---------------------------------------------------------------------------

class AuthApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly detail: string,
  ) {
    super(detail);
    this.name = 'AuthApiError';
  }
}

async function apiFetch<T>(
  path: string,
  options: RequestInit = {},
  token?: string | null,
): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    let detail = `HTTP ${response.status}`;
    try {
      const body = await response.json();
      if (typeof body === 'string') {
        detail = body;
      } else if (body && typeof body === 'object') {
        detail =
          body.message ||
          body.detail ||
          body.error ||
          (response.status === 401
            ? 'Authentication failed. Invalid username or password.'
            : `HTTP ${response.status}`);
      }
    } catch {
      /* ignore */
    }
    throw new AuthApiError(response.status, detail);
  }

  // 204 No Content
  if (response.status === 204) {
    return undefined as unknown as T;
  }

  return response.json() as Promise<T>;
}

// ---------------------------------------------------------------------------
// Auth endpoints
// ---------------------------------------------------------------------------

/** POST /auth/login → LoginResponseDTO */
export async function apiLogin(credentials: LoginCredentials): Promise<LoginResponseDTO> {
  return apiFetch<LoginResponseDTO>('/auth/login', {
    method: 'POST',
    body: JSON.stringify({
      username: credentials.username,
      password: credentials.password,
    }),
  });
}

/** GET /auth/me → MeResponseDTO */
export async function apiGetMe(token: string): Promise<MeResponseDTO> {
  return apiFetch<MeResponseDTO>('/auth/me', { method: 'GET' }, token);
}

/** POST /auth/logout */
export async function apiLogout(token: string): Promise<void> {
  return apiFetch<void>('/auth/logout', { method: 'POST' }, token);
}

/** GET /auth/users → UserDTO[] */
export async function apiListUsers(token: string): Promise<UserDTO[]> {
  return apiFetch<UserDTO[]>('/auth/users', { method: 'GET' }, token);
}

/** POST /auth/users → UserDTO */
export async function apiCreateUser(token: string, payload: CreateUserRequest): Promise<UserDTO> {
  return apiFetch<UserDTO>(
    '/auth/users',
    {
      method: 'POST',
      body: JSON.stringify(payload),
    },
    token,
  );
}

/** PUT /auth/users/{userId}/role → UserDTO */
export async function apiUpdateUserRole(
  token: string,
  userId: string,
  payload: UpdateRoleRequest,
): Promise<UserDTO> {
  return apiFetch<UserDTO>(
    `/auth/users/${userId}/role`,
    {
      method: 'PUT',
      body: JSON.stringify(payload),
    },
    token,
  );
}

/** GET /auth/roles → RoleInfoDTO[] */
export async function apiListRoles(token?: string | null): Promise<RoleInfoDTO[]> {
  return apiFetch<RoleInfoDTO[]>('/auth/roles', { method: 'GET' }, token);
}

/** GET /auth/audit → AuditEntryDTO[] */
export async function apiGetAuditLog(
  token: string,
  limit = 100,
): Promise<AuditEntryDTO[]> {
  return apiFetch<AuditEntryDTO[]>(`/auth/audit?limit=${limit}`, { method: 'GET' }, token);
}

/** PATCH /auth/profile → UserDTO */
export async function apiUpdateProfile(
  token: string,
  payload: { display_name?: string; username?: string; avatar_url?: string },
): Promise<UserDTO> {
  return apiFetch<UserDTO>(
    '/auth/profile',
    {
      method: 'PATCH',
      body: JSON.stringify(payload),
    },
    token,
  );
}

/** POST /auth/change-password → { status: string; message: string } */
export async function apiChangePassword(
  token: string,
  currentPassword: string,
  newPassword: string,
): Promise<{ status: string; message: string }> {
  return apiFetch<{ status: string; message: string }>(
    '/auth/change-password',
    {
      method: 'POST',
      body: JSON.stringify({
        current_password: currentPassword,
        new_password: newPassword,
      }),
    },
    token,
  );
}

export { AuthApiError };
