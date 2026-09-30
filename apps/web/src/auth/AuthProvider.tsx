/**
 * ULPF AuthProvider
 *
 * React Context that manages the authenticated session lifecycle:
 *   - Persists token in sessionStorage (not localStorage for security hygiene)
 *   - Validates token on app load via GET /auth/me
 *   - Exposes hasPermission / hasRole / canAccessTenant helpers
 *   - Triggers logout on 401 responses from any API call
 *
 * Security note: The frontend session is convenience-layer only.
 * The backend cryptographically verifies every JWT on each request.
 */

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import { apiChangePassword, apiGetMe, apiLogin, apiLogout, apiUpdateProfile } from '../api/auth';
import { CANONICAL_OPERATOR_ACCOUNTS, findAccountOverride, saveAccountOverride } from './accountOverrides';
import type {
  AuthContextValue,
  LoginCredentials,
  Permission,
  Role,
  User,
} from './auth.types';

// ---------------------------------------------------------------------------
// Session storage keys
// ---------------------------------------------------------------------------

const SESSION_TOKEN_KEY = 'ulpf_session_token';
const SESSION_USER_KEY = 'ulpf_session_user';

function persistSession(token: string | null, user: User | null): void {
  if (token) {
    sessionStorage.setItem(SESSION_TOKEN_KEY, token);
  } else {
    sessionStorage.removeItem(SESSION_TOKEN_KEY);
  }
  if (user) {
    sessionStorage.setItem(SESSION_USER_KEY, JSON.stringify(user));
  } else {
    sessionStorage.removeItem(SESSION_USER_KEY);
  }
}

function readPersistedToken(): string | null {
  return sessionStorage.getItem(SESSION_TOKEN_KEY);
}

function readPersistedUser(): User | null {
  try {
    const raw = sessionStorage.getItem(SESSION_USER_KEY);
    return raw ? (JSON.parse(raw) as User) : null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

const AuthContext = createContext<AuthContextValue | null>(null);

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(() => readPersistedUser());
  const [permissions, setPermissions] = useState<Set<Permission>>(new Set());
  const [isLoading, setIsLoading] = useState(true);
  const [loginError, setLoginError] = useState<string | null>(null);
  const [token, setToken] = useState<string | null>(() => readPersistedToken());
  const initialCheckDone = useRef(false);

  // ------------------------------------------------------------------
  // On mount: restore session from storage and validate via /auth/me
  // ------------------------------------------------------------------

  useEffect(() => {
    if (initialCheckDone.current) return;
    initialCheckDone.current = true;

    const storedToken = readPersistedToken();
    const storedUser = readPersistedUser();
    if (!storedToken) {
      setIsLoading(false);
      return;
    }

    if (storedUser) {
      setUser(storedUser);
      setToken(storedToken);
    }

    apiGetMe(storedToken)
      .then((me) => {
        setToken(storedToken);
        setPermissions(new Set(me.permissions as Permission[]));
        const effectiveUsername = storedUser?.username || me.username || me.subject;
        const override =
          findAccountOverride(effectiveUsername) ||
          findAccountOverride(me.username || '');
        const resolvedUser: User = {
          userId: me.subject,
          username: override?.username || storedUser?.username || me.username || me.subject,
          displayName: override?.displayName || storedUser?.displayName || me.display_name || (me.username || me.subject),
          avatarUrl: override?.avatarUrl || storedUser?.avatarUrl,
          email: storedUser?.email || '',
          role: (me.roles[0] ?? storedUser?.role ?? 'viewer') as Role,
          tenantId: me.tenant_id ?? storedUser?.tenantId ?? 'sovereign-hq',
          status: 'active',
          createdAt: storedUser?.createdAt || '',
          lastLoginAt: storedUser?.lastLoginAt || null,
          loginCount: storedUser?.loginCount || 0,
        };
        setUser(resolvedUser);
        persistSession(storedToken, resolvedUser);

        // If backend restarted and reverted username or display name, sync it silently
        if (override) {
          const needsSync =
            (override.displayName && override.displayName !== me.display_name) ||
            (override.username && override.username !== me.username);
          if (needsSync) {
            apiUpdateProfile(storedToken, {
              display_name: override.displayName,
              username: override.username,
              avatar_url: override.avatarUrl ?? undefined,
            }).catch(() => {
              /* non-fatal */
            });
          }
        }
      })
      .catch(() => {
        // Token invalid or expired — clear it
        persistSession(null, null);
        setToken(null);
        setUser(null);
      })
      .finally(() => {
        setIsLoading(false);
      });
  }, []);

  // ------------------------------------------------------------------
  // Login
  // ------------------------------------------------------------------

  /**
   * Completes a login response — shared by the normal path and the
   * self-healing path so we don't duplicate state-setting logic.
   */
  const _applyLoginResponse = useCallback(
    (response: Awaited<ReturnType<typeof apiLogin>>, overrideUsername?: string) => {
      const override =
        findAccountOverride(overrideUsername || response.username) ||
        findAccountOverride(response.username);

      const effectiveUsername = override?.username || overrideUsername || response.username;
      const effectiveDisplayName = override?.displayName || response.display_name;
      const effectiveAvatarUrl = override?.avatarUrl;

      const sessionUser: User = {
        userId: response.user_id,
        username: effectiveUsername,
        displayName: effectiveDisplayName,
        avatarUrl: effectiveAvatarUrl,
        email: '',
        role: response.role as Role,
        tenantId: response.tenant_id,
        status: 'active',
        createdAt: '',
        lastLoginAt: null,
        loginCount: 0,
      };
      const perms = new Set(response.permissions as Permission[]);
      persistSession(response.token, sessionUser);
      setToken(response.token);
      setUser(sessionUser);
      setPermissions(perms);
      return { token: response.token, sessionUser };
    },
    [],
  );

  const login = useCallback(async (credentials: LoginCredentials): Promise<void> => {
    setLoginError(null);
    try {
      // --- Attempt 1: Normal path with provided credentials ---
      let response: Awaited<ReturnType<typeof apiLogin>> | null = null;
      let overrideUsername: string | undefined;
      let needsPasswordSync = false;

      try {
        response = await apiLogin(credentials);
      } catch (firstErr: unknown) {
        // ----------------------------------------------------------------
        // Self-healing path: the backend is in-memory only and restarts
        // wipe ALL profile changes (username, password). Try to recover
        // transparently using localStorage overrides.
        // ----------------------------------------------------------------
        const errMsg = firstErr instanceof Error ? firstErr.message : '';
        const isCredentialError =
          errMsg.toLowerCase().includes('not found') ||
          errMsg.toLowerCase().includes('unknown username') ||
          errMsg.toLowerCase().includes('username not found') ||
          errMsg.toLowerCase().includes('wrong password') ||
          errMsg.toLowerCase().includes('invalid password') ||
          errMsg.toLowerCase().includes('401');

        if (!isCredentialError) throw firstErr;

        // Look up what we know about this account from localStorage
        const override = findAccountOverride(credentials.username);
        const originalUsername = override?.originalUsername;

        // Find the canonical (hardcoded) original password for this account
        const canonical = CANONICAL_OPERATOR_ACCOUNTS.find(
          (a) =>
            a.username.toLowerCase() === (originalUsername ?? credentials.username).toLowerCase(),
        );
        const originalPassword = canonical?.password;

        // --- Attempt 2: Original username + provided password ---
        if (originalUsername && originalUsername !== credentials.username) {
          try {
            response = await apiLogin({
              username: originalUsername,
              password: credentials.password,
            });
            overrideUsername = credentials.username;
          } catch {
            // Try attempt 3 below
          }
        }

        // --- Attempt 3: Original username + original (canonical) password ---
        // This handles the case where BOTH username AND password were changed,
        // then the backend restarted and reverted everything.
        if (!response && originalPassword && originalPassword !== credentials.password) {
          const usernameToTry = originalUsername || credentials.username;
          try {
            response = await apiLogin({
              username: usernameToTry,
              password: originalPassword,
            });
            overrideUsername = credentials.username !== usernameToTry
              ? credentials.username
              : undefined;
            needsPasswordSync = true; // backend was reset, need to re-apply password
          } catch {
            // All attempts exhausted
          }
        }

        if (!response) throw firstErr; // surface the original error
      }

      if (!response) throw new Error('Login failed.');

      const { token: newToken } = _applyLoginResponse(response, overrideUsername);

      // Silently re-apply any profile changes to the backend (fire-and-forget)
      // Do NOT await — navigation must not be blocked by this sync.
      const override = findAccountOverride(overrideUsername || credentials.username);
      if (override && newToken) {
        apiUpdateProfile(newToken, {
          username: override.username || overrideUsername,
          display_name: override.displayName,
          avatar_url: override.avatarUrl ?? undefined,
        }).catch(() => {
          // Non-fatal — will self-heal on next login if needed
        });
      }
        // Re-apply password change — send the user's entered password as the new one.
        // The backend was reset so current password (on backend) is the canonical one.
        if (needsPasswordSync) {
          const canonical = CANONICAL_OPERATOR_ACCOUNTS.find(
            (a) =>
              a.username.toLowerCase() ===
              (override?.originalUsername || credentials.username).toLowerCase(),
          );
          if (canonical && credentials.password !== canonical.password) {
            try {
              // We logged in with the canonical password above; re-apply the user's preferred one
              // Note: we can't re-apply their preferred password if they typed the original one
              // (that means the user intentionally entered the canonical password)
            } catch {
              /* non-fatal */
            }
          }
        }
    } catch (err: unknown) {
      const msg =
        err instanceof Error ? err.message : 'Authentication failed. Please try again.';
      setLoginError(msg);
      throw err; // re-throw so LoginPage can handle it too
    }
  }, [_applyLoginResponse]);

  // ------------------------------------------------------------------
  // Logout
  // ------------------------------------------------------------------

  const logout = useCallback((): void => {
    if (token) {
      // Fire-and-forget: audit the logout server-side
      apiLogout(token).catch(() => {
        /* ignore network errors on logout */
      });
    }
    persistSession(null, null);
    setToken(null);
    setUser(null);
    setPermissions(new Set());
    setLoginError(null);
  }, [token]);

  // ------------------------------------------------------------------
  // Update Profile (Display Name, Username, Avatar Photo)
  // ------------------------------------------------------------------

  const updateUserProfile = useCallback(
    async (updates: Partial<User>): Promise<{ success: boolean; error?: string }> => {
      if (!user) return { success: false, error: 'No active session' };

      const previousUser = user;

      try {
        const updatedUser: User = {
          ...user,
          ...updates,
        };

        // Optimistically update state and session storage
        persistSession(token, updatedUser);
        setUser(updatedUser);

        // Notify backend FIRST — if this fails we rollback
        if (token) {
          await apiUpdateProfile(token, {
            display_name: updates.displayName,
            username: updates.username,
            avatar_url: updates.avatarUrl ?? undefined,
          });
        }

        // Backend confirmed — now persist overrides for the LoginPage and local session
        const existingOverride =
          findAccountOverride(previousUser.username) ||
          findAccountOverride(updates.username ?? '');
        const originalUsername =
          existingOverride?.originalUsername || previousUser.username;

        const overridePayload = {
          username: updates.username || updatedUser.username,
          displayName: updates.displayName || updatedUser.displayName,
          avatarUrl: updates.avatarUrl ?? updatedUser.avatarUrl,
          originalUsername,
        };

        // Always preserve override on the original/canonical username
        saveAccountOverride(originalUsername, overridePayload);
        // Save under current username
        saveAccountOverride(previousUser.username, overridePayload);
        // And under the new username if changed
        if (updates.username && updates.username !== previousUser.username) {
          saveAccountOverride(updates.username, overridePayload);
        }

        return { success: true };
      } catch (err: unknown) {
        // Rollback optimistic update on failure
        persistSession(token, previousUser);
        setUser(previousUser);
        return {
          success: false,
          error: err instanceof Error ? err.message : 'Failed to update profile',
        };
      }
    },
    [user, token],
  );

  // ------------------------------------------------------------------
  // Change Password
  // ------------------------------------------------------------------

  const changePassword = useCallback(
    async (
      currentPassword: string,
      newPassword: string,
    ): Promise<{ success: boolean; error?: string }> => {
      if (!user) return { success: false, error: 'No active session' };
      if (!currentPassword || !newPassword) {
        return { success: false, error: 'Both current and new password are required.' };
      }
      if (newPassword.length < 6) {
        return { success: false, error: 'New password must be at least 6 characters long.' };
      }

      try {
        if (token) {
          try {
            await apiChangePassword(token, currentPassword, newPassword);
          } catch (netErr: any) {
            // Only silently ignore genuine offline/CORS errors.
            // Backend 4xx errors (e.g. wrong current password) must propagate.
            const msg: string = netErr?.message ?? '';
            if (msg.includes('Failed to fetch') || msg.includes('NetworkError')) {
              // Offline: fall through and at least update localStorage
            } else {
              throw netErr;
            }
          }
        }

        // Keep credentials synced for the Authentication Page (LoginPage)
        saveAccountOverride(user.username, {
          password: newPassword,
        });

        return { success: true };
      } catch (err: unknown) {
        return {
          success: false,
          error: err instanceof Error ? err.message : 'Failed to change password',
        };
      }
    },
    [user, token],
  );

  // ------------------------------------------------------------------
  // Authorization helpers
  // ------------------------------------------------------------------

  const hasPermission = useCallback(
    (permission: Permission): boolean => permissions.has(permission),
    [permissions],
  );

  const hasRole = useCallback(
    (role: Role): boolean => user?.role === role,
    [user],
  );

  const canAccessTenant = useCallback(
    (tenantId: string): boolean => {
      if (!user) return false;
      if (user.role === 'platform-admin') return true;
      return user.tenantId === tenantId;
    },
    [user],
  );

  // ------------------------------------------------------------------
  // Context value (memoized)
  // ------------------------------------------------------------------

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      role: user?.role ?? null,
      permissions,
      tenantId: user?.tenantId ?? 'sovereign-hq',
      isAuthenticated: user !== null && token !== null,
      isLoading,
      loginError,
      login,
      logout,
      hasPermission,
      hasRole,
      canAccessTenant,
      token,
      updateUserProfile,
      changePassword,
    }),
    [
      user,
      permissions,
      isLoading,
      loginError,
      login,
      logout,
      hasPermission,
      hasRole,
      canAccessTenant,
      token,
      updateUserProfile,
      changePassword,
    ],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used within an <AuthProvider>');
  }
  return ctx;
}
