/**
 * ProtectedRoute
 *
 * Guards any route that requires authentication.
 * Redirects unauthenticated users to /login, preserving the
 * intended destination in location state for post-login redirect.
 */

import React from 'react';
import { Navigate, Outlet, useLocation } from 'react-router-dom';
import { useAuth } from './AuthProvider';

interface ProtectedRouteProps {
  /** Optional fallback redirect path (default: /login) */
  redirectTo?: string;
}

export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({
  redirectTo = '/login',
}) => {
  const { isAuthenticated, isLoading } = useAuth();
  const location = useLocation();

  // If already authenticated, render immediately — don't block on isLoading.
  // This prevents the full-screen spinner flash right after login.
  if (isAuthenticated) {
    return <Outlet />;
  }

  // Not yet authenticated: block rendering until the initial session
  // hydration check completes (prevents briefly flashing /login).
  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-screen bg-slate-50">
        <div className="flex flex-col items-center gap-3">
          <div className="w-8 h-8 border-2 border-gov-blue border-t-transparent rounded-full animate-spin" />
          <span className="text-xs text-slate-500 font-mono">Verifying session…</span>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <Navigate
        to={redirectTo}
        state={{ from: location }}
        replace
      />
    );
  }

  return <Outlet />;
};
