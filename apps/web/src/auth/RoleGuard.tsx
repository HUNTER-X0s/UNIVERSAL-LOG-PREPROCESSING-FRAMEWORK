/**
 * RoleGuard
 *
 * Guards a route that requires a specific role or permission.
 * Users who are authenticated but lack the required access
 * are redirected to /access-denied with context about what
 * was required.
 */

import React from 'react';
import { Navigate, Outlet, useLocation } from 'react-router-dom';
import { useAuth } from './AuthProvider';
import type { Permission, Role } from './auth.types';

interface RoleGuardProps {
  /** Required role — user must have exactly this role, OR one of the roles in allowedRoles */
  requiredRole?: Role;
  /** Alternative: list of roles that are allowed access */
  allowedRoles?: Role[];
  /** Alternative: required permission (role-based check is preferred for UX) */
  requiredPermission?: Permission;
}

export const RoleGuard: React.FC<RoleGuardProps> = ({
  requiredRole,
  allowedRoles,
  requiredPermission,
}) => {
  const { isAuthenticated, isLoading, hasRole, hasPermission } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-screen bg-slate-50">
        <div className="w-8 h-8 border-2 border-gov-blue border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  // Must be authenticated first
  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // Check permission if specified
  if (requiredPermission && !hasPermission(requiredPermission)) {
    return (
      <Navigate
        to="/access-denied"
        state={{
          from: location,
          requiredPermission,
        }}
        replace
      />
    );
  }

  // Check role if specified
  if (requiredRole && !hasRole(requiredRole)) {
    const allowed = allowedRoles ?? [requiredRole];
    const anyAllowed = allowed.some((r) => hasRole(r));
    if (!anyAllowed) {
      return (
        <Navigate
          to="/access-denied"
          state={{
            from: location,
            requiredRole,
            allowedRoles: allowed,
          }}
          replace
        />
      );
    }
  }

  return <Outlet />;
};
