/**
 * AccessDeniedPage — 403 Formal Denial Screen
 *
 * Shown when an authenticated user attempts to access a route
 * they do not have sufficient permissions or role to access.
 * Provides clear context about current role vs. required access.
 */

import React from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { ArrowLeft, ShieldOff } from 'lucide-react';
import { useAuth } from '../../auth/AuthProvider';

export const AccessDeniedPage: React.FC = () => {
  const { user } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const state = location.state as {
    requiredPermission?: string;
    requiredRole?: string;
    allowedRoles?: string[];
    from?: { pathname: string };
  } | null;

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col items-center justify-center px-4">
      <div className="max-w-lg w-full">
        {/* Header */}
        <div className="flex flex-col items-center text-center mb-8">
          <div className="w-16 h-16 rounded-lg bg-red-50 border border-red-200 flex items-center justify-center mb-4">
            <ShieldOff className="w-8 h-8 text-red-600" />
          </div>
          <div className="text-[10px] font-mono font-bold text-red-600 uppercase tracking-widest mb-2">
            HTTP 403 — Access Denied
          </div>
          <h1 className="text-xl font-bold text-navy-900 leading-tight">
            Insufficient Access Privileges
          </h1>
          <p className="text-sm text-slate-500 mt-2">
            Your current role does not grant access to the requested resource.
            Contact a Platform Administrator to request elevated privileges.
          </p>
        </div>

        {/* Detail Card */}
        <div className="bg-white border border-slate-200 rounded-lg overflow-hidden shadow-sm mb-6">
          <div className="px-4 py-3 bg-slate-50 border-b border-slate-100">
            <span className="text-xs font-bold text-navy-900 uppercase tracking-wider">
              Access Denial Report
            </span>
          </div>
          <div className="px-4 py-4 space-y-3">
            <Row label="Authenticated User" value={user?.displayName ?? user?.username ?? '—'} />
            <Row label="Current Role" value={user?.role ?? '—'} mono />
            <Row label="Tenant" value={user?.tenantId ?? '—'} mono />

            {state?.requiredPermission && (
              <Row
                label="Required Permission"
                value={state.requiredPermission}
                mono
                highlight
              />
            )}
            {state?.requiredRole && (
              <Row label="Required Role" value={state.requiredRole} mono highlight />
            )}
            {state?.allowedRoles && state.allowedRoles.length > 1 && (
              <Row
                label="Allowed Roles"
                value={state.allowedRoles.join(', ')}
                mono
                highlight
              />
            )}
            {state?.from?.pathname && (
              <Row label="Attempted Path" value={state.from.pathname} mono />
            )}
          </div>
        </div>

        {/* Actions */}
        <div className="flex flex-col sm:flex-row gap-2">
          <button
            id="access-denied-back"
            type="button"
            onClick={() => navigate(-1)}
            className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 border border-slate-300 text-slate-700 text-sm font-medium rounded hover:bg-slate-50 transition-colors"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            Go Back
          </button>
          <button
            id="access-denied-home"
            type="button"
            onClick={() => navigate('/command-center', { replace: true })}
            className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 bg-navy-900 text-white text-sm font-medium rounded hover:bg-navy-800 transition-colors"
          >
            Return to Command Center
          </button>
        </div>

        <p className="text-center text-[10px] text-slate-400 font-mono mt-6">
          This access denial has been logged in the Security Audit Trail.
        </p>
      </div>
    </div>
  );
};

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

function Row({
  label,
  value,
  mono = false,
  highlight = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
  highlight?: boolean;
}) {
  return (
    <div className="flex items-start justify-between gap-4">
      <span className="text-xs text-slate-500 flex-shrink-0 pt-0.5">{label}</span>
      <span
        className={`text-xs font-semibold text-right ${
          mono ? 'font-mono' : ''
        } ${
          highlight ? 'text-red-700 bg-red-50 px-1.5 py-0.5 rounded' : 'text-navy-900'
        }`}
      >
        {value}
      </span>
    </div>
  );
}
