/**
 * AuthAuditPage — Security Audit Trail
 *
 * Displays authentication and privilege change events from /auth/audit.
 * Requires: admin.manage permission (platform-admin role)
 *
 * Events include: login attempts, logouts, role changes, user creation.
 */

import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  AlertTriangle,
  CheckCircle,
  Clock,
  FileText,
  RefreshCw,
  Search,
  Shield,
  XCircle,
} from 'lucide-react';
import { useAuth } from '../../auth/AuthProvider';
import { apiGetAuditLog } from '../../api/auth';
import type { AuditEntryDTO } from '../../auth/auth.types';

const EVENT_TYPE_LABELS: Record<string, string> = {
  login_success: 'Login Success',
  login_failure: 'Login Failure',
  logout: 'Logout',
  role_change: 'Role Change',
  user_created: 'User Created',
  user_suspended: 'User Suspended',
  password_reset: 'Password Reset',
  token_revoked: 'Token Revoked',
};

const EVENT_STYLES: Record<string, { bg: string; text: string; border: string }> = {
  login_success: { bg: 'bg-emerald-50', text: 'text-emerald-700', border: 'border-emerald-200' },
  login_failure: { bg: 'bg-red-50', text: 'text-red-700', border: 'border-red-200' },
  logout: { bg: 'bg-slate-50', text: 'text-slate-600', border: 'border-slate-200' },
  role_change: { bg: 'bg-amber-50', text: 'text-amber-700', border: 'border-amber-200' },
  user_created: { bg: 'bg-blue-50', text: 'text-blue-700', border: 'border-blue-200' },
  user_suspended: { bg: 'bg-orange-50', text: 'text-orange-700', border: 'border-orange-200' },
  password_reset: { bg: 'bg-indigo-50', text: 'text-indigo-700', border: 'border-indigo-200' },
  token_revoked: { bg: 'bg-purple-50', text: 'text-purple-700', border: 'border-purple-200' },
};

export const AuthAuditPage: React.FC = () => {
  const { token } = useAuth();
  const [search, setSearch] = useState('');
  const [outcomeFilter, setOutcomeFilter] = useState<'all' | 'success' | 'failure'>('all');
  const [limit, setLimit] = useState(100);

  const { data: entries = [], isLoading, error, refetch } = useQuery({
    queryKey: ['auth', 'audit', limit],
    queryFn: () => apiGetAuditLog(token!, limit),
    enabled: !!token,
    refetchInterval: 30_000, // auto-refresh every 30s
  });

  const filtered = entries.filter((e) => {
    const matchSearch =
      !search ||
      e.actor.toLowerCase().includes(search.toLowerCase()) ||
      e.event_type.toLowerCase().includes(search.toLowerCase()) ||
      e.detail.toLowerCase().includes(search.toLowerCase());
    const matchOutcome =
      outcomeFilter === 'all' || e.outcome === outcomeFilter;
    return matchSearch && matchOutcome;
  });

  const successCount = entries.filter((e) => e.outcome === 'success').length;
  const failureCount = entries.filter((e) => e.outcome === 'failure').length;

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-base font-bold text-navy-900 flex items-center gap-2">
            <Shield className="w-4 h-4" />
            Authentication Audit Trail
          </h1>
          <p className="text-xs text-slate-500 mt-0.5">
            Immutable security audit log for authentication and privilege events
          </p>
        </div>
        <button
          type="button"
          onClick={() => refetch()}
          className="p-2 text-slate-500 hover:text-navy-900 hover:bg-slate-100 rounded transition-colors"
          title="Refresh"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {/* Summary stats */}
      <div className="grid grid-cols-3 gap-3">
        <StatCard label="Total Events" value={entries.length.toString()} icon={<FileText className="w-4 h-4 text-slate-400" />} />
        <StatCard label="Successful" value={successCount.toString()} icon={<CheckCircle className="w-4 h-4 text-emerald-500" />} />
        <StatCard label="Failures" value={failureCount.toString()} icon={<XCircle className="w-4 h-4 text-red-500" />} />
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <div className="relative">
          <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-slate-400">
            <Search className="w-3.5 h-3.5" />
          </div>
          <input
            type="text"
            placeholder="Search events…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{ paddingLeft: '36px' }}
            className="pr-3 py-1.5 text-xs bg-white border border-slate-300 rounded-lg focus:outline-none focus:ring-1 focus:ring-gov-blue w-64 transition-all"
          />
        </div>
        <div className="flex rounded overflow-hidden border border-slate-200">
          {(['all', 'success', 'failure'] as const).map((v) => (
            <button
              key={v}
              type="button"
              onClick={() => setOutcomeFilter(v)}
              className={`px-3 py-1.5 text-xs font-semibold capitalize transition-colors ${
                outcomeFilter === v
                  ? 'bg-navy-900 text-white'
                  : 'bg-white text-slate-600 hover:bg-slate-50'
              }`}
            >
              {v}
            </button>
          ))}
        </div>
        <select
          value={limit}
          onChange={(e) => setLimit(Number(e.target.value))}
          className="px-3 py-1.5 text-xs bg-white border border-slate-300 rounded focus:outline-none focus:ring-1 focus:ring-gov-blue"
        >
          <option value={50}>Last 50</option>
          <option value={100}>Last 100</option>
          <option value={250}>Last 250</option>
          <option value={500}>Last 500</option>
        </select>
      </div>

      {/* Audit log */}
      <div className="bg-white border border-slate-200 rounded-lg shadow-sm overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <div className="w-6 h-6 border-2 border-gov-blue border-t-transparent rounded-full animate-spin" />
          </div>
        ) : error ? (
          <div className="flex items-center justify-center py-12 gap-2 text-red-600 text-sm">
            <AlertTriangle className="w-4 h-4" />
            Failed to load audit log. Ensure you have admin.manage permission.
          </div>
        ) : (
          <div className="divide-y divide-slate-50">
            {filtered.map((entry) => (
              <AuditRow key={entry.event_id} entry={entry} />
            ))}
            {filtered.length === 0 && (
              <div className="text-center py-8 text-slate-400 text-xs">
                No audit events match the current filters.
              </div>
            )}
          </div>
        )}
        <div className="px-4 py-2 bg-slate-50 border-t border-slate-100 text-[10px] text-slate-400 font-mono">
          Showing {filtered.length} of {entries.length} events · Auto-refresh every 30s
        </div>
      </div>
    </div>
  );
};

// ---------------------------------------------------------------------------
// AuditRow
// ---------------------------------------------------------------------------

function AuditRow({ entry }: { entry: AuditEntryDTO }) {
  const style =
    EVENT_STYLES[entry.event_type] ?? {
      bg: 'bg-slate-50',
      text: 'text-slate-600',
      border: 'border-slate-200',
    };
  const label = EVENT_TYPE_LABELS[entry.event_type] ?? entry.event_type;
  const ts = new Date(entry.timestamp).toLocaleString(undefined, {
    dateStyle: 'short',
    timeStyle: 'medium',
  });

  return (
    <div className="flex items-start gap-3 px-4 py-3 hover:bg-slate-50 transition-colors">
      {/* Outcome icon */}
      <div className="mt-0.5 flex-shrink-0">
        {entry.outcome === 'success' ? (
          <CheckCircle className="w-3.5 h-3.5 text-emerald-500" />
        ) : (
          <XCircle className="w-3.5 h-3.5 text-red-500" />
        )}
      </div>

      {/* Content */}
      <div className="flex-1 min-w-0">
        <div className="flex flex-wrap items-center gap-2 mb-0.5">
          <span
            className={`px-1.5 py-0.5 rounded border text-[9px] font-bold uppercase tracking-wider ${style.bg} ${style.text} ${style.border}`}
          >
            {label}
          </span>
          <span className="text-xs font-mono font-semibold text-navy-900">{entry.actor}</span>
          {entry.target_user && entry.target_user !== entry.actor && (
            <>
              <span className="text-slate-300 text-xs">→</span>
              <span className="text-xs font-mono text-slate-600">{entry.target_user}</span>
            </>
          )}
        </div>
        <p className="text-xs text-slate-500 truncate">{entry.detail}</p>
        <div className="flex items-center gap-3 mt-0.5 text-[10px] text-slate-400 font-mono">
          <span className="flex items-center gap-0.5">
            <Clock className="w-2.5 h-2.5" />
            {ts}
          </span>
          <span>IP: {entry.client_ip}</span>
          <span>Tenant: {entry.tenant_id}</span>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// StatCard
// ---------------------------------------------------------------------------

function StatCard({
  label,
  value,
  icon,
}: {
  label: string;
  value: string;
  icon: React.ReactNode;
}) {
  return (
    <div className="bg-white border border-slate-200 rounded-lg px-4 py-3 shadow-sm flex items-center gap-3">
      {icon}
      <div>
        <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">{label}</div>
        <div className="text-xl font-bold text-navy-900 font-mono">{value}</div>
      </div>
    </div>
  );
}
