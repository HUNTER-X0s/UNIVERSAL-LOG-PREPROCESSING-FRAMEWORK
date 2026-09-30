/**
 * RolesPage — Role Catalog & Permission Matrix
 *
 * Displays all registered platform roles with:
 *   - Role descriptions
 *   - Fine-grained permission list organized by domain
 *   - Permission count badge
 *   - Accessible to all authenticated users (read-only)
 */

import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ChevronDown, ChevronRight, KeyRound, Shield } from 'lucide-react';
import { useAuth } from '../../auth/AuthProvider';
import { apiListRoles } from '../../api/auth';
import type { RoleInfoDTO } from '../../auth/auth.types';

const ROLE_COLORS: Record<string, { bg: string; text: string; border: string; dot: string }> = {
  viewer: { bg: 'bg-slate-50', text: 'text-slate-700', border: 'border-slate-200', dot: 'bg-slate-400' },
  operator: { bg: 'bg-blue-50', text: 'text-blue-800', border: 'border-blue-200', dot: 'bg-blue-500' },
  analyst: { bg: 'bg-indigo-50', text: 'text-indigo-800', border: 'border-indigo-200', dot: 'bg-indigo-500' },
  'threat-hunter': { bg: 'bg-amber-50', text: 'text-amber-800', border: 'border-amber-200', dot: 'bg-amber-500' },
  'detection-engineer': { bg: 'bg-purple-50', text: 'text-purple-800', border: 'border-purple-200', dot: 'bg-purple-500' },
  'ingest-service': { bg: 'bg-gray-50', text: 'text-gray-700', border: 'border-gray-200', dot: 'bg-gray-400' },
  'mapping-reviewer': { bg: 'bg-teal-50', text: 'text-teal-800', border: 'border-teal-200', dot: 'bg-teal-500' },
  'mapping-admin': { bg: 'bg-emerald-50', text: 'text-emerald-800', border: 'border-emerald-200', dot: 'bg-emerald-500' },
  'platform-admin': { bg: 'bg-red-50', text: 'text-red-800', border: 'border-red-200', dot: 'bg-red-500' },
};

export const RolesPage: React.FC = () => {
  const { token } = useAuth();
  const [expanded, setExpanded] = useState<string | null>('platform-admin');

  const { data: roles = [], isLoading } = useQuery({
    queryKey: ['auth', 'roles'],
    queryFn: () => apiListRoles(token),
    staleTime: 300_000, // 5 min — role definitions rarely change
  });

  // Sort: platform-admin first, then alphabetical
  const sortedRoles = [...roles].sort((a, b) => {
    if (a.role === 'platform-admin') return -1;
    if (b.role === 'platform-admin') return 1;
    return a.role.localeCompare(b.role);
  });

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div>
        <h1 className="text-base font-bold text-navy-900 flex items-center gap-2">
          <Shield className="w-4 h-4" />
          Role Catalog
        </h1>
        <p className="text-xs text-slate-500 mt-0.5">
          Platform roles and their fine-grained permission assignments
        </p>
      </div>

      {/* Summary */}
      {!isLoading && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <StatCard label="Total Roles" value={roles.length.toString()} />
          <StatCard
            label="Max Permissions"
            value={Math.max(...roles.map((r) => r.permissions.length), 0).toString()}
          />
          <StatCard
            label="Admin Roles"
            value={roles.filter((r) => r.permissions.includes('admin.manage')).length.toString()}
          />
          <StatCard
            label="Unique Permissions"
            value={new Set(roles.flatMap((r) => r.permissions)).size.toString()}
          />
        </div>
      )}

      {/* Role cards */}
      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <div className="w-6 h-6 border-2 border-gov-blue border-t-transparent rounded-full animate-spin" />
        </div>
      ) : (
        <div className="space-y-2">
          {sortedRoles.map((role) => (
            <RoleCard
              key={role.role}
              role={role}
              isExpanded={expanded === role.role}
              onToggle={() => setExpanded(expanded === role.role ? null : role.role)}
            />
          ))}
        </div>
      )}
    </div>
  );
};

// ---------------------------------------------------------------------------
// RoleCard
// ---------------------------------------------------------------------------

function RoleCard({
  role,
  isExpanded,
  onToggle,
}: {
  role: RoleInfoDTO;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  const style = ROLE_COLORS[role.role] ?? ROLE_COLORS.viewer;

  // Group permissions by domain prefix
  const domains = groupPermissions(role.permissions);

  return (
    <div className={`bg-white border rounded-lg overflow-hidden shadow-sm ${style.border}`}>
      {/* Header row */}
      <button
        type="button"
        onClick={onToggle}
        className="w-full flex items-center gap-3 px-4 py-3 hover:bg-slate-50 transition-colors text-left"
        aria-expanded={isExpanded}
      >
        <div className={`w-2 h-2 rounded-full flex-shrink-0 ${style.dot}`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className={`text-xs font-mono font-bold ${style.text}`}>{role.role}</span>
            {role.permissions.includes('admin.manage') && (
              <span className="px-1 py-0.5 bg-red-50 text-red-600 text-[9px] font-bold uppercase tracking-wider rounded border border-red-200">
                ADMIN
              </span>
            )}
          </div>
          <p className="text-[11px] text-slate-500 mt-0.5 truncate">{role.description}</p>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          <span className="text-[10px] font-mono text-slate-400">
            {role.permissions.length} permissions
          </span>
          {isExpanded ? (
            <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
          ) : (
            <ChevronRight className="w-3.5 h-3.5 text-slate-400" />
          )}
        </div>
      </button>

      {/* Permissions grid */}
      {isExpanded && (
        <div className="border-t border-slate-100 px-4 py-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {Object.entries(domains).map(([domain, perms]) => (
              <div key={domain}>
                <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider border-b border-slate-100 pb-1 mb-1.5">
                  {domain}
                </div>
                {perms.map((p) => (
                  <div key={p} className="flex items-center gap-1.5 text-[11px] font-mono text-navy-900 mb-0.5">
                    <KeyRound className="w-2.5 h-2.5 text-emerald-500 flex-shrink-0" />
                    {p}
                  </div>
                ))}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function groupPermissions(permissions: string[]): Record<string, string[]> {
  const domains: Record<string, string[]> = {};
  for (const perm of permissions) {
    const [prefix] = perm.split('.');
    const domain = domainLabel(prefix);
    if (!domains[domain]) domains[domain] = [];
    domains[domain].push(perm);
  }
  return domains;
}

function domainLabel(prefix: string): string {
  const map: Record<string, string> = {
    event: 'Events',
    raw: 'Raw Data',
    uce: 'UCE',
    semantic: 'Semantic',
    dlq: 'DLQ / Pipeline',
    replay: 'Replay',
    mapping: 'Mapping & Parsers',
    config: 'Configuration',
    retention: 'Retention',
    admin: 'Administration',
    intelligence: 'Intelligence',
    detection: 'Detection',
    rule: 'Rule Management',
    case: 'Case Management',
  };
  return map[prefix] ?? prefix;
}

function StatCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-white border border-slate-200 rounded-lg px-4 py-3 shadow-sm">
      <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">{label}</div>
      <div className="text-xl font-bold text-navy-900 mt-0.5 font-mono">{value}</div>
    </div>
  );
}
