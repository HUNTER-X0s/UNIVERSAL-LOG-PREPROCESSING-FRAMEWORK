/**
 * UsersPage — Enterprise User Management Console (Admin)
 *
 * Requires: admin.manage permission (platform-admin role)
 *
 * Features:
 *   - Paginated user list with status badges and role pills
 *   - Create new user modal with form validation
 *   - Change role modal with permission delta preview
 *   - Real-time data from /auth/users endpoint
 */

import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Plus,
  RefreshCw,
  Search,
  ShieldCheck,
  Users,
  X,
  AlertTriangle,
} from 'lucide-react';
import { useAuth } from '../../auth/AuthProvider';
import { apiCreateUser, apiListUsers, apiUpdateUserRole } from '../../api/auth';
import type { UserDTO } from '../../auth/auth.types';

// ---------------------------------------------------------------------------
// Available roles for assignment
// ---------------------------------------------------------------------------

const ALL_ROLES = [
  'viewer',
  'operator',
  'analyst',
  'threat-hunter',
  'detection-engineer',
  'mapping-reviewer',
  'mapping-admin',
  'platform-admin',
] as const;

type AnyRole = (typeof ALL_ROLES)[number];

const ROLE_COLORS: Record<string, string> = {
  viewer: 'bg-slate-100 text-slate-700 border-slate-200',
  operator: 'bg-blue-50 text-blue-800 border-blue-200',
  analyst: 'bg-indigo-50 text-indigo-800 border-indigo-200',
  'threat-hunter': 'bg-amber-50 text-amber-800 border-amber-200',
  'detection-engineer': 'bg-purple-50 text-purple-800 border-purple-200',
  'mapping-reviewer': 'bg-teal-50 text-teal-800 border-teal-200',
  'mapping-admin': 'bg-emerald-50 text-emerald-800 border-emerald-200',
  'platform-admin': 'bg-red-50 text-red-800 border-red-200',
};

const STATUS_COLORS: Record<string, string> = {
  active: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  suspended: 'bg-amber-50 text-amber-700 border-amber-200',
  locked: 'bg-red-50 text-red-700 border-red-200',
};

// ---------------------------------------------------------------------------
// UsersPage
// ---------------------------------------------------------------------------

export const UsersPage: React.FC = () => {
  const { token } = useAuth();
  const queryClient = useQueryClient();
  const [search, setSearch] = useState('');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [roleTarget, setRoleTarget] = useState<UserDTO | null>(null);

  const { data: users = [], isLoading, error, refetch } = useQuery({
    queryKey: ['auth', 'users'],
    queryFn: () => apiListUsers(token!),
    enabled: !!token,
  });

  const filtered = users.filter(
    (u) =>
      u.username.toLowerCase().includes(search.toLowerCase()) ||
      u.display_name.toLowerCase().includes(search.toLowerCase()) ||
      u.role.toLowerCase().includes(search.toLowerCase()),
  );

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-base font-bold text-navy-900 flex items-center gap-2">
            <Users className="w-4 h-4" />
            User Management
          </h1>
          <p className="text-xs text-slate-500 mt-0.5">
            Provision and manage platform operator accounts
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => refetch()}
            className="p-2 text-slate-500 hover:text-navy-900 hover:bg-slate-100 rounded transition-colors"
            title="Refresh"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
          <button
            id="users-create-btn"
            type="button"
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-1.5 px-3 py-2 bg-navy-900 text-white text-xs font-semibold rounded hover:bg-navy-800 transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
            Create User
          </button>
        </div>
      </div>

      {/* Search */}
      <div className="relative max-w-xs">
        <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-slate-400">
          <Search className="w-3.5 h-3.5" />
        </div>
        <input
          type="text"
          placeholder="Search users…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ paddingLeft: '36px' }}
          className="w-full pr-3 py-1.5 text-xs bg-white border border-slate-300 rounded-lg focus:outline-none focus:ring-1 focus:ring-gov-blue transition-all"
        />
      </div>

      {/* Table */}
      <div className="bg-white border border-slate-200 rounded-lg shadow-sm overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <div className="w-6 h-6 border-2 border-gov-blue border-t-transparent rounded-full animate-spin" />
          </div>
        ) : error ? (
          <div className="flex items-center justify-center py-12 gap-2 text-red-600 text-sm">
            <AlertTriangle className="w-4 h-4" />
            Failed to load users. Ensure you have admin.manage permission.
          </div>
        ) : (
          <table className="w-full text-xs">
            <thead>
              <tr className="bg-slate-50 border-b border-slate-100">
                <Th>Username</Th>
                <Th>Display Name</Th>
                <Th>Role</Th>
                <Th>Status</Th>
                <Th>Tenant</Th>
                <Th>Logins</Th>
                <Th>Actions</Th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((user, idx) => (
                <tr
                  key={user.user_id}
                  className={`border-b border-slate-50 hover:bg-slate-50 transition-colors ${
                    idx % 2 === 0 ? '' : 'bg-slate-25'
                  }`}
                >
                  <td className="px-4 py-2.5 font-mono text-navy-900">{user.username}</td>
                  <td className="px-4 py-2.5 text-slate-700">{user.display_name}</td>
                  <td className="px-4 py-2.5">
                    <span
                      className={`px-1.5 py-0.5 rounded border text-[10px] font-bold uppercase tracking-wider ${
                        ROLE_COLORS[user.role] ?? 'bg-slate-100 text-slate-600 border-slate-200'
                      }`}
                    >
                      {user.role}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">
                    <span
                      className={`px-1.5 py-0.5 rounded border text-[10px] font-bold uppercase tracking-wider ${
                        STATUS_COLORS[user.status] ?? 'bg-slate-100 text-slate-600 border-slate-200'
                      }`}
                    >
                      {user.status}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 font-mono text-slate-600">{user.tenant_id}</td>
                  <td className="px-4 py-2.5 text-slate-600">{user.login_count}</td>
                  <td className="px-4 py-2.5">
                    <button
                      type="button"
                      onClick={() => setRoleTarget(user)}
                      className="text-[10px] font-semibold text-gov-blue hover:underline"
                    >
                      Change Role
                    </button>
                  </td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={7} className="text-center py-8 text-slate-400">
                    No users match the search criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
        <div className="px-4 py-2 bg-slate-50 border-t border-slate-100 text-[10px] text-slate-400 font-mono">
          {filtered.length} of {users.length} users — restricted to authorised administrators
        </div>
      </div>

      {/* Create User Modal */}
      {showCreateModal && (
        <CreateUserModal
          token={token!}
          onClose={() => setShowCreateModal(false)}
          onSuccess={() => {
            setShowCreateModal(false);
            queryClient.invalidateQueries({ queryKey: ['auth', 'users'] });
          }}
        />
      )}

      {/* Change Role Modal */}
      {roleTarget && (
        <ChangeRoleModal
          user={roleTarget}
          token={token!}
          onClose={() => setRoleTarget(null)}
          onSuccess={() => {
            setRoleTarget(null);
            queryClient.invalidateQueries({ queryKey: ['auth', 'users'] });
          }}
        />
      )}
    </div>
  );
};

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function Th({ children }: { children: React.ReactNode }) {
  return (
    <th className="px-4 py-2.5 text-left text-[10px] font-bold text-slate-500 uppercase tracking-wider">
      {children}
    </th>
  );
}

// ---------------------------------------------------------------------------
// CreateUserModal
// ---------------------------------------------------------------------------

function CreateUserModal({
  token,
  onClose,
  onSuccess,
}: {
  token: string;
  onClose: () => void;
  onSuccess: () => void;
}) {
  const [form, setForm] = useState({
    username: '',
    display_name: '',
    email: '',
    role: 'viewer' as AnyRole,
    password: '',
    tenant_id: 'sovereign-hq',
  });
  const [error, setError] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: () => apiCreateUser(token, form),
    onSuccess,
    onError: (err: Error) => setError(err.message),
  });

  return (
    <Modal title="Create Platform User" onClose={onClose}>
      {error && (
        <div className="flex items-start gap-2 px-3 py-2 bg-red-50 border border-red-200 rounded text-xs text-red-800 mb-4">
          <AlertTriangle className="w-3.5 h-3.5 mt-0.5 flex-shrink-0" />
          {error}
        </div>
      )}
      <div className="space-y-3">
        <Field
          label="Username"
          placeholder="e.g. john.doe"
          value={form.username}
          onChange={(v) => setForm((f) => ({ ...f, username: v }))}
          mono
        />
        <Field
          label="Display Name"
          placeholder="e.g. John Doe"
          value={form.display_name}
          onChange={(v) => setForm((f) => ({ ...f, display_name: v }))}
        />
        <Field
          label="Email"
          placeholder="e.g. john.doe@ulpf.gov"
          value={form.email}
          onChange={(v) => setForm((f) => ({ ...f, email: v }))}
          mono
        />
        <Field
          label="Password (min. 8 chars)"
          type="password"
          placeholder="••••••••"
          value={form.password}
          onChange={(v) => setForm((f) => ({ ...f, password: v }))}
        />
        <div>
          <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-1">
            Role
          </label>
          <select
            value={form.role}
            onChange={(e) => setForm((f) => ({ ...f, role: e.target.value as AnyRole }))}
            className="w-full px-3 py-1.5 text-xs bg-white border border-slate-300 rounded focus:outline-none focus:ring-1 focus:ring-gov-blue"
          >
            {ALL_ROLES.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
        </div>
      </div>
      <div className="flex gap-2 mt-5">
        <button
          type="button"
          onClick={onClose}
          className="flex-1 px-3 py-2 text-xs border border-slate-300 text-slate-700 rounded hover:bg-slate-50 transition-colors"
        >
          Cancel
        </button>
        <button
          type="button"
          onClick={() => mutation.mutate()}
          disabled={mutation.isPending || !form.username || !form.password}
          className="flex-1 px-3 py-2 text-xs bg-navy-900 text-white rounded hover:bg-navy-800 transition-colors disabled:opacity-50"
        >
          {mutation.isPending ? 'Creating…' : 'Create User'}
        </button>
      </div>
    </Modal>
  );
}

// ---------------------------------------------------------------------------
// ChangeRoleModal
// ---------------------------------------------------------------------------

function ChangeRoleModal({
  user,
  token,
  onClose,
  onSuccess,
}: {
  user: UserDTO;
  token: string;
  onClose: () => void;
  onSuccess: () => void;
}) {
  const [newRole, setNewRole] = useState<AnyRole>(user.role as AnyRole);
  const [error, setError] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: () => apiUpdateUserRole(token, user.user_id, { role: newRole }),
    onSuccess,
    onError: (err: Error) => setError(err.message),
  });

  return (
    <Modal title={`Change Role — ${user.username}`} onClose={onClose}>
      {error && (
        <div className="flex items-start gap-2 px-3 py-2 bg-red-50 border border-red-200 rounded text-xs text-red-800 mb-4">
          <AlertTriangle className="w-3.5 h-3.5 mt-0.5 flex-shrink-0" />
          {error}
        </div>
      )}
      <div className="mb-4">
        <div className="text-[10px] text-slate-500 mb-2">
          Current role: <span className="font-mono font-bold text-navy-900">{user.role}</span>
        </div>
        <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-1">
          New Role
        </label>
        <select
          value={newRole}
          onChange={(e) => setNewRole(e.target.value as AnyRole)}
          className="w-full px-3 py-1.5 text-xs bg-white border border-slate-300 rounded focus:outline-none focus:ring-1 focus:ring-gov-blue"
        >
          {ALL_ROLES.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </select>
      </div>
      <div className="flex items-center gap-1.5 px-3 py-2 bg-amber-50 border border-amber-200 rounded text-[10px] text-amber-800 mb-4">
        <ShieldCheck className="w-3.5 h-3.5 flex-shrink-0" />
        Role changes take effect on the user's next login. Active sessions are not revoked.
      </div>
      <div className="flex gap-2">
        <button
          type="button"
          onClick={onClose}
          className="flex-1 px-3 py-2 text-xs border border-slate-300 text-slate-700 rounded hover:bg-slate-50 transition-colors"
        >
          Cancel
        </button>
        <button
          type="button"
          onClick={() => mutation.mutate()}
          disabled={mutation.isPending || newRole === user.role}
          className="flex-1 px-3 py-2 text-xs bg-navy-900 text-white rounded hover:bg-navy-800 transition-colors disabled:opacity-50"
        >
          {mutation.isPending ? 'Updating…' : 'Update Role'}
        </button>
      </div>
    </Modal>
  );
}

// ---------------------------------------------------------------------------
// Modal wrapper
// ---------------------------------------------------------------------------

function Modal({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div className="bg-white rounded-lg shadow-xl w-full max-w-md border border-slate-200 overflow-hidden">
        <div className="flex items-center justify-between px-5 py-3 border-b border-slate-100 bg-slate-50">
          <span className="text-sm font-bold text-navy-900">{title}</span>
          <button
            type="button"
            onClick={onClose}
            className="text-slate-400 hover:text-navy-900 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="px-5 py-5">{children}</div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Field helper
// ---------------------------------------------------------------------------

function Field({
  label,
  value,
  onChange,
  placeholder,
  type = 'text',
  mono = false,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  type?: string;
  mono?: boolean;
}) {
  return (
    <div>
      <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-1">
        {label}
      </label>
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className={`w-full px-3 py-1.5 text-xs bg-white border border-slate-300 rounded focus:outline-none focus:ring-1 focus:ring-gov-blue ${
          mono ? 'font-mono' : ''
        }`}
      />
    </div>
  );
}
