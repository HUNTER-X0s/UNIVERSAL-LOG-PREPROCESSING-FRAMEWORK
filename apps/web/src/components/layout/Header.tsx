/**
 * Header — ULPF Institutional Application Header
 *
 * Updated to include authenticated user profile dropdown with:
 *   - Active username + role pill
 *   - Tenant context
 *   - Quick navigation to profile and admin pages
 *   - Sign out action
 *   - Functional search bar (type & press Enter to search)
 */

import React, { useRef, useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Bell,
  ChevronDown,
  KeyRound,
  LogOut,
  Search,
  Settings,
  Shield,
  User,
  Users,
} from 'lucide-react';
import { useAuth } from '../../auth/AuthProvider';
import { BrandLogo } from '../ui/BrandLogo';

const ROLE_COLORS: Record<string, string> = {
  viewer: 'bg-slate-100 text-slate-700',
  operator: 'bg-blue-50 text-blue-800',
  analyst: 'bg-indigo-50 text-indigo-800',
  'threat-hunter': 'bg-amber-50 text-amber-800',
  'detection-engineer': 'bg-purple-50 text-purple-800',
  'mapping-reviewer': 'bg-teal-50 text-teal-800',
  'mapping-admin': 'bg-emerald-50 text-emerald-800',
  'platform-admin': 'bg-red-50 text-red-800',
};

export const Header: React.FC = () => {
  const { user, isAuthenticated, logout, hasPermission } = useAuth();
  const navigate = useNavigate();
  const [showDropdown, setShowDropdown] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const settingsRef = useRef<HTMLDivElement>(null);

  // Simple search bar state
  const [searchQuery, setSearchQuery] = useState('');

  // Close dropdowns on outside click
  useEffect(() => {
    const handleClick = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setShowDropdown(false);
      }
      if (settingsRef.current && !settingsRef.current.contains(e.target as Node)) {
        setShowSettings(false);
      }
    };
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, []);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const q = searchQuery.trim();
    if (!q) return;
    navigate(`/live-logs?q=${encodeURIComponent(q)}`);
    setSearchQuery('');
  };

  const handleLogout = () => {
    setShowDropdown(false);
    logout();
    navigate('/login', { replace: true });
  };

  const roleColor = user ? ROLE_COLORS[user.role] ?? 'bg-slate-100 text-slate-700' : '';

  return (
    <header className="h-14 bg-white border-b border-border-medium px-5 flex items-center justify-between shadow-xs z-30 flex-shrink-0">
      {/* Left: ULPF Institutional Identity Mark */}
      <div className="flex items-center gap-3.5">
        <div className="w-9 h-9 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-center flex-shrink-0 shadow-md p-1 group hover:border-cyan-500/50 transition-colors">
          <BrandLogo size={28} />
        </div>
        <div className="flex flex-col justify-center">
          <span className="header-brand-title font-bold text-navy-900 leading-tight tracking-tight uppercase">
            Universal Log Pre-processing Framework
          </span>
          <span className="header-brand-subtitle font-medium text-slate-500">
            Security Telemetry Processing Platform
          </span>
        </div>
      </div>

      {/* Right: Controls */}
      <div className="flex items-center gap-3">
        {/* Global Search — type and press Enter to search events */}
        <form onSubmit={handleSearchSubmit} className="relative hidden md:flex items-center">
          <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-slate-400">
            <Search className="w-3.5 h-3.5" />
          </div>
          <input
            id="header-search"
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search events, sources, parsers…"
            style={{ paddingLeft: '36px' }}
            className="w-72 pr-3 py-1.5 text-xs bg-slate-50 border border-border-medium rounded-lg text-navy-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-gov-blue/30 focus:border-gov-blue focus:bg-white transition-all shadow-2xs"
          />
        </form>

        {/* Notifications — navigates to Alerts & Detection */}
        <button
          onClick={() => navigate('/alerts')}
          className="p-1.5 text-slate-500 hover:text-navy-900 hover:bg-slate-100 rounded transition-colors relative"
          title="Alerts & Detection"
          aria-label="Notifications"
        >
          <Bell className="w-4 h-4" />
          <span className="w-1.5 h-1.5 rounded-full bg-gov-blue absolute top-1.5 right-1.5" />
        </button>

        {/* Settings & Administration Dropdown (Just left of user profile) */}
        {isAuthenticated && user && (
          <div className="relative" ref={settingsRef}>
            <button
              id="header-settings-btn"
              type="button"
              onClick={() => {
                setShowSettings((v) => !v);
                setShowDropdown(false);
              }}
              className={`p-1.5 rounded-lg transition-colors flex items-center justify-center ${
                showSettings
                  ? 'bg-slate-100 text-gov-blue ring-1 ring-slate-200'
                  : 'text-slate-500 hover:text-navy-900 hover:bg-slate-100'
              }`}
              title="Settings & Administration"
              aria-label="Settings"
              aria-expanded={showSettings}
            >
              <Settings
                className={`w-4 h-4 transition-transform duration-200 ${
                  showSettings ? 'rotate-90 text-gov-blue' : ''
                }`}
              />
            </button>

            {/* Settings Dropdown Panel */}
            {showSettings && (
              <div className="absolute right-0 top-full mt-2 w-72 bg-white border border-slate-200 rounded-xl shadow-xl z-50 overflow-hidden text-left animate-in fade-in slide-in-from-top-1 duration-150">
                {/* Header */}
                <div className="px-3.5 py-2.5 bg-slate-50 border-b border-slate-100 flex items-center justify-between">
                  <div>
                    <div className="text-xs font-bold text-navy-900 uppercase tracking-wider">
                      Settings & Administration
                    </div>
                    <div className="text-[10px] text-slate-500">
                      User profile & platform governance
                    </div>
                  </div>
                  <div className="w-6 h-6 rounded bg-slate-200/70 flex items-center justify-center text-slate-600">
                    <Settings className="w-3.5 h-3.5" />
                  </div>
                </div>

                <div className="p-1.5 space-y-1">
                  {/* My Profile Section */}
                  <div className="px-2 pt-1 pb-0.5 text-[9px] font-bold text-slate-400 uppercase tracking-wider">
                    User Account
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      setShowSettings(false);
                      navigate('/profile');
                    }}
                    className="w-full flex items-center gap-3 px-2.5 py-2 rounded-lg hover:bg-slate-50 transition-colors text-left group"
                  >
                    <div className="w-7 h-7 rounded-md bg-blue-50 border border-blue-100 flex items-center justify-center text-gov-blue group-hover:bg-gov-blue group-hover:text-white transition-colors flex-shrink-0">
                      <User className="w-3.5 h-3.5" />
                    </div>
                    <div className="min-w-0">
                      <div className="text-xs font-semibold text-navy-900 group-hover:text-gov-blue transition-colors">
                        My Profile
                      </div>
                      <div className="text-[10px] text-slate-400 truncate">
                        Credentials, active roles & token details
                      </div>
                    </div>
                  </button>

                  {/* Administration Section */}
                  <div className="pt-2">
                    <div className="px-2 pt-1 pb-0.5 text-[9px] font-bold text-slate-400 uppercase tracking-wider border-t border-slate-100">
                      Administration
                    </div>

                    {hasPermission('admin.manage') ? (
                      <div className="space-y-0.5 mt-0.5">
                        <button
                          type="button"
                          onClick={() => {
                            setShowSettings(false);
                            navigate('/admin/users');
                          }}
                          className="w-full flex items-center gap-3 px-2.5 py-2 rounded-lg hover:bg-slate-50 transition-colors text-left group"
                        >
                          <div className="w-7 h-7 rounded-md bg-purple-50 border border-purple-100 flex items-center justify-center text-purple-700 group-hover:bg-purple-700 group-hover:text-white transition-colors flex-shrink-0">
                            <Users className="w-3.5 h-3.5" />
                          </div>
                          <div className="min-w-0">
                            <div className="text-xs font-semibold text-navy-900 group-hover:text-purple-700 transition-colors">
                              User Management
                            </div>
                            <div className="text-[10px] text-slate-400 truncate">
                              Account provisioning, status & access
                            </div>
                          </div>
                        </button>

                        <button
                          type="button"
                          onClick={() => {
                            setShowSettings(false);
                            navigate('/admin/roles');
                          }}
                          className="w-full flex items-center gap-3 px-2.5 py-2 rounded-lg hover:bg-slate-50 transition-colors text-left group"
                        >
                          <div className="w-7 h-7 rounded-md bg-emerald-50 border border-emerald-100 flex items-center justify-center text-emerald-700 group-hover:bg-emerald-700 group-hover:text-white transition-colors flex-shrink-0">
                            <Shield className="w-3.5 h-3.5" />
                          </div>
                          <div className="min-w-0">
                            <div className="text-xs font-semibold text-navy-900 group-hover:text-emerald-700 transition-colors">
                              Role Catalog
                            </div>
                            <div className="text-[10px] text-slate-400 truncate">
                              RBAC definitions & policy matrix
                            </div>
                          </div>
                        </button>

                        <button
                          type="button"
                          onClick={() => {
                            setShowSettings(false);
                            navigate('/admin/audit');
                          }}
                          className="w-full flex items-center gap-3 px-2.5 py-2 rounded-lg hover:bg-slate-50 transition-colors text-left group"
                        >
                          <div className="w-7 h-7 rounded-md bg-amber-50 border border-amber-100 flex items-center justify-center text-amber-700 group-hover:bg-amber-700 group-hover:text-white transition-colors flex-shrink-0">
                            <KeyRound className="w-3.5 h-3.5" />
                          </div>
                          <div className="min-w-0">
                            <div className="text-xs font-semibold text-navy-900 group-hover:text-amber-700 transition-colors">
                              Auth Audit Trail
                            </div>
                            <div className="text-[10px] text-slate-400 truncate">
                              Cryptographic authentication logs
                            </div>
                          </div>
                        </button>
                      </div>
                    ) : (
                      <div className="p-2.5 text-center text-xs text-slate-400">
                        Restricted to Platform Administrators
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* User Profile Area */}
        {isAuthenticated && user ? (
          <div className="relative pl-2 border-l border-slate-200" ref={dropdownRef}>
            <button
              id="header-user-menu"
              type="button"
              onClick={() => {
                setShowDropdown((v) => !v);
                setShowSettings(false);
              }}
              className="flex items-center gap-2 hover:bg-slate-50 px-2 py-1 rounded transition-colors"
              aria-haspopup="true"
              aria-expanded={showDropdown}
            >
              {/* Avatar */}
              {user.avatarUrl ? (
                <img
                  src={user.avatarUrl}
                  alt={user.displayName}
                  className="w-8 h-8 rounded-full object-cover border border-slate-300 shadow-xs flex-shrink-0"
                />
              ) : (
                <div className="w-8 h-8 rounded-full bg-navy-900 border border-navy-800 flex items-center justify-center text-white font-bold text-sm flex-shrink-0 shadow-xs">
                  {user.displayName.charAt(0).toUpperCase()}
                </div>
              )}
              {/* Info */}
              <div className="hidden lg:flex flex-col text-left">
                <span className="header-user-name font-bold text-navy-900 leading-tight">
                  {user.displayName}
                </span>
                <span
                  className={`px-1.5 py-0.5 rounded header-user-role uppercase ${roleColor} w-fit mt-0.5`}
                >
                  {user.role}
                </span>
              </div>
              <ChevronDown
                className={`w-3.5 h-3.5 text-slate-400 transition-transform ${showDropdown ? 'rotate-180' : ''}`}
              />
            </button>

            {/* Dropdown */}
            {showDropdown && (
              <div className="absolute right-0 top-full mt-2 w-60 bg-white border border-slate-200 rounded-xl shadow-lg z-50 overflow-hidden">
                {/* User info header */}
                <div className="px-3.5 py-2.5 border-b border-slate-100 bg-slate-50 flex items-center gap-2.5">
                  {user.avatarUrl ? (
                    <img
                      src={user.avatarUrl}
                      alt={user.displayName}
                      className="w-9 h-9 rounded-full object-cover border border-slate-300 flex-shrink-0 shadow-2xs"
                    />
                  ) : (
                    <div className="w-9 h-9 rounded-full bg-navy-900 text-white font-bold text-sm flex items-center justify-center flex-shrink-0 shadow-2xs">
                      {user.displayName.charAt(0).toUpperCase()}
                    </div>
                  )}
                  <div className="min-w-0 flex-1">
                    <div className="header-user-name font-bold text-navy-900 truncate">{user.displayName}</div>
                    <div className="text-[10px] text-slate-400 font-mono truncate">{user.username}</div>
                    <div className="flex items-center gap-1 mt-0.5">
                      <div className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                      <span className="text-[10px] text-slate-500 font-mono truncate">{user.tenantId}</span>
                    </div>
                  </div>
                </div>

                <div className="p-1">
                  <button
                    id="header-logout"
                    type="button"
                    onClick={handleLogout}
                    className="w-full flex items-center gap-2.5 px-3 py-2 text-xs font-medium text-red-600 hover:bg-red-50 rounded-lg transition-colors"
                  >
                    <LogOut className="w-3.5 h-3.5" />
                    Sign Out
                  </button>
                </div>
              </div>
            )}
          </div>
        ) : (
          /* Unauthenticated fallback */
          <div className="flex items-center gap-2 pl-2 border-l border-slate-200">
            <div className="w-7 h-7 rounded-full bg-slate-200 border border-slate-300 flex items-center justify-center text-slate-700 font-bold text-xs">
              <User className="w-3.5 h-3.5" />
            </div>
          </div>
        )}
      </div>
    </header>
  );
};

// ---------------------------------------------------------------------------
// DropdownItem helper
// ---------------------------------------------------------------------------

function DropdownItem({
  icon,
  label,
  onClick,
}: {
  icon: React.ReactNode;
  label: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="w-full flex items-center gap-2.5 px-3 py-2 text-xs text-slate-700 hover:bg-slate-50 transition-colors"
    >
      <span className="text-slate-400">{icon}</span>
      {label}
    </button>
  );
}
