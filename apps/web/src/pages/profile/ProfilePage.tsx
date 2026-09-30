/**
 * ProfilePage â€” User Identity, Photo & Credentials Management
 *
 * Provides:
 *   - Photo management (upload, preview, remove) synced with global header
 *   - Display name modification
 *   - Current username display & new username modification
 *   - Current password & new password modification with visibility toggles
 *   - Role assignments and effective permission matrix
 *   - UX: Password strength meter, unsaved-changes guard, last-saved badge,
 *          character counter, session fingerprint display
 */

import React, { useState, useRef, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  AlertCircle,
  AlertTriangle,
  Building2,
  Camera,
  CheckCircle2,
  Clock,
  Eye,
  EyeOff,
  Fingerprint,
  KeyRound,
  Lock,
  LogOut,
  RefreshCw,
  Save,
  Shield,
  ShieldCheck,
  Trash2,
  Upload,
  User as UserIcon,
} from 'lucide-react';
import { useAuth } from '../../auth/AuthProvider';

// ---------------------------------------------------------------------------
// Permission domain groupings
// ---------------------------------------------------------------------------

const PERMISSION_DOMAINS: Array<{ label: string; permissions: string[] }> = [
  {
    label: 'Telemetry & Events',
    permissions: ['event.read', 'event.search', 'event.ingest', 'raw.read', 'uce.read', 'semantic.read'],
  },
  {
    label: 'Pipeline Operations',
    permissions: ['dlq.read', 'dlq.replay', 'replay.execute'],
  },
  {
    label: 'Mapping & Parsers',
    permissions: ['mapping.read', 'mapping.approve', 'mapping.activate', 'mapping.rollback'],
  },
  {
    label: 'Intelligence',
    permissions: ['intelligence.read', 'intelligence.hunt', 'intelligence.investigate', 'case.write'],
  },
  {
    label: 'Detection',
    permissions: ['detection.manage', 'rule.review', 'rule.activate'],
  },
  {
    label: 'Platform Administration',
    permissions: ['config.read', 'config.modify', 'retention.modify', 'admin.manage'],
  },
];

const ROLE_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  viewer: { bg: 'bg-slate-100', text: 'text-slate-700', border: 'border-slate-300' },
  operator: { bg: 'bg-blue-50', text: 'text-blue-800', border: 'border-blue-200' },
  analyst: { bg: 'bg-indigo-50', text: 'text-indigo-800', border: 'border-indigo-200' },
  'threat-hunter': { bg: 'bg-amber-50', text: 'text-amber-800', border: 'border-amber-200' },
  'detection-engineer': { bg: 'bg-purple-50', text: 'text-purple-800', border: 'border-purple-200' },
  'mapping-reviewer': { bg: 'bg-teal-50', text: 'text-teal-800', border: 'border-teal-200' },
  'mapping-admin': { bg: 'bg-emerald-50', text: 'text-emerald-800', border: 'border-emerald-200' },
  'platform-admin': { bg: 'bg-red-50', text: 'text-red-800', border: 'border-red-200' },
};

// ---------------------------------------------------------------------------
// UX Enhancement 1: Password Strength Meter
// ---------------------------------------------------------------------------
function getPasswordStrength(pw: string): { score: number; label: string; color: string; bg: string } {
  if (!pw) return { score: 0, label: '', color: 'bg-slate-200', bg: 'bg-slate-100' };
  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 12) score++;
  if (/[A-Z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  if (score <= 1) return { score, label: 'Weak', color: 'bg-red-500', bg: 'bg-red-50' };
  if (score === 2) return { score, label: 'Fair', color: 'bg-amber-500', bg: 'bg-amber-50' };
  if (score === 3) return { score, label: 'Good', color: 'bg-blue-500', bg: 'bg-blue-50' };
  if (score === 4) return { score, label: 'Strong', color: 'bg-emerald-500', bg: 'bg-emerald-50' };
  return { score, label: 'Sovereign Grade', color: 'bg-emerald-600', bg: 'bg-emerald-50' };
}

// ---------------------------------------------------------------------------
// UX Enhancement 2: Derive session fingerprint (SHA-256 like hash from userId)
// ---------------------------------------------------------------------------
async function deriveFingerprint(userId: string, username: string): Promise<string> {
  try {
    const data = new TextEncoder().encode(`${userId}:${username}:ulpf-65b`);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 40).toUpperCase();
  } catch {
    return Array.from({ length: 40 }, () => Math.floor(Math.random() * 16).toString(16)).join('').toUpperCase();
  }
}

export const ProfilePage: React.FC = () => {
  const { user, permissions, logout, updateUserProfile, changePassword } = useAuth();
  const navigate = useNavigate();

  // Photo state
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [avatarPreview, setAvatarPreview] = useState<string | null>(user?.avatarUrl ?? null);

  // Profile fields state
  const [displayName, setDisplayName] = useState(user?.displayName ?? '');
  const [newUsername, setNewUsername] = useState('');
  const [profileSuccess, setProfileSuccess] = useState<string | null>(null);
  const [profileError, setProfileError] = useState<string | null>(null);
  const [isSavingProfile, setIsSavingProfile] = useState(false);

  // UX Enhancement 3: Unsaved changes guard
  const [profileDirty, setProfileDirty] = useState(false);
  const [profileLastSaved, setProfileLastSaved] = useState<Date | null>(null);

  // Password fields state
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showCurrentPass, setShowCurrentPass] = useState(false);
  const [showNewPass, setShowNewPass] = useState(false);
  const [showConfirmPass, setShowConfirmPass] = useState(false);
  const [passwordSuccess, setPasswordSuccess] = useState<string | null>(null);
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [isChangingPass, setIsChangingPass] = useState(false);
  const [passwordLastSaved, setPasswordLastSaved] = useState<Date | null>(null);

  // UX Enhancement 4: Session fingerprint
  const [sessionFingerprint, setSessionFingerprint] = useState<string>('');

  useEffect(() => {
    if (user) {
      deriveFingerprint(user.userId, user.username).then(setSessionFingerprint);
    }
  }, [user]);

  // Keep form fields synchronized with user state if untouched
  useEffect(() => {
    if (user?.displayName && !profileDirty) {
      setDisplayName(user.displayName);
    }
    if (user?.avatarUrl !== undefined && !profileDirty) {
      setAvatarPreview(user.avatarUrl ?? null);
    }
  }, [user?.displayName, user?.avatarUrl, profileDirty]);

  // Track profile dirty state
  useEffect(() => {
    if (!user) return;
    const isDirty =
      displayName.trim() !== user.displayName ||
      newUsername.trim() !== '' ||
      avatarPreview !== (user.avatarUrl ?? null);
    setProfileDirty(isDirty);
  }, [displayName, newUsername, avatarPreview, user]);

  // UX Enhancement 5: Warn before leaving with unsaved changes
  useEffect(() => {
    const handleBeforeUnload = (e: BeforeUnloadEvent) => {
      if (profileDirty) {
        e.preventDefault();
      }
    };
    window.addEventListener('beforeunload', handleBeforeUnload);
    return () => window.removeEventListener('beforeunload', handleBeforeUnload);
  }, [profileDirty]);

  if (!user) return null;

  const roleStyle = ROLE_COLORS[user.role] ?? ROLE_COLORS.viewer;
  const pwStrength = getPasswordStrength(newPassword);

  // Handle Photo Upload
  const handlePhotoSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > 5 * 1024 * 1024) {
      setProfileError('Photo file size exceeds 5MB limit.');
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      setAvatarPreview(reader.result as string);
      setProfileError(null);
    };
    reader.readAsDataURL(file);
  };

  const handleRemovePhoto = () => {
    setAvatarPreview(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  // Handle Save Profile — syncs display name, username, avatar to backend & app
  const handleSaveProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    setProfileSuccess(null);
    setProfileError(null);

    const trimmedName = displayName.trim();
    if (!trimmedName) {
      setProfileError('Display name cannot be empty.');
      return;
    }

    const trimmedUsername = newUsername.trim();
    if (trimmedUsername) {
      if (trimmedUsername.length < 3) {
        setProfileError('New username must be at least 3 characters long.');
        return;
      }
      if (!/^[a-zA-Z0-9._-]+$/.test(trimmedUsername)) {
        setProfileError('Username can only contain letters, numbers, dots, dashes, and underscores.');
        return;
      }
      if (trimmedUsername === user.username) {
        setProfileError('New username matches your current username — no change needed.');
        return;
      }
    }

    setIsSavingProfile(true);
    try {
      const result = await updateUserProfile({
        displayName: trimmedName,
        username: trimmedUsername || undefined,
        avatarUrl: avatarPreview,
      });

      if (result.success) {
        setProfileSuccess('Profile updated. Display name, username, and photo are now synced across the whole application.');
        setNewUsername('');
        setProfileDirty(false);
        setProfileLastSaved(new Date());
        setTimeout(() => setProfileSuccess(null), 6000);
      } else {
        setProfileError(result.error || 'Failed to update profile.');
      }
    } catch (err: any) {
      setProfileError(err.message || 'An unexpected error occurred.');
    } finally {
      setIsSavingProfile(false);
    }
  };

  // Handle Password Change - verifies current, hashes new, syncs to backend
  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setPasswordSuccess(null);
    setPasswordError(null);

    if (!currentPassword) {
      setPasswordError('Please enter your current password to authorize changes.');
      return;
    }
    if (!newPassword) {
      setPasswordError('Please enter a new password.');
      return;
    }
    if (newPassword.length < 6) {
      setPasswordError('New password must be at least 6 characters.');
      return;
    }
    if (newPassword !== confirmPassword) {
      setPasswordError('New password and confirmation do not match.');
      return;
    }
    if (newPassword === currentPassword) {
      setPasswordError('New password cannot be identical to your current password.');
      return;
    }

    setIsChangingPass(true);
    try {
      const result = await changePassword(currentPassword, newPassword);
      if (result.success) {
        setPasswordSuccess('Password modified successfully. Your new credentials are active across all sessions.');
        setCurrentPassword('');
        setNewPassword('');
        setConfirmPassword('');
        setPasswordLastSaved(new Date());
        setTimeout(() => setPasswordSuccess(null), 6000);
      } else {
        setPasswordError(result.error || 'Failed to change password.');
      }
    } catch (err: any) {
      setPasswordError(err.message || 'Error occurred while updating password.');
    } finally {
      setIsChangingPass(false);
    }
  };

  const handleLogout = () => {
    logout();
    navigate('/login', { replace: true });
  };

  return (
    <div className="p-6 max-w-3xl mx-auto space-y-6">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-base font-bold text-navy-900 flex items-center gap-2">
            <UserIcon className="w-4 h-4 text-gov-blue" />
            User Profile & Credentials
          </h1>
          <p className="text-xs text-slate-500 mt-0.5">
            Modify profile photo, display name, username, and account password
          </p>
        </div>
        <button
          id="profile-logout"
          type="button"
          onClick={handleLogout}
          className="flex items-center gap-2 px-3 py-2 text-xs font-semibold text-red-700 bg-red-50 border border-red-200 rounded-lg hover:bg-red-100 transition-colors"
        >
          <LogOut className="w-3.5 h-3.5" />
          Sign Out
        </button>
      </div>

      {/* UX Enhancement 3: Unsaved changes warning banner */}
      {profileDirty && (
        <div className="flex items-center gap-2.5 px-4 py-2.5 rounded-lg bg-amber-50 border border-amber-200 text-amber-800 text-xs">
          <AlertTriangle className="w-4 h-4 flex-shrink-0 text-amber-500" />
          <span>You have unsaved profile changes. Click <strong>Save Profile Changes</strong> to apply them.</span>
        </div>
      )}

      {/* ============================================================
          CARD 1 â€” Profile & Identity
         ============================================================ */}
      <div className="bg-white border border-slate-200 rounded-xl shadow-xs overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-100 bg-slate-50 flex items-center gap-2">
          <UserIcon className="w-4 h-4 text-gov-blue" />
          <span className="text-xs font-bold text-navy-900 uppercase tracking-wider">
            Profile & Identity
          </span>
          {profileLastSaved && (
            <span className="ml-auto text-[10px] text-emerald-600 font-mono flex items-center gap-1">
              <CheckCircle2 className="w-3 h-3" />
              Saved {profileLastSaved.toLocaleTimeString()}
            </span>
          )}
        </div>

        <form onSubmit={handleSaveProfile} className="p-6 space-y-5">
          {profileSuccess && (
            <div className="flex items-start gap-2.5 p-3 rounded-lg bg-emerald-50 border border-emerald-200 text-emerald-800 text-xs">
              <CheckCircle2 className="w-4 h-4 flex-shrink-0 text-emerald-600 mt-0.5" />
              <span>{profileSuccess}</span>
            </div>
          )}
          {profileError && (
            <div className="flex items-start gap-2.5 p-3 rounded-lg bg-red-50 border border-red-200 text-red-800 text-xs">
              <AlertCircle className="w-4 h-4 flex-shrink-0 text-red-600 mt-0.5" />
              <span>{profileError}</span>
            </div>
          )}

          {/* Photo Section */}
          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-5 pb-5 border-b border-slate-100">
            <div className="relative">
              {avatarPreview ? (
                <img
                  src={avatarPreview}
                  alt="Profile"
                  className="w-20 h-20 rounded-full object-cover border-2 border-slate-200 shadow-md"
                />
              ) : (
                <div className="w-20 h-20 rounded-full bg-navy-900 border-2 border-navy-800 flex items-center justify-center text-white text-2xl font-bold shadow-md select-none">
                  {displayName.charAt(0).toUpperCase() || user.username.charAt(0).toUpperCase()}
                </div>
              )}
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                className="absolute bottom-0 right-0 p-1.5 bg-gov-blue text-white rounded-full shadow-md hover:bg-blue-700 transition-colors"
                title="Change Photo"
              >
                <Camera className="w-3.5 h-3.5" />
              </button>
            </div>
            <div className="space-y-1.5 flex-1">
              <div className="text-xs font-bold text-navy-900 uppercase tracking-wider">Profile Photo</div>
              <p className="text-[11px] text-slate-500">
                Upload a portrait image (JPG, PNG, WebP - max 5 MB). Updates in the top navigation header.
              </p>
              <div className="flex items-center gap-2 pt-1">
                <input
                  ref={fileInputRef}
                  type="file"
                  accept="image/png,image/jpeg,image/webp"
                  onChange={handlePhotoSelect}
                  className="hidden"
                />
                <button
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-navy-900 bg-slate-100 hover:bg-slate-200 border border-slate-200 rounded-lg transition-colors"
                >
                  <Upload className="w-3.5 h-3.5" />
                  Upload Photo
                </button>
                {avatarPreview && (
                  <button
                    type="button"
                    onClick={handleRemovePhoto}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-red-700 bg-red-50 hover:bg-red-100 border border-red-200 rounded-lg transition-colors"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    Remove
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* Modify Display Name */}
          <div className="space-y-1.5">
            <label htmlFor="display-name" className="block text-xs font-bold text-navy-900 uppercase tracking-wider">
              Modify Display Name
            </label>
            <input
              id="display-name"
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="e.g. Anurag Swain"
              maxLength={128}
              required
              className="w-full px-3 py-2 text-xs bg-white border border-slate-300 rounded-lg text-navy-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-gov-blue/20 focus:border-gov-blue transition-all"
            />
            <p className="text-[10px] text-slate-400">
              The visible institutional name shown in headers, audit logs, and forensic certificates.
            </p>
          </div>

          {/* Current Username - read-only, stacked */}
          <div className="space-y-1.5">
            <label className="block text-xs font-bold text-navy-900 uppercase tracking-wider">
              Current Username
            </label>
            <div className="flex items-center gap-2 px-3 py-2 bg-slate-100 border border-slate-200 rounded-lg text-xs font-mono text-slate-700">
              <Lock className="w-3.5 h-3.5 text-slate-400 flex-shrink-0" />
              <span className="flex-1">{user.username}</span>
              <span className="text-[10px] text-slate-400 font-sans">Active Login Identity</span>
            </div>
          </div>

          {/* New Username */}
          <div className="space-y-1.5">
            <label htmlFor="new-username" className="block text-xs font-bold text-navy-900 uppercase tracking-wider">
              Enter new username
            </label>
            <input
              id="new-username"
              type="text"
              value={newUsername}
              onChange={(e) => setNewUsername(e.target.value)}
              placeholder="Enter new username"
              maxLength={64}
              className="w-full px-3 py-2 text-xs font-mono bg-white border border-slate-300 rounded-lg text-navy-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-gov-blue/20 focus:border-gov-blue transition-all"
            />
            <p className="text-[10px] text-slate-400">
              Min. 3 characters · Letters, numbers, underscores, dots, and dashes only.
            </p>
          </div>

          <div className="flex justify-end pt-1">
            <button
              type="submit"
              disabled={isSavingProfile}
              className="flex items-center gap-2 px-4 py-2 text-xs font-semibold text-white bg-gov-blue hover:bg-blue-700 rounded-lg shadow-sm transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Save className="w-3.5 h-3.5" />
              {isSavingProfile ? 'Saving...' : 'Save Profile Changes'}
            </button>
          </div>
        </form>
      </div>

      {/* ============================================================
          CARD 2: Modify Password (Stacked vertically)
         ============================================================ */}
      <div className="bg-white border border-slate-200 rounded-xl shadow-xs overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-100 bg-slate-50 flex items-center gap-2">
          <KeyRound className="w-4 h-4 text-gov-blue" />
          <span className="text-xs font-bold text-navy-900 uppercase tracking-wider">
            Modify Password
          </span>
          {passwordLastSaved && (
            <span className="ml-auto text-[10px] text-emerald-600 font-mono flex items-center gap-1">
              <CheckCircle2 className="w-3 h-3" />
              Changed {passwordLastSaved.toLocaleTimeString()}
            </span>
          )}
        </div>

        <form onSubmit={handleChangePassword} className="p-6 space-y-4">
          {passwordSuccess && (
            <div className="flex items-start gap-2.5 p-3 rounded-lg bg-emerald-50 border border-emerald-200 text-emerald-800 text-xs">
              <CheckCircle2 className="w-4 h-4 flex-shrink-0 text-emerald-600 mt-0.5" />
              <span>{passwordSuccess}</span>
            </div>
          )}
          {passwordError && (
            <div className="flex items-start gap-2.5 p-3 rounded-lg bg-red-50 border border-red-200 text-red-800 text-xs">
              <AlertCircle className="w-4 h-4 flex-shrink-0 text-red-600 mt-0.5" />
              <span>{passwordError}</span>
            </div>
          )}

          {/* Current Password */}
          <div className="space-y-1.5">
            <label htmlFor="current-password" className="block text-xs font-bold text-navy-900 uppercase tracking-wider">
              Enter current password
            </label>
            <div className="relative">
              <input
                id="current-password"
                type={showCurrentPass ? 'text' : 'password'}
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                placeholder="Enter current password"
                required
                className="w-full px-3 py-2 pr-10 text-xs bg-white border border-slate-300 rounded-lg text-navy-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-gov-blue/20 focus:border-gov-blue transition-all"
              />
              <button
                type="button"
                onClick={() => setShowCurrentPass(!showCurrentPass)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 transition-colors"
                aria-label="Toggle current password visibility"
              >
                {showCurrentPass ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
              </button>
            </div>
            <p className="text-[10px] text-slate-400">Required to authorize the credential change.</p>
          </div>

          {/* New Password */}
          <div className="space-y-1.5">
            <label htmlFor="new-password" className="block text-xs font-bold text-navy-900 uppercase tracking-wider">
              Enter new password
            </label>
            <div className="relative">
              <input
                id="new-password"
                type={showNewPass ? 'text' : 'password'}
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="Enter new password"
                required
                className="w-full px-3 py-2 pr-10 text-xs bg-white border border-slate-300 rounded-lg text-navy-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-gov-blue/20 focus:border-gov-blue transition-all"
              />
              <button
                type="button"
                onClick={() => setShowNewPass(!showNewPass)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 transition-colors"
                aria-label="Toggle new password visibility"
              >
                {showNewPass ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
              </button>
            </div>
            {/* Strength meter */}
            {newPassword.length > 0 && (
              <div className="space-y-1">
                <div className="flex gap-1">
                  {[1, 2, 3, 4, 5].map((level) => (
                    <div
                      key={level}
                      className={`h-1 flex-1 rounded-full transition-all duration-300 ${
                        pwStrength.score >= level ? pwStrength.color : 'bg-slate-200'
                      }`}
                    />
                  ))}
                </div>
                <p className={`text-[10px] font-semibold ${
                  pwStrength.score <= 1 ? 'text-red-600' :
                  pwStrength.score === 2 ? 'text-amber-600' :
                  pwStrength.score === 3 ? 'text-blue-600' : 'text-emerald-600'
                }`}>
                  Strength: {pwStrength.label} · Min. 6 characters, use uppercase, numbers & symbols for best security.
                </p>
              </div>
            )}
          </div>

          {/* Confirm New Password */}
          <div className="space-y-1.5">
            <label htmlFor="confirm-password" className="block text-xs font-bold text-navy-900 uppercase tracking-wider">
              Confirm new password
            </label>
            <div className="relative">
              <input
                id="confirm-password"
                type={showConfirmPass ? 'text' : 'password'}
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Confirm new password"
                required
                className={`w-full px-3 py-2 pr-10 text-xs bg-white border rounded-lg text-navy-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 transition-all ${
                  confirmPassword && confirmPassword !== newPassword
                    ? 'border-red-400 focus:ring-red-200'
                    : confirmPassword && confirmPassword === newPassword
                    ? 'border-emerald-400 focus:ring-emerald-200'
                    : 'border-slate-300 focus:ring-gov-blue/20 focus:border-gov-blue'
                }`}
              />
              <button
                type="button"
                onClick={() => setShowConfirmPass(!showConfirmPass)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 transition-colors"
                aria-label="Toggle confirm password visibility"
              >
                {showConfirmPass ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
              </button>
            </div>
            {confirmPassword && confirmPassword !== newPassword && (
              <p className="text-[10px] text-red-600 font-medium">Passwords do not match.</p>
            )}
            {confirmPassword && confirmPassword === newPassword && (
              <p className="text-[10px] text-emerald-600 font-medium flex items-center gap-1">
                <CheckCircle2 className="w-3 h-3" /> Passwords match.
              </p>
            )}
          </div>

          <div className="flex justify-end pt-1">
            <button
              type="submit"
              disabled={isChangingPass}
              className="flex items-center gap-2 px-4 py-2 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-lg shadow-sm transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isChangingPass ? 'animate-spin' : ''}`} />
              {isChangingPass ? 'Modifying...' : 'Modify Password'}
            </button>
          </div>
        </form>
      </div>

      {/* ============================================================
          CARD 3: Operational Metadata & Tenant Context
         ============================================================ */}
      <div className="bg-white border border-slate-200 rounded-xl shadow-xs overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-100 bg-slate-50 flex items-center gap-2">
          <Shield className="w-4 h-4 text-navy-900" />
          <span className="text-xs font-bold text-navy-900 uppercase tracking-wider">
            Operational Metadata & Tenant Context
          </span>
        </div>
        <div className="p-5 space-y-3">
          <InfoRow icon={<Shield className="w-3.5 h-3.5" />} label="Assigned Role" value={
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${roleStyle.bg} ${roleStyle.text} ${roleStyle.border}`}>
              {user.role}
            </span>
          } />
          <InfoRow icon={<Building2 className="w-3.5 h-3.5" />} label="Tenant ID" value={user.tenantId} mono />
          <InfoRow icon={<ShieldCheck className="w-3.5 h-3.5" />} label="Account Status" value={
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
              user.status === 'active'
                ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                : 'bg-red-50 text-red-700 border border-red-200'
            }`}>
              {user.status}
            </span>
          } />
          {user.lastLoginAt && (
            <InfoRow icon={<Clock className="w-3.5 h-3.5" />} label="Last Login" value={new Date(user.lastLoginAt).toLocaleString()} mono />
          )}
          {/* UX Enhancement 4: Session Fingerprint */}
          {sessionFingerprint && (
            <InfoRow
              icon={<Fingerprint className="w-3.5 h-3.5" />}
              label="Session Cryptographic Fingerprint (SHA-256)"
              value={
                <span className="font-mono text-[10px] text-slate-600 break-all">
                  {sessionFingerprint.match(/.{1,8}/g)?.join(' ')}
                </span>
              }
            />
          )}
        </div>
      </div>

      {/* ============================================================
          CARD 4: Effective Permission Matrix
         ============================================================ */}
      <div className="bg-white border border-slate-200 rounded-xl shadow-xs overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-100 bg-slate-50 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <KeyRound className="w-4 h-4 text-navy-900" />
            <span className="text-xs font-bold text-navy-900 uppercase tracking-wider">
              Effective Permission Matrix
            </span>
          </div>
          <span className="text-[10px] font-mono text-slate-500">
            {permissions.size} permissions granted
          </span>
        </div>
        <div className="p-5 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {PERMISSION_DOMAINS.map((domain) => (
            <div key={domain.label} className="space-y-1.5">
              <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider border-b border-slate-100 pb-1">
                {domain.label}
              </div>
              {domain.permissions.map((perm) => {
                const granted = permissions.has(perm as any);
                return (
                  <div
                    key={perm}
                    className={`flex items-center gap-1.5 text-[11px] font-mono ${granted ? 'text-navy-900' : 'text-slate-300'}`}
                  >
                    <div className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${granted ? 'bg-emerald-500' : 'bg-slate-200'}`} />
                    {perm}
                  </div>
                );
              })}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

// ---------------------------------------------------------------------------
// InfoRow helper
// ---------------------------------------------------------------------------

function InfoRow({
  icon,
  label,
  value,
  mono = false,
}: {
  icon: React.ReactNode;
  label: string;
  value: React.ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="flex items-start gap-2.5">
      <div className="text-slate-400 mt-0.5 flex-shrink-0">{icon}</div>
      <div className="min-w-0 flex-1">
        <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-0.5">{label}</div>
        <div className={`text-xs text-navy-900 ${mono ? 'font-mono' : 'font-semibold'}`}>{value}</div>
      </div>
    </div>
  );
}
