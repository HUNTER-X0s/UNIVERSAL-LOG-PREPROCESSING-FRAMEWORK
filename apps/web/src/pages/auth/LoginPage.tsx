/**
 * LoginPage — ULPF Institutional Authentication
 *
 * - Fixed-width icon column (w-10) on both fields — eliminates icon/text collision
 * - Header label changed to "Authentication"
 * - Authorised Personnel panel has no scroll restriction — whole page scrolls naturally
 * - No bottom classification bar (top bar carries full context)
 */

import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { AlertTriangle, ChevronDown, Eye, EyeOff, Lock, Shield, User } from 'lucide-react';
import { useAuth } from '../../auth/AuthProvider';
import { applyAccountOverrides } from '../../auth/accountOverrides';
import { BrandLogo } from '../../components/ui/BrandLogo';

// ---------------------------------------------------------------------------
// Authorised operator accounts
// ---------------------------------------------------------------------------

interface AuthorizedAccount {
  username: string;
  displayName: string;
  role: string;
  password: string;
  avatarUrl?: string;
}

const AUTHORIZED_ACCOUNTS: AuthorizedAccount[] = [
  { username: 'pradyumna.biswal', displayName: 'PRADYUMNA BISWAL', role: 'Analyst',            password: 'Ulpf@N4!yst#8x2K' },
  { username: 'rajesh.marshall',  displayName: 'RAJESH MARSHALL',  role: 'Viewer',             password: 'Ulpf@V!3wer#4mZ9' },
  { username: 'rashu.kaithwas',   displayName: 'RASHI KAITHWAS',   role: 'Operator',           password: 'Ulpf@0p3r#7nR1q' },
  { username: 'swadheenta.jeenu', displayName: 'SWADHEENTA SAMAL', role: 'Threat Hunter',      password: 'Ulpf@H4nt3r#9kLm' },
  { username: 'Subhankar.Swain',  displayName: 'Subhankar Swain',  role: 'Detection Engineer', password: 'Ulpf@D3tect#2pQw' },
  { username: 'simran.swain',     displayName: 'SIMRAN SWAIN',     role: 'Mapping Reviewer',   password: 'Ulpf@R3v!ew#6sYt' },
  { username: 'jahanabi.dalai',   displayName: 'JAHANABI DALAI',   role: 'Mapping Admin',      password: 'Ulpf@Adm!n#3fGh' },
  { username: 'anurag.swain',     displayName: 'ANURAG SWAIN',     role: 'Platform Admin',     password: 'Ulpf@Pl@tf#1rM!x' },
];

const ROLE_STYLES: Record<string, string> = {
  'Analyst':              'bg-indigo-50 text-indigo-800 border-indigo-200',
  'Viewer':               'bg-slate-100 text-slate-700 border-slate-300',
  'Operator':             'bg-blue-50 text-blue-800 border-blue-200',
  'Threat Hunter':        'bg-amber-50 text-amber-800 border-amber-200',
  'Detection Engineer':   'bg-purple-50 text-purple-800 border-purple-200',
  'Mapping Reviewer':     'bg-teal-50 text-teal-800 border-teal-200',
  'Mapping Admin':        'bg-emerald-50 text-emerald-800 border-emerald-200',
  'Platform Admin':       'bg-red-50 text-red-800 border-red-200',
};

// ---------------------------------------------------------------------------
// Shared input field component — guarantees identical height, padding & alignment
// ---------------------------------------------------------------------------

interface FieldProps {
  id: string;
  type?: string;
  icon: React.ReactNode;
  rightElement?: React.ReactNode;
  placeholder: string;
  value: string;
  onChange: (v: string) => void;
  disabled?: boolean;
  autoComplete?: string;
  inputRef?: React.RefObject<HTMLInputElement>;
  required?: boolean;
}

const InputField: React.FC<FieldProps> = ({
  id, type = 'text', icon, rightElement, placeholder, value, onChange,
  disabled, autoComplete, inputRef, required,
}) => (
  <div className="relative w-full" style={{ borderRadius: '10px' }}>
    <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3.5 text-slate-400 select-none">
      {icon}
    </div>
    <input
      id={id}
      ref={inputRef as React.RefObject<HTMLInputElement> | undefined}
      type={type}
      autoComplete={autoComplete}
      spellCheck={false}
      placeholder={placeholder}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      disabled={disabled}
      required={required}
      style={{
        height: '46px',
        paddingLeft: '46px',
        paddingRight: rightElement ? '44px' : '16px',
        fontSize: '14.5px',
        lineHeight: '22px',
        borderRadius: '10px',
        boxSizing: 'border-box',
      }}
      className="block w-full border border-slate-300 bg-white text-navy-900 placeholder:text-slate-400 transition-colors focus:border-gov-blue focus:outline-none focus:ring-2 focus:ring-gov-blue disabled:opacity-50"
    />
    {rightElement && (
      <div className="absolute inset-y-0 right-0 flex items-center pr-3">
        {rightElement}
      </div>
    )}
  </div>
);

// ---------------------------------------------------------------------------
// LoginPage
// ---------------------------------------------------------------------------

export const LoginPage: React.FC = () => {
  const { login, isAuthenticated } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const from = (location.state as any)?.from?.pathname ?? '/command-center';

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [showPersonnel, setShowPersonnel] = useState(false);
  const usernameRef = useRef<HTMLInputElement>(null);
  const passwordRef = useRef<HTMLInputElement>(null);
  const prefetchedRef = useRef(false);

  // Prefetch the CommandCenter chunk as early as possible so it's ready
  // by the time login() resolves — overlapping network + JS parse time.
  const prefetchCommandCenter = useCallback(() => {
    if (prefetchedRef.current) return;
    prefetchedRef.current = true;
    import('../CommandCenter').catch(() => { /* non-fatal */ });
  }, []);

  // Reflect profile, username, password and avatar updates dynamically.
  // Re-computed whenever localStorage changes (storage event) or on focus so
  // username/password changes made in the Profile page are immediately visible.
  const [accounts, setAccounts] = useState(() => applyAccountOverrides(AUTHORIZED_ACCOUNTS));
  const refreshAccounts = useCallback(() => {
    setAccounts(applyAccountOverrides(AUTHORIZED_ACCOUNTS));
  }, []);

  useEffect(() => {
    // React to localStorage writes from this tab (storage event fires for other
    // tabs; for same-tab writes we also call refreshAccounts directly where needed).
    const onStorage = (e: StorageEvent) => {
      if (e.key === 'ulpf_account_overrides' || e.key === null) {
        refreshAccounts();
      }
    };
    window.addEventListener('storage', onStorage);
    // Also refresh when the window regains focus (user navigated away and came back)
    window.addEventListener('focus', refreshAccounts);
    return () => {
      window.removeEventListener('storage', onStorage);
      window.removeEventListener('focus', refreshAccounts);
    };
  }, [refreshAccounts]);

  useEffect(() => {
    // Redirect away from login if user is already authenticated
    // (e.g. navigated to /login manually while already logged in)
    if (isAuthenticated) {
      navigate(from, { replace: true });
    }
  }, [isAuthenticated, navigate, from]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password.trim()) {
      setError('Please enter your credentials to continue.');
      return;
    }
    setError(null);
    setIsSubmitting(true);
    // Prefetch the target page chunk immediately — runs in parallel with the API call.
    prefetchCommandCenter();
    try {
      await login({ username: username.trim(), password });
      navigate(from, { replace: true });
    } catch (err: unknown) {
      let msg = 'Authentication failed. Verify credentials and try again.';
      if (err instanceof Error) {
        msg = err.message;
        if (msg.trim().startsWith('{') && msg.trim().endsWith('}')) {
          try {
            const parsed = JSON.parse(msg);
            msg = parsed.message || parsed.detail || parsed.error || msg;
          } catch {
            /* keep msg */
          }
        }
      }
      setError(msg);
    } finally {
      setIsSubmitting(false);
    }
  };

  const selectAccount = (account: AuthorizedAccount) => {
    setUsername(account.username);
    setPassword(account.password);
    setError(null);
    setShowPersonnel(false);
    usernameRef.current?.focus();
  };

  return (
    /*
     * Layout: the outer div has NO overflow restriction.
     * Content taller than the viewport causes the browser's native page scroll
     * to activate — this is the cleanest and most reliable approach.
     * The classification banner sticks to the top via `sticky top-0`.
     */
    <div className="min-h-screen w-full bg-slate-100 flex flex-col">

      {/* Sticky classification banner */}
      <div className="sticky top-0 z-20 bg-navy-900 text-white text-center py-1.5 text-[10px] font-bold tracking-widest uppercase flex items-center justify-center gap-2 select-none">
        <Lock className="w-2.5 h-2.5" />
        SOVEREIGN TELEMETRY PLATFORM — AUTHORISED ACCESS ONLY
        <Lock className="w-2.5 h-2.5" />
      </div>

      {/* Page body — scrolls naturally */}
      <div className="flex-1 flex flex-col items-center px-4 pt-12 pb-24">
        <div className="w-full max-w-md">

          {/* Institutional identity */}
          <div className="text-center mb-8">
            <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-slate-950 border border-slate-800 shadow-xl mb-4 p-2.5">
              <BrandLogo size={46} />
            </div>
            <h1 className="text-lg font-bold text-navy-900 tracking-tight leading-tight">
              Universal Log Pre-processing Framework
            </h1>
            <p className="text-xs text-slate-500 font-medium mt-0.5">
              Security Telemetry Processing Platform
            </p>
            <div className="mt-3 inline-flex items-center gap-1.5 px-3 py-1 bg-slate-200 rounded-full text-[10px] font-mono font-semibold text-slate-600 uppercase tracking-wider">
              <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
              Sovereign-HQ — Restricted Access
            </div>
          </div>

          {/* Login card */}
          <div className="bg-white rounded-xl shadow-md border border-slate-200 overflow-hidden">

            {/* Card header — "Authentication" only */}
            <div className="px-6 py-4 border-b border-slate-100 bg-slate-50 flex items-center gap-2">
              <Shield className="w-4 h-4 text-navy-900" />
              <span className="text-sm font-semibold text-navy-900">Authentication</span>
            </div>

            {/* Form */}
            <form onSubmit={handleSubmit} className="px-6 py-6 space-y-4">
              {error && (
                <div
                  role="alert"
                  className="flex items-start gap-2.5 px-3.5 py-2.5 bg-red-50 border border-red-200 rounded-lg text-xs text-red-800"
                >
                  <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0 text-red-600" />
                  <div className="flex flex-col">
                    <span className="font-semibold text-red-900">Authentication Failed</span>
                    <span className="text-red-700 mt-0.5 leading-relaxed">{error}</span>
                  </div>
                </div>
              )}

              {/* Username */}
              <div className="space-y-1.5">
                <label htmlFor="login-username" className="block text-[11px] font-bold text-navy-900 uppercase tracking-wider">
                  Username
                </label>
                <InputField
                  id="login-username"
                  type="text"
                  icon={<User className="w-5 h-5" strokeWidth={2} />}
                  placeholder="Enter access identity"
                  value={username}
                  onChange={setUsername}
                  autoComplete="username"
                  inputRef={usernameRef}
                  disabled={isSubmitting}
                  required
                />
              </div>

              {/* Password */}
              <div className="space-y-1.5">
                <label htmlFor="login-password" className="block text-[11px] font-bold text-navy-900 uppercase tracking-wider">
                  Password
                </label>
                <InputField
                  id="login-password"
                  type={showPassword ? 'text' : 'password'}
                  icon={<Lock className="w-[18px] h-[18px]" strokeWidth={2} />}
                  rightElement={
                    <button
                      type="button"
                      onClick={() => setShowPassword((v) => !v)}
                      className="p-1 text-slate-400 hover:text-navy-900 focus:outline-none transition-colors"
                      tabIndex={-1}
                      title={showPassword ? 'Hide password' : 'Show password'}
                      aria-label={showPassword ? 'Hide password' : 'Show password'}
                    >
                      {showPassword ? (
                        <EyeOff className="w-4 h-4" />
                      ) : (
                        <Eye className="w-4 h-4" />
                      )}
                    </button>
                  }
                  placeholder="Enter access credential"
                  value={password}
                  onChange={setPassword}
                  autoComplete="current-password"
                  inputRef={passwordRef}
                  disabled={isSubmitting}
                  required
                />
              </div>

              {/* Submit */}
              <button
                id="login-submit"
                type="submit"
                disabled={isSubmitting || !username || !password}
                onMouseEnter={prefetchCommandCenter}
                onFocus={prefetchCommandCenter}
                className="w-full mt-1 flex items-center justify-center gap-2 px-4 py-2.5 bg-navy-900 text-white text-sm font-semibold rounded-lg hover:bg-navy-800 focus:outline-none focus:ring-2 focus:ring-gov-blue focus:ring-offset-1 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {isSubmitting ? (
                  <>
                    <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                    Authenticating…
                  </>
                ) : (
                  <>
                    <Shield className="w-3.5 h-3.5" />
                    Authenticate
                  </>
                )}
              </button>
            </form>

            {/* Authorised Personnel — no scroll restriction; page scrolls */}
            <div className="border-t border-slate-100">
              <button
                type="button"
                onClick={() => setShowPersonnel((v) => !v)}
                className="w-full flex items-center justify-between px-6 py-3 text-xs text-slate-500 hover:bg-slate-50 transition-colors"
                aria-expanded={showPersonnel}
              >
                <span className="font-semibold text-slate-600 uppercase tracking-wider text-[11px]">
                  Authorised Personnel
                </span>
                <ChevronDown className={`w-3.5 h-3.5 transition-transform duration-200 ${showPersonnel ? 'rotate-180' : ''}`} />
              </button>

              {showPersonnel && (
                /* No max-h, no overflow-y — content grows freely, page scrolls */
                <div className="px-4 pb-5 space-y-2">
                  {accounts.map((account) => (
                    <button
                      key={account.username}
                      type="button"
                      onClick={() => selectAccount(account)}
                      className="w-full text-left flex items-center justify-between px-4 py-2.5 rounded-lg border border-slate-200 hover:border-gov-blue hover:bg-slate-50 transition-colors"
                    >
                      <div className="flex items-center gap-3">
                        {account.avatarUrl ? (
                          <img
                            src={account.avatarUrl}
                            alt={account.displayName}
                            className="w-8 h-8 rounded-full object-cover border border-slate-200 flex-shrink-0 shadow-xs"
                          />
                        ) : (
                          <div className="w-8 h-8 rounded-full bg-navy-900 text-white flex items-center justify-center text-xs font-bold flex-shrink-0">
                            {account.displayName.charAt(0)}
                          </div>
                        )}
                        <div className="text-left">
                          <div className="text-xs font-semibold text-navy-900 leading-tight">
                            {account.displayName}
                          </div>
                          <div className="text-[10px] text-slate-400 font-mono mt-0.5">
                            {account.username}
                          </div>
                        </div>
                      </div>
                      <span className={`px-2 py-0.5 rounded border text-[9px] font-bold uppercase tracking-wide flex-shrink-0 ml-3 ${ROLE_STYLES[account.role] ?? 'bg-slate-100 text-slate-600 border-slate-200'}`}>
                        {account.role}
                      </span>
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>

        </div>
      </div>
    </div>
  );
};
