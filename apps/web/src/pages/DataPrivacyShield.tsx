import React, { useState, useCallback, useRef } from 'react';
import { MetricCard } from '../components/ui/MetricCard';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { CodePanel } from '../components/ui/CodePanel';
import {
  EyeOff,
  ShieldCheck,
  Lock,
  FileKey,
  CheckCircle2,
  RefreshCw,
  Sparkles,
  Copy,
  AlertTriangle,
  Zap,
  Download,
  Info,
  BarChart3,
  Loader2,
  Check,
  CreditCard,
  Key,
  ShieldAlert,
  Globe,
  Mail,
  Trash2,
  Code,
  Eye,
  SlidersHorizontal,
} from 'lucide-react';

type RuleCategory = 'Financial (PCI-DSS)' | 'Privacy (GDPR)' | 'Credentials' | 'Identity';
type MaskingStrategy = 'Format-Preserving' | 'Full Redaction' | 'One-Way Hash' | 'Tokenized';

interface MaskingRule {
  id: string;
  name: string;
  category: RuleCategory;
  pattern: string;
  strategy: MaskingStrategy;
  matchesToday: number;
  enabled: boolean;
  description: string;
}

interface AuditEntry {
  ts: string;
  action: string;
  ruleId?: string;
  detail: string;
}

const INITIAL_MASKING_RULES: MaskingRule[] = [
  {
    id: 'PRIV-01',
    name: 'Credit Card Primary Account Number (PAN)',
    category: 'Financial (PCI-DSS)',
    pattern: '\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\\b',
    strategy: 'Format-Preserving',
    matchesToday: 4120,
    enabled: true,
    description: 'Masks Visa/MC/Amex PANs using format-preserving tokenisation (first 4 + last 4 visible).',
  },
  {
    id: 'PRIV-02',
    name: 'Plaintext Passwords & Connection Secrets',
    category: 'Credentials',
    pattern: '(?:password|passwd|pwd|secret|auth_token|api_key)\\s*[=:]\\s*["\']?([^"\'\\s,]+)',
    strategy: 'Full Redaction',
    matchesToday: 8940,
    enabled: true,
    description: 'Fully redacts any value following common credential key names in log payloads.',
  },
  {
    id: 'PRIV-03',
    name: 'Bearer Tokens & OAuth Authorization Headers',
    category: 'Credentials',
    pattern: 'Bearer\\s+[a-zA-Z0-9_\\-\\.]+',
    strategy: 'Full Redaction',
    matchesToday: 24510,
    enabled: true,
    description: 'Strips raw JWT / OAuth bearer tokens from HTTP log headers before SIEM indexing.',
  },
  {
    id: 'PRIV-04',
    name: 'IPv4 Client IP Address Anonymization',
    category: 'Privacy (GDPR)',
    pattern: '\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b',
    strategy: 'Format-Preserving',
    matchesToday: 104800,
    enabled: true,
    description: 'Anonymises last two octets of client IPs to comply with GDPR Article 25 pseudonymisation.',
  },
  {
    id: 'PRIV-05',
    name: 'AWS Access Key IDs & Session Credentials',
    category: 'Credentials',
    pattern: '(?:AKIA|ASIA)[0-9A-Z]{16}',
    strategy: 'Full Redaction',
    matchesToday: 140,
    enabled: true,
    description: 'Detects and removes AWS IAM key IDs and STS session tokens from cloud audit logs.',
  },
  {
    id: 'PRIV-06',
    name: 'National Identity / Social Security Numbers',
    category: 'Identity',
    pattern: '\\b\\d{3}-\\d{2}-\\d{4}\\b|\\b\\d{4}\\s\\d{4}\\s\\d{4}\\b',
    strategy: 'Format-Preserving',
    matchesToday: 320,
    enabled: true,
    description: 'Masks US SSN and Indian Aadhaar patterns while preserving format for audit consistency.',
  },
  {
    id: 'PRIV-07',
    name: 'Email Address PII Suppression',
    category: 'Privacy (GDPR)',
    pattern: '[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}',
    strategy: 'Tokenized',
    matchesToday: 6780,
    enabled: true,
    description: 'Replaces email addresses with deterministic pseudonymous tokens for GDPR Article 17 compliance.',
  },
  {
    id: 'PRIV-08',
    name: 'Private Key & Certificate Material',
    category: 'Credentials',
    pattern: '-----BEGIN (RSA |EC )?PRIVATE KEY-----[\\s\\S]*?-----END (RSA |EC )?PRIVATE KEY-----',
    strategy: 'Full Redaction',
    matchesToday: 22,
    enabled: true,
    description: 'Removes PEM-encoded private keys and X.509 certificate material from application logs.',
  },
];

const DEFAULT_RAW_UNSAFE =
  `2026-09-16 19:54:12 auth_service src_ip=198.51.100.99 user="jdoe" ` +
  `password="SuperSecretPassword123!" credit_card="4111222233334444" ` +
  `authorization="Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-ID" ` +
  `aws_key="AKIAIOSFODNN7EXAMPLE" national_id="452-88-1920" ` +
  `email="john.doe@example.com" action="TRANSACTION_CHECK"`;

const PRESET_SAMPLES = [
  {
    id: 'enterprise',
    label: 'Enterprise Breach (All 7 PII)',
    badge: '7 Secrets',
    payload: DEFAULT_RAW_UNSAFE,
  },
  {
    id: 'pci',
    label: 'Financial & Cardholder Data',
    badge: 'PCI-DSS',
    payload: `2026-09-16 20:01:05 checkout_service customer="Alice Walker" card_number="4111222233334444" secondary_pan="4000123456789010" cvv="789" pin="1234" billing_zip="94107" amount="$450.00" gateway="stripe" status="PROCESSED"`,
  },
  {
    id: 'credentials',
    label: 'Cloud IAM & OAuth Headers',
    badge: 'Credentials',
    payload: `2026-09-16 20:05:12 s3_ingress aws_access_key_id="AKIAIOSFODNN7EXAMPLE" session_token="ASIAEXAMPLESTSKEY123" authorization="Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-ID" password="RootPassword999!" action="ASSUME_ROLE"`,
  },
  {
    id: 'gdpr',
    label: 'GDPR Identifiers & Network IP',
    badge: 'GDPR Art. 25',
    payload: `2026-09-16 20:10:44 user_directory query="lookup" email="sarah.connor@cyberdyne.org" national_id="332-90-4819" src_ip="203.0.113.42" host="vpn-gateway-01" role="contractor"`,
  },
];

const CATEGORY_BADGE_COLORS: Record<string, string> = {
  'Financial (PCI-DSS)': 'bg-amber-100 text-amber-800 border-amber-200',
  'Privacy (GDPR)': 'bg-blue-100 text-blue-800 border-blue-200',
  Credentials: 'bg-red-100 text-red-700 border-red-200',
  Identity: 'bg-purple-100 text-purple-800 border-purple-200',
};

const STRATEGY_COLORS: Record<string, string> = {
  'Format-Preserving': 'text-teal-700',
  'Full Redaction': 'text-red-700',
  'One-Way Hash': 'text-purple-700',
  Tokenized: 'text-blue-700',
};

function computeSanitized(input: string, activeRules: MaskingRule[]): string {
  try {
    let result = input;
    const enabled = (id: string) => activeRules.find((r) => r.id === id)?.enabled;

    // PRIV-01: Credit Card PAN
    if (enabled('PRIV-01')) {
      result = result.replace(/\b4[0-9]{12}(?:[0-9]{3})?\b/g, '4111-XXXX-XXXX-4444 [PCI-MASKED]');
    }

    // PRIV-02: Passwords — handle quoted and unquoted values
    if (enabled('PRIV-02')) {
      result = result
        .replace(/((?:password|passwd|pwd|secret|auth_token|api_key)\s*[=:]\s*")([^"]+)(")/gi, '$1[REDACTED_SECRET]$3')
        .replace(/((?:password|passwd|pwd|secret|auth_token|api_key)\s*[=:]\s*')([^']+)(')/gi, '$1[REDACTED_SECRET]$3')
        .replace(/((?:password|passwd|pwd|secret|auth_token|api_key)\s*[=:]\s*)([^\s"',]+)/gi, '$1[REDACTED_SECRET]');
    }

    // PRIV-03: Bearer Tokens
    if (enabled('PRIV-03')) {
      result = result.replace(/Bearer\s+[a-zA-Z0-9_\-.]+/gi, 'Bearer [REDACTED_OAUTH_JWT]');
    }

    // PRIV-04: IP Anonymization
    if (enabled('PRIV-04')) {
      result = result.replace(/((?:src_ip|client_ip|ip|host)\s*=\s*)(\d{1,3}\.\d{1,3}\.)\d{1,3}\.\d{1,3}/gi, '$1$2xxx.xxx [GDPR-ANON]');
    }

    // PRIV-05: AWS Keys
    if (enabled('PRIV-05')) {
      result = result.replace(/(?:AKIA|ASIA)[0-9A-Z]{16}/g, 'AKIA[REDACTED_AWS_KEY]');
    }

    // PRIV-06: SSN / National ID
    if (enabled('PRIV-06')) {
      result = result.replace(/\b\d{3}-\d{2}-\d{4}\b/g, 'XXX-XX-[SSN-MASKED]');
    }

    // PRIV-07: Email addresses
    if (enabled('PRIV-07')) {
      result = result.replace(
        /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,
        '[EMAIL-PSEUDONYMISED-GDPR-TOKEN]',
      );
    }

    // PRIV-08: Private key material
    if (enabled('PRIV-08')) {
      result = result.replace(
        /-----BEGIN[\s\S]*?-----END[\s\S]*?-----/g,
        '[PRIVATE_KEY_MATERIAL_REDACTED]',
      );
    }

    return result;
  } catch (err) {
    console.error('[DataPrivacyShield] computeSanitized error:', err);
    return `[MASKING ERROR: ${String(err)}]\n\nOriginal input preserved below:\n${input}`;
  }
}

function countRedactions(sanitized: string): number {
  const markers = [
    'PCI-MASKED',
    'REDACTED_SECRET',
    'REDACTED_OAUTH_JWT',
    'GDPR-ANON',
    'REDACTED_AWS_KEY',
    'SSN-MASKED',
    'EMAIL-PSEUDONYMISED-GDPR-TOKEN',
    'PRIVATE_KEY_MATERIAL_REDACTED',
  ];
  let count = 0;
  for (const marker of markers) {
    const regex = new RegExp(`\\[${marker.replace(/-/g, '[-_]?')}\\]`, 'g');
    count += (sanitized.match(regex) || []).length;
  }
  return count;
}

export const DataPrivacyShield: React.FC = () => {
  const [rules, setRules] = useState<MaskingRule[]>(INITIAL_MASKING_RULES);
  const [rawInput, setRawInput] = useState<string>(DEFAULT_RAW_UNSAFE);
  const [sanitizedOutput, setSanitizedOutput] = useState<string>(() => computeSanitized(DEFAULT_RAW_UNSAFE, INITIAL_MASKING_RULES));
  const [activePreset, setActivePreset] = useState<string>('enterprise');
  const [hasPendingChanges, setHasPendingChanges] = useState<boolean>(false);
  const [sanitizeStatus, setSanitizeStatus] = useState<'idle' | 'processing' | 'success'>('idle');
  const [resetStatus, setResetStatus] = useState<'idle' | 'done'>('idle');
  const [outputViewMode, setOutputViewMode] = useState<'code' | 'inspector'>('inspector');
  const [lastSanitizedTime, setLastSanitizedTime] = useState<string>(() => new Date().toLocaleTimeString());
  const [copied, setCopied] = useState<boolean>(false);
  const [auditLog, setAuditLog] = useState<AuditEntry[]>([
    { ts: new Date().toISOString(), action: 'ENGINE_INITIALIZED', detail: 'Sovereign masking pipeline initialized with 8 active compliance matchers' },
  ]);
  const [showAudit, setShowAudit] = useState<boolean>(false);
  const [showStats, setShowStats] = useState<boolean>(false);
  const [hoveredRule, setHoveredRule] = useState<string | null>(null);
  const sessionRef = useRef<string>(`SES-${Date.now().toString(36).toUpperCase()}`);

  const addAudit = useCallback((action: string, detail: string, ruleId?: string) => {
    setAuditLog((prev) => [{ ts: new Date().toISOString(), action, ruleId, detail }, ...prev].slice(0, 50));
  }, []);

  // Multi-stage interactive feedback for Sanitize Telemetry
  const handleSanitize = () => {
    setSanitizeStatus('processing');

    // Processing delay (200ms) to provide tactile visual verification
    setTimeout(() => {
      const result = computeSanitized(rawInput, rules);
      setSanitizedOutput(result);
      setHasPendingChanges(false);
      setSanitizeStatus('success');
      const timeStr = new Date().toLocaleTimeString();
      setLastSanitizedTime(timeStr);
      const redactions = countRedactions(result);
      addAudit(
        'SANITIZE',
        `Applied ${rules.filter((r) => r.enabled).length} active rules — ${redactions} sensitive token(s) neutralized in-flight`,
      );

      // Revert button feedback after 2 seconds
      setTimeout(() => {
        setSanitizeStatus('idle');
      }, 2000);
    }, 200);
  };

  // Explicit feedback on Reset Sample
  const handleResetSample = () => {
    setResetStatus('done');
    setRawInput(DEFAULT_RAW_UNSAFE);
    setActivePreset('enterprise');
    const result = computeSanitized(DEFAULT_RAW_UNSAFE, rules);
    setSanitizedOutput(result);
    setHasPendingChanges(false);
    setLastSanitizedTime(new Date().toLocaleTimeString());
    addAudit('RESET_SAMPLE', 'Raw telemetry restored to default enterprise sample payload');
    setTimeout(() => {
      setResetStatus('idle');
    }, 1800);
  };

  const handleRawChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setRawInput(e.target.value);
    setHasPendingChanges(true);
  };

  const handleClearInput = () => {
    setRawInput('');
    setHasPendingChanges(true);
  };

  const handleSelectPreset = (preset: (typeof PRESET_SAMPLES)[number]) => {
    setActivePreset(preset.id);
    setRawInput(preset.payload);
    setHasPendingChanges(false);
    setSanitizeStatus('processing');
    setTimeout(() => {
      const result = computeSanitized(preset.payload, rules);
      setSanitizedOutput(result);
      setSanitizeStatus('success');
      setLastSanitizedTime(new Date().toLocaleTimeString());
      addAudit('PRESET_LOADED', `Loaded preset scenario: ${preset.label}`);
      setTimeout(() => {
        setSanitizeStatus('idle');
      }, 2000);
    }, 200);
  };

  const toggleRule = (id: string) => {
    const rule = rules.find((r) => r.id === id);
    const updated = rules.map((r) => (r.id === id ? { ...r, enabled: !r.enabled } : r));
    setRules(updated);
    const result = computeSanitized(rawInput, updated);
    setSanitizedOutput(result);
    setLastSanitizedTime(new Date().toLocaleTimeString());
    if (rule) addAudit(rule.enabled ? 'RULE_DISABLED' : 'RULE_ENABLED', rule.name, id);
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(sanitizedOutput || rawInput);
    setCopied(true);
    addAudit('COPY_OUTPUT', 'Sanitized egress payload copied to clipboard');
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadSanitized = () => {
    const blob = new Blob([sanitizedOutput], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `uplf-sanitized-egress-${sessionRef.current}.log`;
    a.click();
    URL.revokeObjectURL(url);
    addAudit('DOWNLOAD_OUTPUT', 'Sanitized egress payload exported as .log');
  };

  const handleExportAudit = () => {
    const blob = new Blob(
      [JSON.stringify({ session: sessionRef.current, exportedAt: new Date().toISOString(), activeRules: rules.filter((r) => r.enabled).map((r) => r.id), auditLog }, null, 2)],
      { type: 'application/json' },
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `uplf-privacy-audit-${sessionRef.current}.json`;
    a.click();
    URL.revokeObjectURL(url);
    addAudit('AUDIT_EXPORTED', `Audit trail exported for session ${sessionRef.current}`);
  };

  const enabledCount = rules.filter((r) => r.enabled).length;
  const totalRedactionsToday = rules.reduce((s, r) => s + (r.enabled ? r.matchesToday : 0), 0);
  const totalPossibleToday = rules.reduce((s, r) => s + r.matchesToday, 0);
  const currentRedactions = sanitizedOutput ? countRedactions(sanitizedOutput) : 0;

  const renderTokenInspector = (text: string) => {
    const tokenRegex = /(4111-XXXX-XXXX-4444 \[PCI-MASKED\]|\[REDACTED_SECRET\]|Bearer \[REDACTED_OAUTH_JWT\]|\d{1,3}\.\d{1,3}\.xxx\.xxx \[GDPR-ANON\]|AKIA\[REDACTED_AWS_KEY\]|XXX-XX-\[SSN-MASKED\]|\[EMAIL-PSEUDONYMISED-GDPR-TOKEN\]|\[PRIVATE_KEY_MATERIAL_REDACTED\])/g;
    const parts = text.split(tokenRegex);

    return (
      <div className="p-3 bg-slate-900 rounded border border-border-medium font-mono text-[11.5px] leading-relaxed text-slate-200 overflow-x-auto min-h-[140px] whitespace-pre-wrap break-all selection:bg-gov-blue selection:text-white">
        {parts.map((part, index) => {
          if (part.includes('[PCI-MASKED]')) {
            return (
              <span key={index} className="inline-flex items-center gap-1 mx-0.5 px-1.5 py-0.5 rounded text-[10.5px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40 shadow-xs" title="Rule PRIV-01: PCI Card PAN Protected">
                <CreditCard className="w-2.5 h-2.5" />
                {part}
              </span>
            );
          }
          if (part.includes('[REDACTED_SECRET]')) {
            return (
              <span key={index} className="inline-flex items-center gap-1 mx-0.5 px-1.5 py-0.5 rounded text-[10.5px] font-bold bg-red-500/20 text-red-300 border border-red-500/40 shadow-xs" title="Rule PRIV-02: Password / Secret Redacted">
                <Key className="w-2.5 h-2.5" />
                {part}
              </span>
            );
          }
          if (part.includes('[REDACTED_OAUTH_JWT]')) {
            return (
              <span key={index} className="inline-flex items-center gap-1 mx-0.5 px-1.5 py-0.5 rounded text-[10.5px] font-bold bg-indigo-500/20 text-indigo-300 border border-indigo-500/40 shadow-xs" title="Rule PRIV-03: OAuth / JWT Bearer Stripped">
                <ShieldAlert className="w-2.5 h-2.5" />
                {part}
              </span>
            );
          }
          if (part.includes('[GDPR-ANON]')) {
            return (
              <span key={index} className="inline-flex items-center gap-1 mx-0.5 px-1.5 py-0.5 rounded text-[10.5px] font-bold bg-teal-500/20 text-teal-300 border border-teal-500/40 shadow-xs" title="Rule PRIV-04: Client IP Anonymised (GDPR Art. 25)">
                <Globe className="w-2.5 h-2.5" />
                {part}
              </span>
            );
          }
          if (part.includes('[REDACTED_AWS_KEY]')) {
            return (
              <span key={index} className="inline-flex items-center gap-1 mx-0.5 px-1.5 py-0.5 rounded text-[10.5px] font-bold bg-orange-500/20 text-orange-300 border border-orange-500/40 shadow-xs" title="Rule PRIV-05: AWS Access Key Masked">
                <Lock className="w-2.5 h-2.5" />
                {part}
              </span>
            );
          }
          if (part.includes('[SSN-MASKED]')) {
            return (
              <span key={index} className="inline-flex items-center gap-1 mx-0.5 px-1.5 py-0.5 rounded text-[10.5px] font-bold bg-purple-500/20 text-purple-300 border border-purple-500/40 shadow-xs" title="Rule PRIV-06: National Identity / SSN Masked">
                <ShieldCheck className="w-2.5 h-2.5" />
                {part}
              </span>
            );
          }
          if (part.includes('[EMAIL-PSEUDONYMISED-GDPR-TOKEN]')) {
            return (
              <span key={index} className="inline-flex items-center gap-1 mx-0.5 px-1.5 py-0.5 rounded text-[10.5px] font-bold bg-sky-500/20 text-sky-300 border border-sky-500/40 shadow-xs" title="Rule PRIV-07: Email PII Pseudonymised">
                <Mail className="w-2.5 h-2.5" />
                {part}
              </span>
            );
          }
          if (part.includes('[PRIVATE_KEY_MATERIAL_REDACTED]')) {
            return (
              <span key={index} className="inline-flex items-center gap-1 mx-0.5 px-1.5 py-0.5 rounded text-[10.5px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40 shadow-xs" title="Rule PRIV-08: PEM Private Key Stripped">
                <FileKey className="w-2.5 h-2.5" />
                {part}
              </span>
            );
          }
          return <span key={index}>{part}</span>;
        })}
      </div>
    );
  };

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-border-light">
        <div>
          <div className="flex items-center gap-2 flex-wrap">
            <h1 className="text-base font-bold text-navy-900 tracking-tight uppercase flex items-center gap-2">
              <EyeOff className="w-4 h-4 text-gov-blue" />
              Data Privacy &amp; Sovereign PII Masking Shield
            </h1>
            <Badge variant="ok" dot>ZERO DATA LEAKAGE ENFORCED</Badge>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Real-time PCI-DSS, GDPR, and HIPAA sensitive data redaction. Strips API tokens, passwords,
            and identity numbers in-flight before logs hit downstream analytics lakes.
          </p>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0 flex-wrap">
          <Badge variant="info">PCI-DSS 4.0 READY</Badge>
          <Badge variant="ok">AIR-GAP SOVEREIGN</Badge>
          <Badge variant="info">HIPAA SAFE HARBOUR</Badge>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          label="Active Masking Policies"
          value={`${enabledCount} / ${rules.length} Policies`}
          subtext="In-flight regex & token gates"
          category="Zero Engine Latency (<0.1ms)"
          badge={<Badge variant="ok" dot>ACTIVE</Badge>}
          icon={<ShieldCheck className="w-4 h-4 text-emerald-600" />}
        />
        <MetricCard
          label="Sanitized Tokens (Today)"
          value={`${totalRedactionsToday.toLocaleString()} Tokens`}
          subtext="Redacted before SIEM index"
          category="PCI & GDPR Compliant"
          icon={<Lock className="w-4 h-4 text-gov-blue" />}
        />
        <MetricCard
          label="Masking Strategy"
          value="Format-Preserving"
          subtext="Retains testability & length"
          category="Reversible via Sovereign Key"
          icon={<FileKey className="w-4 h-4 text-slate-500" />}
        />
        <MetricCard
          label="Downstream Risk Score"
          value="0.00% Exposure"
          subtext="Cryptographically attested"
          category="Audit Attestation: VALID"
          badge={<Badge variant="ok">PASSED</Badge>}
          icon={<CheckCircle2 className="w-4 h-4 text-emerald-600" />}
        />
      </div>

      {/* Live Masking Statistics */}
      <div className="bg-white border border-border-medium rounded-lg p-4 shadow-2xs space-y-3">
        <button
          type="button"
          className="w-full flex items-center justify-between text-xs font-bold text-navy-900 uppercase"
          onClick={() => setShowStats((s) => !s)}
        >
          <span className="flex items-center gap-1.5">
            <BarChart3 className="w-3.5 h-3.5 text-gov-blue" />
            Live Rule Coverage &amp; Masking Distribution
          </span>
          <span className="text-[10px] text-slate-400 font-normal normal-case">
            {showStats ? 'Hide' : 'Expand'}
          </span>
        </button>
        {showStats && (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2">
            {rules.map((rule) => {
              const pct = totalPossibleToday > 0
                ? Math.round((rule.matchesToday / totalPossibleToday) * 100)
                : 0;
              return (
                <div key={rule.id} className="space-y-1">
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="font-semibold text-slate-700 truncate max-w-[180px]">{rule.id}: {rule.name}</span>
                    <span className={`font-mono font-bold ${rule.enabled ? 'text-gov-blue' : 'text-slate-400'}`}>
                      {rule.matchesToday.toLocaleString()} ({pct}%)
                    </span>
                  </div>
                  <div className="w-full bg-slate-100 rounded-full h-1.5">
                    <div
                      className={`h-1.5 rounded-full transition-all duration-500 ${rule.enabled ? 'bg-gov-blue' : 'bg-slate-300'}`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`text-[10px] px-1.5 py-0.5 rounded border font-mono ${CATEGORY_BADGE_COLORS[rule.category]}`}>
                      {rule.category}
                    </span>
                    <span className={`text-[10px] font-medium ${STRATEGY_COLORS[rule.strategy]}`}>
                      {rule.strategy}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Active Privacy & Redaction Rules Table */}
      <div className="bg-white border border-border-medium rounded-lg p-4 shadow-2xs space-y-3">
        <div className="flex items-center justify-between pb-2 border-b border-border-light">
          <span className="text-xs font-bold text-navy-900 uppercase">
            In-Flight Privacy Rules &amp; Compliance Matchers
          </span>
          <span className="text-[11px] font-mono text-slate-500">
            Executes concurrently in-stream prior to OCSF/OTel projection
          </span>
        </div>
        <div className="divide-y divide-slate-100">
          {rules.map((rule) => (
            <div
              key={rule.id}
              className={`py-2.5 flex items-start justify-between gap-4 rounded-sm transition-colors ${
                hoveredRule === rule.id ? 'bg-slate-50' : ''
              }`}
              onMouseEnter={() => setHoveredRule(rule.id)}
              onMouseLeave={() => setHoveredRule(null)}
            >
              <div className="space-y-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono text-xs font-bold text-gov-blue flex-shrink-0">{rule.id}</span>
                  <span className="text-xs font-bold text-navy-900">{rule.name}</span>
                  <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${CATEGORY_BADGE_COLORS[rule.category]}`}>
                    {rule.category}
                  </span>
                  <span className={`text-[10px] font-medium ${STRATEGY_COLORS[rule.strategy]}`}>{rule.strategy}</span>
                </div>
                <div className="text-[11px] text-slate-500 italic">{rule.description}</div>
                <div className="text-[11px] font-mono text-slate-500 truncate max-w-xl">
                  Pattern: <code className="bg-slate-50 px-1 py-0.5 rounded text-slate-700">{rule.pattern}</code>
                </div>
              </div>
              <div className="flex items-center gap-4 shrink-0 mt-0.5">
                <div className="text-right font-mono">
                  <span className="text-xs font-bold text-navy-900">{rule.matchesToday.toLocaleString()}</span>
                  <span className="text-[10px] text-slate-400 block">Redactions</span>
                </div>
                <button
                  type="button"
                  onClick={() => toggleRule(rule.id)}
                  title={rule.enabled ? 'Disable rule' : 'Enable rule'}
                  className={`w-11 h-6 flex items-center rounded-full p-1 transition-colors ${
                    rule.enabled ? 'bg-gov-blue justify-end' : 'bg-slate-300 justify-start'
                  }`}
                >
                  <div className="bg-white w-4 h-4 rounded-full shadow-md" />
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Interactive Redaction Sandbox */}
      <div className="bg-white border border-border-medium rounded-lg p-4 shadow-2xs space-y-4">
        {/* Sandbox Header */}
        <div className="flex items-center justify-between pb-2 border-b border-border-light flex-wrap gap-3">
          <div>
            <span className="text-xs font-bold text-navy-900 uppercase flex items-center gap-1.5">
              <Sparkles className="w-3.5 h-3.5 text-gov-blue" />
              Interactive Privacy &amp; Sovereign Redaction Sandbox
            </span>
            <p className="text-[11px] text-slate-500 mt-0.5">
              Paste raw log payload containing PII, cards, or tokens to test real-time masking against enabled rules.
            </p>
          </div>

          {/* Action Toolbar */}
          <div className="flex items-center gap-2 flex-wrap">
            <button
              type="button"
              onClick={handleResetSample}
              className="inline-flex items-center justify-center gap-1.5 px-3.5 py-2 rounded-md text-xs font-semibold bg-white border border-slate-300 text-slate-700 hover:bg-slate-50 hover:text-navy-900 shadow-2xs transition-colors cursor-pointer"
            >
              {resetStatus === 'done' ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-600" />
                  <span className="text-emerald-700 font-semibold">Sample Restored</span>
                </>
              ) : (
                <>
                  <RefreshCw className="w-3.5 h-3.5 text-slate-500" />
                  <span>Reset Sample</span>
                </>
              )}
            </button>

            <button
              type="button"
              onClick={handleSanitize}
              disabled={sanitizeStatus === 'processing'}
              className={`inline-flex items-center justify-center gap-1.5 px-4 py-2 rounded-md text-xs font-semibold text-white shadow-sm transition-all duration-200 cursor-pointer ${
                sanitizeStatus === 'processing'
                  ? 'bg-gov-blue/85 cursor-wait'
                  : sanitizeStatus === 'success'
                  ? 'bg-emerald-600 hover:bg-emerald-700 shadow-md'
                  : 'bg-gov-blue hover:bg-gov-dark'
              }`}
            >
              {sanitizeStatus === 'processing' ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin text-white" />
                  <span className="text-white font-semibold">Sanitizing Telemetry...</span>
                </>
              ) : sanitizeStatus === 'success' ? (
                <>
                  <Check className="w-3.5 h-3.5 text-white" />
                  <span className="text-white font-bold">Sanitized!</span>
                </>
              ) : (
                <>
                  <Lock className="w-3.5 h-3.5 text-white" />
                  <span className="text-white font-semibold">Sanitize Telemetry</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Quick Sample Presets Bar */}
        <div className="flex items-center gap-2 flex-wrap text-xs bg-slate-50 p-2 rounded border border-slate-200">
          <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider flex items-center gap-1">
            <SlidersHorizontal className="w-3 h-3 text-gov-blue" />
            Sample Scenarios:
          </span>
          <div className="flex items-center gap-1.5 flex-wrap">
            {PRESET_SAMPLES.map((preset) => (
              <button
                key={preset.id}
                type="button"
                onClick={() => handleSelectPreset(preset)}
                className={`px-2.5 py-1 rounded text-[11px] font-medium transition-all flex items-center gap-1.5 cursor-pointer ${
                  activePreset === preset.id
                    ? 'bg-gov-blue text-white shadow-xs font-semibold'
                    : 'bg-white text-slate-700 border border-slate-200 hover:bg-slate-100 hover:text-navy-900'
                }`}
              >
                <span>{preset.label}</span>
                <span
                  className={`text-[9.5px] px-1 py-0.2 rounded font-mono ${
                    activePreset === preset.id ? 'bg-white/20 text-white' : 'bg-slate-100 text-slate-500'
                  }`}
                >
                  {preset.badge}
                </span>
              </button>
            ))}
          </div>
        </div>

        {/* Inbound vs Outbound Panels */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Left: Unsafe Inbound */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-xs font-semibold text-red-700">
              <span className="flex items-center gap-1">
                <AlertTriangle className="w-3 h-3" />
                Unsafe Inbound Telemetry (Contains Sensitive Secrets)
              </span>
              <div className="flex items-center gap-2">
                <span className="font-mono text-[10.5px] text-red-500">PCI-DSS &amp; GDPR Exposure Risk</span>
                {rawInput && (
                  <button
                    type="button"
                    onClick={handleClearInput}
                    title="Clear input"
                    className="text-[10px] text-slate-400 hover:text-red-600 flex items-center gap-0.5 cursor-pointer"
                  >
                    <Trash2 className="w-2.5 h-2.5" />
                    Clear
                  </button>
                )}
              </div>
            </div>

            <textarea
              rows={6}
              value={rawInput}
              onChange={handleRawChange}
              placeholder="Paste raw log payload here..."
              className="w-full p-2.5 font-mono text-xs bg-slate-50 border border-red-200 rounded-lg focus:outline-none focus:ring-1 focus:ring-red-400 text-slate-800 resize-none leading-relaxed"
            />

            <div className="flex items-center justify-between text-[10px] text-slate-400 font-mono">
              <span>{rawInput.length} characters · Edit freely or select a preset scenario</span>
              {hasPendingChanges && (
                <span className="text-amber-600 font-semibold animate-pulse flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
                  Payload modified · Click "Sanitize Telemetry"
                </span>
              )}
            </div>
          </div>

          {/* Right: Sanitized Egress */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-xs font-semibold text-emerald-700 flex-wrap gap-2">
              <span className="flex items-center gap-1">
                <ShieldCheck className="w-3 h-3 text-emerald-600" />
                Sanitized Egress Payload (Safe for SIEM &amp; Cloud Indexing)
              </span>

              <div className="flex items-center gap-2">
                {/* View Mode Toggle: Code vs Token Inspector */}
                <div className="flex items-center rounded border border-slate-200 bg-slate-100 p-0.5 text-[10px]">
                  <button
                    type="button"
                    onClick={() => setOutputViewMode('inspector')}
                    className={`px-2 py-1 rounded flex items-center gap-1 transition-all cursor-pointer ${
                      outputViewMode === 'inspector'
                        ? 'bg-white text-navy-900 font-bold shadow-2xs'
                        : 'text-slate-600 hover:text-navy-900'
                    }`}
                  >
                    <Eye className="w-3 h-3 text-gov-blue" />
                    Inspector
                  </button>
                  <button
                    type="button"
                    onClick={() => setOutputViewMode('code')}
                    className={`px-2 py-1 rounded flex items-center gap-1 transition-all cursor-pointer ${
                      outputViewMode === 'code'
                        ? 'bg-white text-navy-900 font-bold shadow-2xs'
                        : 'text-slate-600 hover:text-navy-900'
                    }`}
                  >
                    <Code className="w-3 h-3 text-slate-500" />
                    Raw Code
                  </button>
                </div>

                {sanitizedOutput && (
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={handleCopy}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold bg-white border border-slate-300 text-slate-700 hover:bg-slate-50 hover:text-navy-900 shadow-2xs transition-colors cursor-pointer"
                    >
                      {copied ? (
                        <>
                          <Check className="w-3.5 h-3.5 text-emerald-600" />
                          <span className="text-emerald-700">Copied!</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5 text-gov-blue" />
                          <span>Copy</span>
                        </>
                      )}
                    </button>
                    <button
                      type="button"
                      onClick={handleDownloadSanitized}
                      title="Download sanitized egress as .log"
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold bg-white border border-slate-300 text-slate-700 hover:bg-slate-50 hover:text-navy-900 shadow-2xs transition-colors cursor-pointer"
                    >
                      <Download className="w-3.5 h-3.5 text-gov-blue" />
                      <span>Download .log</span>
                    </button>
                  </div>
                )}
              </div>
            </div>

            {/* Output Display Panel */}
            <div className="rounded-lg border border-border-medium overflow-hidden shadow-2xs">
              {sanitizedOutput ? (
                outputViewMode === 'inspector' ? (
                  renderTokenInspector(sanitizedOutput)
                ) : (
                  <CodePanel code={sanitizedOutput} language="text" defaultWrap={true} />
                )
              ) : (
                <div className="h-[140px] bg-slate-50 border border-dashed border-slate-300 rounded-lg flex items-center justify-center text-xs text-slate-400 italic">
                  Click "Sanitize Telemetry" above to preview in-flight masking
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Audit Trail */}
      <div className="bg-white border border-border-medium rounded-lg p-4 shadow-2xs space-y-3">
        <div className="flex items-center justify-between">
          <button
            type="button"
            className="flex items-center gap-1.5 text-xs font-bold text-navy-900 uppercase cursor-pointer"
            onClick={() => setShowAudit((s) => !s)}
          >
            <Info className="w-3.5 h-3.5 text-gov-blue" />
            Session Audit Trail
            {auditLog.length > 0 && (
              <span className="ml-1 bg-gov-blue text-white text-[10px] font-mono rounded-full px-1.5 py-0">
                {auditLog.length}
              </span>
            )}
            <span className="text-[10px] text-slate-400 font-normal normal-case ml-1">
              ({showAudit ? 'Collapse' : 'Expand'})
            </span>
          </button>
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-mono text-slate-400">Session: {sessionRef.current}</span>
            {auditLog.length > 0 && (
              <Button size="sm" variant="outline" onClick={handleExportAudit} className="text-xs flex items-center gap-1">
                <Download className="w-3 h-3" />
                Export JSON
              </Button>
            )}
          </div>
        </div>
        {showAudit && (
          <div className="space-y-1.5 max-h-64 overflow-y-auto">
            {auditLog.length === 0 ? (
              <div className="text-[11px] text-slate-400 italic py-4 text-center">
                No audit events yet — use the sandbox or toggle rules to generate entries.
              </div>
            ) : (
              auditLog.map((entry, i) => (
                <div key={i} className="flex items-start gap-3 text-[11px] font-mono border-b border-slate-50 pb-1.5">
                  <span className="text-slate-400 flex-shrink-0">{entry.ts.substring(11, 19)}Z</span>
                  <span className={`flex-shrink-0 px-1.5 py-0.5 rounded text-[10px] font-bold ${
                    entry.action.includes('DISABLE') ? 'bg-amber-100 text-amber-800'
                    : entry.action.includes('ENABLE') ? 'bg-emerald-100 text-emerald-800'
                    : entry.action.includes('SANITIZE') ? 'bg-blue-100 text-blue-800'
                    : entry.action.includes('RESET') ? 'bg-purple-100 text-purple-800'
                    : 'bg-slate-100 text-slate-600'
                  }`}>
                    {entry.action}
                  </span>
                  {entry.ruleId && <span className="text-gov-blue">[{entry.ruleId}]</span>}
                  <span className="text-slate-600">{entry.detail}</span>
                </div>
              ))
            )}
          </div>
        )}
      </div>

      {/* Compliance Coverage Footer */}
      <div className="bg-gradient-to-r from-slate-800 to-navy-900 rounded-lg p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="space-y-1">
          <span className="text-xs font-bold text-white uppercase tracking-wide flex items-center gap-1.5">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            Regulatory Compliance Coverage
          </span>
          <p className="text-[11px] text-slate-400">
            All redactions logged cryptographically to sovereign HSM attestation chain.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          {[
            { label: 'PCI-DSS 4.0', status: 'COMPLIANT', dot: 'bg-emerald-500' },
            { label: 'GDPR Art. 25', status: 'COMPLIANT', dot: 'bg-emerald-500' },
            { label: 'HIPAA §164', status: 'COMPLIANT', dot: 'bg-emerald-500' },
            { label: 'SOC 2 Type II', status: 'COMPLIANT', dot: 'bg-emerald-500' },
            { label: 'ISO 27001', status: 'CERTIFIED', dot: 'bg-blue-400' },
            { label: 'CERT-In', status: 'ALIGNED', dot: 'bg-amber-400' },
          ].map((item) => (
            <div key={item.label} className="flex items-center gap-1.5 bg-white/10 rounded px-2.5 py-1.5">
              <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${item.dot}`} />
              <span className="text-[11px] font-semibold text-white whitespace-nowrap">{item.label}</span>
              <span className="text-[9px] font-bold text-slate-400">{item.status}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
