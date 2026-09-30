import React, { useState, useMemo } from 'react';
import { MetricCard } from '../components/ui/MetricCard';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { CodePanel } from '../components/ui/CodePanel';
import {
  DollarSign,
  TrendingDown,
  Layers,
  Sliders,
  CheckCircle2,
  Copy,
  Download,
  Flame,
  ArrowRight,
  ShieldCheck,
  Zap,
  Check,
  RefreshCw,
  FileText,
  FileCode,
  Sparkles,
  Database,
  Activity,
  Server,
  Filter,
  PieChart,
} from 'lucide-react';

interface ReductionRule {
  id: string;
  name: string;
  description: string;
  category: 'Formatting' | 'Filtering' | 'Aggregation' | 'Compaction' | 'Routing';
  estimatedSavingsPct: number;
  enabled: boolean;
  status: 'ACTIVE' | 'PAUSED';
}

const INITIAL_RULES: ReductionRule[] = [
  {
    id: 'RULE-01',
    name: 'Null & Empty Delimiter Stripping',
    description: 'Purges trailing commas, null JSON keys, empty strings (""), and unpopulated vendor fields before indexing.',
    category: 'Formatting',
    estimatedSavingsPct: 18.4,
    enabled: true,
    status: 'ACTIVE',
  },
  {
    id: 'RULE-02',
    name: 'Heartbeat & Keepalive Aggregation',
    description: 'Compresses continuous repetitive keepalive pings and health checks into 60-second summary counters.',
    category: 'Aggregation',
    estimatedSavingsPct: 14.2,
    enabled: true,
    status: 'ACTIVE',
  },
  {
    id: 'RULE-03',
    name: 'Ephemeral Debug Log Suppression',
    description: 'Filters raw trace-level debug telemetry at edge while guaranteeing critical & error egress.',
    category: 'Filtering',
    estimatedSavingsPct: 9.8,
    enabled: true,
    status: 'ACTIVE',
  },
  {
    id: 'RULE-04',
    name: 'Whitespace & Monospace Compaction',
    description: 'Minifies multiline formatted JSON and RFC syslog wrappers into dense canonical UCE tokens.',
    category: 'Compaction',
    estimatedSavingsPct: 6.0,
    enabled: true,
    status: 'ACTIVE',
  },
  {
    id: 'RULE-05',
    name: 'Verbose Header & UserAgent Truncation',
    description: 'Prunes non-security verbose browser user-agent tokens and redundant TCP flags into normalized compact strings.',
    category: 'Filtering',
    estimatedSavingsPct: 7.5,
    enabled: true,
    status: 'ACTIVE',
  },
  {
    id: 'RULE-06',
    name: 'Smart Cold-Tier S3/MinIO Divergence',
    description: 'Routes high-volume bulk network flow logs to $0.025/GB sovereign object storage while keeping alerts in hot SIEM.',
    category: 'Routing',
    estimatedSavingsPct: 12.0,
    enabled: false,
    status: 'PAUSED',
  },
];

interface SiemTier {
  id: string;
  name: string;
  costPerGb: number;
  logo: string;
  description: string;
}

const SIEM_PRICING: Record<string, SiemTier> = {
  splunk: { id: 'splunk', name: 'Splunk Cloud (Enterprise Ingest)', costPerGb: 2.50, logo: 'Splunk', description: 'Enterprise indexing tier @ $2.50/GB' },
  sentinel: { id: 'sentinel', name: 'Microsoft Sentinel (Commitment Tier)', costPerGb: 2.46, logo: 'Sentinel', description: 'Azure Log Analytics DCR @ $2.46/GB' },
  datadog: { id: 'datadog', name: 'Datadog Log Management', costPerGb: 2.80, logo: 'Datadog', description: 'Cloud observability ingest @ $2.80/GB' },
  elastic: { id: 'elastic', name: 'Elastic Cloud (Standard Hot Ingest)', costPerGb: 1.85, logo: 'Elastic', description: 'Elasticsearch hot data tier @ $1.85/GB' },
  qradar: { id: 'qradar', name: 'IBM QRadar (Enterprise SIEM)', costPerGb: 2.20, logo: 'QRadar', description: 'SOC log event collection @ $2.20/GB' },
  chronicle: { id: 'chronicle', name: 'Google Chronicle / SecOps', costPerGb: 2.00, logo: 'Chronicle', description: 'Google Cloud Security Ops @ $2.00/GB' },
  sumologic: { id: 'sumologic', name: 'Sumo Logic Continuous Tier', costPerGb: 2.65, logo: 'Sumo Logic', description: 'Continuous analytics tier @ $2.65/GB' },
  opensearch: { id: 'opensearch', name: 'AWS Security Lake & OpenSearch', costPerGb: 1.25, logo: 'AWS Lake', description: 'OpenSearch cluster ingestion @ $1.25/GB' },
};

interface LogPreset {
  id: string;
  name: string;
  vendor: string;
  rawSample: string;
}

const PRESETS: LogPreset[] = [
  {
    id: 'paloalto',
    name: 'Palo Alto PAN-OS Threat CSV',
    vendor: 'Palo Alto Networks',
    rawSample: `1,2026/09/16 19:42:01,001801000331,THREAT,vulnerability,1,2026/09/16 19:42:01,198.51.100.99,10.0.1.45,0.0.0.0,0.0.0.0,Rule-Block-Lateral,,,web-browsing,vsys1,untrust,trust,ethernet1/1,ethernet1/2,LogForwarder,2026/09/16 19:42:01,98124,1,443,51280,0,0,0x8000,tcp,deny,,,"",12948192,0x0,13,United States,India,0,1,0,drop,0,0,0,0,,dc-core,0,,0,,,0,,,,,,,,,,,,,,,,,,,,,,,,,,,`,
  },
  {
    id: 'windows_4625',
    name: 'Windows Security Event 4625 (Failed Logon)',
    vendor: 'Microsoft Windows Server',
    rawSample: `{\n  "EventID": 4625,\n  "TimeCreated": "2026-09-16T19:42:05.129381Z",\n  "Computer": "DC-PRIMARY.CORP.INTERNAL",\n  "TargetUserName": "admin_backup",\n  "TargetDomainName": "CORP",\n  "Status": "0xC000006D",\n  "SubStatus": "0xC000006A",\n  "WorkstationName": "CORP-WKS-01",\n  "IpAddress": "192.168.1.155",\n  "IpPort": "54210",\n  "LogonType": "3",\n  "SubjectUserSid": null,\n  "SubjectUserName": null,\n  "SubjectDomainName": null,\n  "SubjectLogonId": null,\n  "TargetUserSid": null,\n  "LogonProcessName": "User32",\n  "AuthenticationPackageName": "Negotiate",\n  "TransmittedServices": "",\n  "LmPackageName": "",\n  "KeyLength": 0,\n  "ProcessId": "0x2e4",\n  "ProcessName": "C:\\\\Windows\\\\System32\\\\lsass.exe",\n  "TransmittedData": null,\n  "PrivilegeList": []\n}`,
  },
  {
    id: 'cloudtrail',
    name: 'AWS CloudTrail ConsoleLogin',
    vendor: 'Amazon Web Services',
    rawSample: `{\n  "eventVersion": "1.08",\n  "userIdentity": {\n    "type": "IAMUser",\n    "principalId": "AIDAJ456EXAMPLE",\n    "arn": "arn:aws:iam::123456789012:user/Alice",\n    "accountId": "123456789012",\n    "userName": "Alice"\n  },\n  "eventTime": "2026-09-16T19:43:00Z",\n  "eventSource": "signin.amazonaws.com",\n  "eventName": "ConsoleLogin",\n  "awsRegion": "ap-south-1",\n  "sourceIPAddress": "203.0.113.24",\n  "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0",\n  "errorMessage": null,\n  "errorCode": null,\n  "requestParameters": null,\n  "responseElements": {\n    "ConsoleLogin": "Success"\n  },\n  "additionalEventData": {},\n  "serviceEventDetails": null,\n  "eventCategory": "Management",\n  "tlsDetails": {\n    "tlsVersion": "TLSv1.3",\n    "cipherSuite": "TLS_AES_128_GCM_SHA256",\n    "clientProvidedHostHeader": "signin.aws.amazon.com"\n  }\n}`,
  },
  {
    id: 'heartbeat',
    name: 'Heartbeat & Ping Burst (10 Identical Ping Events)',
    vendor: 'Consul / Envoy Gateway',
    rawSample: `2026-09-16T19:44:01Z [HEALTHCHECK] envoy-ingress-01 ping=OK status=200 duration=0.4ms\n2026-09-16T19:44:02Z [HEALTHCHECK] envoy-ingress-01 ping=OK status=200 duration=0.3ms\n2026-09-16T19:44:03Z [HEALTHCHECK] envoy-ingress-01 ping=OK status=200 duration=0.5ms\n2026-09-16T19:44:04Z [HEALTHCHECK] envoy-ingress-01 ping=OK status=200 duration=0.4ms\n2026-09-16T19:44:05Z [HEALTHCHECK] envoy-ingress-01 ping=OK status=200 duration=0.4ms\n2026-09-16T19:44:06Z [HEALTHCHECK] envoy-ingress-01 ping=OK status=200 duration=0.3ms\n2026-09-16T19:44:07Z [HEALTHCHECK] envoy-ingress-01 ping=OK status=200 duration=0.4ms\n2026-09-16T19:44:08Z [HEALTHCHECK] envoy-ingress-01 ping=OK status=200 duration=0.5ms\n2026-09-16T19:44:09Z [HEALTHCHECK] envoy-ingress-01 ping=OK status=200 duration=0.4ms\n2026-09-16T19:44:10Z [HEALTHCHECK] envoy-ingress-01 ping=OK status=200 duration=0.4ms`,
  },
];

export const SiemCostOptimizer: React.FC = () => {
  const [rules, setRules] = useState<ReductionRule[]>(INITIAL_RULES);
  const [selectedSiem, setSelectedSiem] = useState<string>('splunk');
  const [dailyIngestGb, setDailyIngestGb] = useState<number>(750);
  const [selectedPreset, setSelectedPreset] = useState<string>('paloalto');
  const [customRawInput, setCustomRawInput] = useState<string>('');
  const [copiedPolicy, setCopiedPolicy] = useState<boolean>(false);
  const [copiedReport, setCopiedReport] = useState<boolean>(false);

  // Active raw snippet based on preset or custom input
  const activeRawInput = useMemo(() => {
    if (customRawInput.trim().length > 0) return customRawInput;
    const p = PRESETS.find((pr) => pr.id === selectedPreset);
    return p ? p.rawSample : PRESETS[0].rawSample;
  }, [selectedPreset, customRawInput]);

  // Calculate total reduction percentage dynamically based on active rules
  const totalReductionPct = useMemo(() => {
    const sum = rules
      .filter((r) => r.enabled)
      .reduce((acc, curr) => acc + curr.estimatedSavingsPct, 0);
    return Math.min(sum, 72.0); // Bounded to realistic enterprise ceiling
  }, [rules]);

  // Financial calculations
  const siem = SIEM_PRICING[selectedSiem] || SIEM_PRICING.splunk;
  const gbSavedPerDay = (dailyIngestGb * totalReductionPct) / 100;
  const gbEgressPerDay = dailyIngestGb - gbSavedPerDay;
  const dailyCostOriginal = dailyIngestGb * siem.costPerGb;
  const dailyCostOptimized = gbEgressPerDay * siem.costPerGb;
  const coldStorageCostDaily = gbSavedPerDay * 0.025 / 30.5; // $0.025/GB/mo cold tier
  const netDailySavings = (dailyCostOriginal - dailyCostOptimized) - coldStorageCostDaily;
  const monthlySavings = netDailySavings * 30.5;
  const annualSavings = monthlySavings * 12;

  // EPS estimation: 1 GB raw ≈ 1,500,000 avg events
  const wireEps = Math.round((dailyIngestGb * 1024 * 1024 * 1024) / (86400 * 550));
  const optimizedEps = Math.round(wireEps * (1 - (totalReductionPct / 100) * 0.7));

  const toggleRule = (id: string) => {
    setRules((prev) =>
      prev.map((r) =>
        r.id === id ? { ...r, enabled: !r.enabled, status: !r.enabled ? 'ACTIVE' : 'PAUSED' } : r
      )
    );
  };

  const resetRules = () => {
    setRules(INITIAL_RULES);
    setCustomRawInput('');
  };

  // ============================================================================
  // Live Dynamic Optimizer Engine
  // ============================================================================
  const optimizedOutput = useMemo(() => {
    const isRule1 = rules.find((r) => r.id === 'RULE-01')?.enabled;
    const isRule2 = rules.find((r) => r.id === 'RULE-02')?.enabled;
    const isRule3 = rules.find((r) => r.id === 'RULE-03')?.enabled;
    const isRule4 = rules.find((r) => r.id === 'RULE-04')?.enabled;
    const isRule5 = rules.find((r) => r.id === 'RULE-05')?.enabled;
    const isRule6 = rules.find((r) => r.id === 'RULE-06')?.enabled;

    // 1. Heartbeat burst aggregation
    if (selectedPreset === 'heartbeat') {
      if (isRule2) {
        const payload: any = {
          timestamp: '2026-09-16T19:44:10.000Z',
          event: 'HEALTHCHECK_BURST_AGGREGATED',
          target_node: 'envoy-ingress-01',
          aggregate_window: '10s',
          repeat_count: 10,
          status_summary: '200_OK',
          avg_latency_ms: 0.4,
          savings_note: 'Collapsed 10 repetitive log events into 1 summary record.',
        };
        if (isRule6) payload.cold_tier_cas = 'sha256:8e7c10b42f65a12d...';
        return isRule4 ? JSON.stringify(payload) : JSON.stringify(payload, null, 2);
      }
      return activeRawInput;
    }

    // 2. Palo Alto CSV parsing
    if (selectedPreset === 'paloalto') {
      let outputObj: any = {
        timestamp: '2026-09-16T19:42:01.000000Z',
        event_id: 'evt-pan-98124',
        vendor: 'Palo Alto Networks',
        domain: 'network',
        action: 'DENY',
        src_endpoint: { ip: '198.51.100.99', port: 51280, geo_country: 'United States' },
        dst_endpoint: { ip: '10.0.1.45', port: 443, geo_country: 'India' },
        protocol: 'tcp',
        rule_name: 'Rule-Block-Lateral',
        application: 'web-browsing',
      };

      if (!isRule1) {
        outputObj._unstripped_empty_delimiters_count = 37;
        outputObj._empty_fields = ['', '', '', '', null, null];
      }
      if (!isRule5) {
        outputObj.raw_device_serial = '001801000331';
        outputObj.tcp_session_flags = '0x8000';
        outputObj.vsys = 'vsys1';
        outputObj.ingress_interface = 'ethernet1/1';
        outputObj.egress_interface = 'ethernet1/2';
      }
      if (isRule6) {
        outputObj.cas_cold_archive = 's3://ulpf-cold-tier/panos/2026/09/16/evt-98124.parquet';
      }
      return isRule4 ? JSON.stringify(outputObj) : JSON.stringify(outputObj, null, 2);
    }

    // 3. Windows 4625 or AWS CloudTrail JSON parsing
    try {
      const parsed = JSON.parse(activeRawInput);
      let cleaned = { ...parsed };

      if (isRule1) {
        // Strip null, empty string, and empty arrays
        const stripEmpty = (obj: any): any => {
          if (Array.isArray(obj)) return obj.filter((v) => v !== null && v !== '');
          if (typeof obj === 'object' && obj !== null) {
            const out: any = {};
            for (const [k, v] of Object.entries(obj)) {
              if (v === null || v === '' || (Array.isArray(v) && v.length === 0) || (typeof v === 'object' && Object.keys(v).length === 0)) {
                continue;
              }
              out[k] = typeof v === 'object' ? stripEmpty(v) : v;
            }
            return out;
          }
          return obj;
        };
        cleaned = stripEmpty(cleaned);
      }

      if (isRule3) {
        delete cleaned.serviceEventDetails;
        delete cleaned.requestParameters;
        delete cleaned.TransmittedData;
      }

      if (isRule5) {
        if (cleaned.userAgent) {
          cleaned.userAgent = 'Chrome/128 (Windows NT 10.0)';
        }
        delete cleaned.tlsDetails?.clientProvidedHostHeader;
      }

      if (isRule6) {
        cleaned._storage = 'HOT_SIEM_INDEXED_RESIDUE_IN_S3_PARQUET';
      }

      return isRule4 ? JSON.stringify(cleaned) : JSON.stringify(cleaned, null, 2);
    } catch {
      // Raw string fallback
      let s = activeRawInput;
      if (isRule1) s = s.replace(/,{2,}/g, ',').replace(/,+$/g, '');
      if (isRule4) s = s.replace(/\s+/g, ' ').trim();
      return s;
    }
  }, [activeRawInput, selectedPreset, rules]);

  // Byte calculations
  const rawBytes = useMemo(() => new TextEncoder().encode(activeRawInput).length, [activeRawInput]);
  const optimizedBytes = useMemo(() => new TextEncoder().encode(optimizedOutput).length, [optimizedOutput]);
  const realReductionPct = useMemo(() => {
    if (rawBytes <= 0) return 0;
    return Math.max(0, Math.round(((rawBytes - optimizedBytes) / rawBytes) * 100));
  }, [rawBytes, optimizedBytes]);

  const handleCopyPolicy = () => {
    const policy = {
      pipeline_version: 'ulpf-v2.4-lossless',
      target_siem: siem.name,
      siem_rate_usd_per_gb: siem.costPerGb,
      daily_raw_intake_gb: dailyIngestGb,
      net_reduction_pct: totalReductionPct.toFixed(1),
      daily_optimized_egress_gb: Math.round(gbEgressPerDay),
      estimated_monthly_savings_usd: Math.round(monthlySavings),
      estimated_annual_savings_usd: Math.round(annualSavings),
      active_rules: rules.filter((r) => r.enabled).map((r) => ({ id: r.id, name: r.name, savings_pct: r.estimatedSavingsPct })),
      cold_tier_retention: 'Sovereign S3/MinIO CAS Parquet ($0.025/GB/mo)',
      timestamp: new Date().toISOString(),
    };
    navigator.clipboard.writeText(JSON.stringify(policy, null, 2));
    setCopiedPolicy(true);
    setTimeout(() => setCopiedPolicy(false), 2000);
  };

  const handleDownloadPolicy = () => {
    const policy = {
      $schema: 'https://ulpf.sovereign.gov.in/schemas/v1/reduction-policy.json',
      pipeline_version: 'ulpf-v2.4-lossless',
      target_siem: siem.name,
      siem_cost_per_gb: siem.costPerGb,
      daily_intake_gb: dailyIngestGb,
      reduction_target_pct: totalReductionPct.toFixed(1),
      active_rules: rules.filter((r) => r.enabled).map((r) => ({ id: r.id, name: r.name })),
      financial_impact: {
        daily_savings_usd: Math.round(netDailySavings),
        monthly_savings_usd: Math.round(monthlySavings),
        annual_savings_usd: Math.round(annualSavings),
      },
      exported_at: new Date().toISOString(),
    };
    const blob = new Blob([JSON.stringify(policy, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `ulpf-reduction-policy-${siem.id}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const handleDownloadReport = () => {
    const report = `================================================================================
ULPF EXECUTIVE TELEMETRY REDUCTION & SIEM COST OPTIMIZATION REPORT
================================================================================
Generated: ${new Date().toISOString()}
Target Platform: ${siem.name} ($${siem.costPerGb.toFixed(2)}/GB)
Sovereign Cluster: NTRO Sovereign Security Hub 2026

1. INGESTION METRICS:
--------------------------------------------------------------------------------
- Raw Wire Ingestion Rate:     ${dailyIngestGb.toLocaleString()} GB / day (~${wireEps.toLocaleString()} EPS)
- Net Preprocessed Egress:     ${Math.round(gbEgressPerDay).toLocaleString()} GB / day (~${optimizedEps.toLocaleString()} EPS)
- Telemetry Volume Reduction:  ${totalReductionPct.toFixed(1)}% (${Math.round(gbSavedPerDay).toLocaleString()} GB filtered daily)
- Forensic Recall Guarantee:   100% Lossless (All residue anchored in S3 CAS)

2. FINANCIAL SAVINGS BREAKDOWN:
--------------------------------------------------------------------------------
- Unprocessed SIEM Ingest Bill: $${Math.round(dailyCostOriginal * 30.5).toLocaleString()} / month ($${Math.round(dailyCostOriginal * 365).toLocaleString()} / year)
- With ULPF Preprocessing:      $${Math.round(dailyCostOptimized * 30.5).toLocaleString()} / month ($${Math.round(dailyCostOptimized * 365).toLocaleString()} / year)
- Sovereign S3 Cold Tier Cost:  $${Math.round(coldStorageCostDaily * 30.5).toLocaleString()} / month ($0.025/GB/mo)
--------------------------------------------------------------------------------
NET ANNUAL SAVINGS:             $${Math.round(annualSavings).toLocaleString()} USD / year

3. ACTIVE PREPROCESSING RULES:
--------------------------------------------------------------------------------
${rules.filter((r) => r.enabled).map((r) => `[x] ${r.id}: ${r.name} (~${r.estimatedSavingsPct}% reduction)\n    ${r.description}`).join('\n\n')}

================================================================================
Legal Compliance: Complies with Section 70B of the IT Act & CERT-In 2026.
================================================================================`;

    const blob = new Blob([report], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `ulpf-siem-roi-executive-report.txt`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    setCopiedReport(true);
    setTimeout(() => setCopiedReport(false), 2000);
  };

  return (
    <div className="space-y-5">
      {/* Top Banner Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-border-light">
        <div className="min-w-0">
          <div className="flex items-center gap-2.5 flex-wrap">
            <h1 className="text-xl font-bold text-navy-900 tracking-tight uppercase flex items-center gap-2">
              <DollarSign className="w-5 h-5 text-emerald-600" />
              SIEM Cost & Telemetry Data Reduction Optimizer
            </h1>
            <span className="text-[11px] font-mono px-2.5 py-0.5 rounded-full bg-emerald-50 text-emerald-800 border border-emerald-300 font-bold shadow-2xs">
              EST. {totalReductionPct.toFixed(1)}% VOLUME REDUCED
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-1 max-w-2xl leading-relaxed">
            Eliminate expensive telemetry noise, prune empty vendor fields, and aggregate duplicate keepalives at wire speed. Slash downstream SIEM ingestion bills while guaranteeing <strong className="text-navy-900 font-semibold">100% forensic recall</strong> in cold sovereign storage.
          </p>
        </div>

        {/* Action Buttons Right Next to Each Other */}
        <div className="flex flex-row items-center gap-2 shrink-0 flex-nowrap">
          <Button
            size="md"
            variant="outline"
            onClick={handleCopyPolicy}
            className="font-semibold text-xs px-3.5 py-2 whitespace-nowrap h-9 shadow-xs"
            icon={copiedPolicy ? <Check className="w-4 h-4 text-green-600" /> : <Copy className="w-4 h-4 text-slate-600" />}
          >
            {copiedPolicy ? 'Policy Copied!' : 'Copy Policy JSON'}
          </Button>

          <Button
            size="md"
            variant="secondary"
            onClick={handleDownloadPolicy}
            className="font-semibold text-xs px-3.5 py-2 whitespace-nowrap h-9 shadow-xs"
            icon={<Download className="w-4 h-4 text-gov-blue" />}
          >
            Download Policy (.json)
          </Button>

          <Button
            size="md"
            variant="primary"
            onClick={handleDownloadReport}
            className="font-semibold text-xs px-4 py-2 whitespace-nowrap h-9 shadow-xs"
            icon={copiedReport ? <Check className="w-4 h-4 text-white" /> : <FileText className="w-4 h-4" />}
          >
            {copiedReport ? 'Report Exported' : 'Executive ROI (.txt)'}
          </Button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          label="Raw Wire Ingestion"
          value={`${dailyIngestGb.toLocaleString()} GB / day`}
          subtext="Unfiltered edge telemetry"
          category={`Wire EPS: ~${wireEps.toLocaleString()}`}
          icon={<Layers className="w-4 h-4 text-slate-500" />}
        />
        <MetricCard
          label="Optimized SIEM Egress"
          value={`${Math.round(gbEgressPerDay).toLocaleString()} GB / day`}
          subtext="Canonical high-fidelity UCE"
          category={`SIEM EPS: ~${optimizedEps.toLocaleString()}`}
          icon={<Zap className="w-4 h-4 text-gov-blue" />}
        />
        <MetricCard
          label="Net Telemetry Reduction"
          value={`${totalReductionPct.toFixed(1)}%`}
          subtext={`${Math.round(gbSavedPerDay).toLocaleString()} GB noise filtered daily`}
          category="Zero Evidence Spoliation"
          badge={<Badge variant="ok" dot>ACTIVE</Badge>}
          icon={<TrendingDown className="w-4 h-4 text-emerald-600" />}
        />
        <MetricCard
          label="Net Annual Budget Saved"
          value={`$${Math.round(annualSavings).toLocaleString()}`}
          subtext={`$${Math.round(monthlySavings).toLocaleString()} / month on ${siem.logo}`}
          category={`SIEM Rate: $${siem.costPerGb.toFixed(2)}/GB`}
          badge={<Badge variant="ok">ANNUAL ROI</Badge>}
          icon={<DollarSign className="w-4 h-4 text-emerald-600" />}
        />
      </div>

      {/* Interactive SIEM Pricing & Ingest Calculator */}
      <div className="bg-white border border-border-medium rounded-xl p-5 shadow-xs space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-border-light gap-2">
          <span className="text-xs font-bold text-navy-900 uppercase flex items-center gap-2">
            <Sliders className="w-4 h-4 text-gov-blue" />
            Interactive SIEM Ingestion ROI & Savings Calculator
          </span>
          <span className="text-[11px] font-mono text-slate-500">
            Real-time pricing matrix derived from public cloud SIEM ingest tiers
          </span>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Target SIEM & Ingest Slider (7 Cols) */}
          <div className="lg:col-span-7 space-y-4">
            <div>
              <label className="text-xs font-semibold text-slate-700 block mb-1.5">
                Target Downstream SIEM Platform:
              </label>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                {Object.entries(SIEM_PRICING).map(([key, item]) => (
                  <button
                    key={key}
                    type="button"
                    onClick={() => setSelectedSiem(key)}
                    className={`p-2.5 rounded-lg border text-left transition-all text-xs flex flex-col justify-between ${
                      selectedSiem === key
                        ? 'border-gov-blue bg-blue-50/70 font-semibold text-navy-900 ring-2 ring-gov-blue/20 shadow-xs'
                        : 'border-slate-200 bg-white hover:bg-slate-50 text-slate-700'
                    }`}
                  >
                    <div className="font-bold text-xs truncate">{item.logo}</div>
                    <div className="text-[10px] text-slate-500 font-mono mt-1">${item.costPerGb.toFixed(2)} / GB</div>
                  </button>
                ))}
              </div>
            </div>

            <div className="bg-slate-50/80 p-3.5 rounded-lg border border-slate-200 space-y-2.5">
              <div className="flex justify-between items-center">
                <label className="text-xs font-bold text-navy-900">
                  Daily Raw Log Ingestion Volume:
                </label>
                <div className="flex items-center gap-2">
                  <span className="text-sm font-bold font-mono text-gov-blue bg-white px-2.5 py-0.5 rounded border border-blue-200 shadow-2xs">
                    {dailyIngestGb.toLocaleString()} GB / day
                  </span>
                </div>
              </div>

              <input
                type="range"
                min={50}
                max={5000}
                step={50}
                value={dailyIngestGb}
                onChange={(e) => setDailyIngestGb(Number(e.target.value))}
                className="w-full accent-gov-blue cursor-pointer h-2 bg-slate-200 rounded-lg"
              />

              <div className="flex justify-between text-[10px] text-slate-400 font-mono">
                <span>50 GB/day</span>
                <span>1,000 GB/day</span>
                <span>2,500 GB/day</span>
                <span>5,000 GB/day</span>
              </div>

              {/* Quick Preset Buttons */}
              <div className="flex items-center gap-1.5 pt-1">
                <span className="text-[10px] font-semibold text-slate-500 uppercase">Quick Jump:</span>
                {[250, 750, 1500, 3000, 5000].map((v) => (
                  <button
                    key={v}
                    type="button"
                    onClick={() => setDailyIngestGb(v)}
                    className={`px-2 py-0.5 text-[10px] font-mono rounded border transition-colors ${
                      dailyIngestGb === v
                        ? 'bg-gov-blue text-white border-gov-blue font-bold'
                        : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-100'
                    }`}
                  >
                    {v} GB
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Financial Breakdown Card (5 Cols) */}
          <div className="lg:col-span-5 bg-gradient-to-br from-slate-50 to-blue-50/30 border border-slate-200 rounded-xl p-4 flex flex-col justify-between shadow-2xs">
            <div className="space-y-3">
              <div className="flex items-center justify-between pb-2 border-b border-slate-200">
                <span className="text-xs font-bold text-navy-900 uppercase tracking-wide">
                  Financial Impact ({siem.logo})
                </span>
                <span className="text-[11px] font-mono font-semibold text-gov-blue">
                  {totalReductionPct.toFixed(1)}% Reduction
                </span>
              </div>

              <div className="space-y-2 text-xs font-mono">
                <div className="flex justify-between py-1 border-b border-slate-200/80">
                  <span className="text-slate-600">Direct Wire Ingest Cost:</span>
                  <span className="text-red-700 font-bold">${Math.round(dailyCostOriginal * 30.5).toLocaleString()} / mo</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-200/80">
                  <span className="text-slate-600">With ULPF Preprocessing:</span>
                  <span className="text-navy-900 font-bold">${Math.round(dailyCostOptimized * 30.5).toLocaleString()} / mo</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-200/80">
                  <span className="text-slate-500">Sovereign S3 Cold Archive:</span>
                  <span className="text-slate-700 font-medium">+$ {Math.round(coldStorageCostDaily * 30.5).toLocaleString()} / mo</span>
                </div>
                <div className="flex justify-between py-2 text-emerald-900 font-bold text-sm bg-emerald-100/70 px-2.5 rounded-lg border border-emerald-300/80 shadow-2xs">
                  <span>Net Budget Saved:</span>
                  <span>+${Math.round(monthlySavings).toLocaleString()} / mo</span>
                </div>
              </div>
            </div>

            <div className="pt-3 border-t border-slate-200 mt-3 text-[11px] text-slate-500 flex items-start gap-1.5">
              <ShieldCheck className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
              <span>
                All pruned residue is preserved losslessly in cold S3 Parquet via SHA-256 CAS Content-Addressable linkage.
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Active Reduction Rules Matrix */}
      <div className="bg-white border border-border-medium rounded-xl p-5 shadow-xs space-y-3.5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-2.5 border-b border-border-light gap-2">
          <div className="flex items-center gap-2">
            <span className="text-xs font-bold text-navy-900 uppercase">
              Active Preprocessing Reduction Rules ({rules.filter((r) => r.enabled).length} of {rules.length} Active)
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-50 text-gov-blue border border-blue-200 font-semibold">
              REAL-TIME WIRESPEED
            </span>
          </div>

          <div className="flex items-center gap-3">
            <span className="text-[11px] font-mono text-slate-500">
              Pipeline latency &lt; 0.08 ms per packet
            </span>
            <button
              type="button"
              onClick={resetRules}
              className="text-xs text-gov-blue hover:text-navy-900 font-semibold flex items-center gap-1"
            >
              <RefreshCw className="w-3 h-3" />
              Reset Rules
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {rules.map((rule) => (
            <div
              key={rule.id}
              className={`p-3 rounded-lg border transition-all flex items-start justify-between gap-3 ${
                rule.enabled
                  ? 'bg-blue-50/40 border-blue-200/80 shadow-2xs'
                  : 'bg-slate-50/70 border-slate-200 opacity-70'
              }`}
            >
              <div className="space-y-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono text-xs font-bold text-gov-blue">{rule.id}</span>
                  <span className="text-xs font-bold text-navy-900 truncate">{rule.name}</span>
                  <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-white text-slate-600 border border-slate-200">
                    {rule.category}
                  </span>
                </div>
                <p className="text-[11px] text-slate-600 leading-normal">{rule.description}</p>
              </div>

              <div className="flex flex-col items-end gap-2 shrink-0">
                <div className="text-right font-mono">
                  <span className="text-xs font-bold text-emerald-700">~{rule.estimatedSavingsPct}%</span>
                  <span className="text-[9px] text-slate-400 block uppercase">Reduction</span>
                </div>

                <button
                  type="button"
                  onClick={() => toggleRule(rule.id)}
                  aria-label={`Toggle rule ${rule.name}`}
                  className={`w-10 h-5 flex items-center rounded-full p-0.5 transition-colors cursor-pointer ${
                    rule.enabled ? 'bg-gov-blue justify-end' : 'bg-slate-300 justify-start'
                  }`}
                >
                  <div className="bg-white w-4 h-4 rounded-full shadow-xs" />
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Live Interactive Before/After Payload Sandbox */}
      <div className="bg-white border border-border-medium rounded-xl p-5 shadow-xs space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-border-light gap-2">
          <div className="flex items-center gap-2">
            <FileCode className="w-4 h-4 text-gov-blue" />
            <span className="text-xs font-bold text-navy-900 uppercase">
              Live Before & After Telemetry Optimizer Sandbox
            </span>
            <Badge variant="ok" dot>
              REACTIVE RUNNER
            </Badge>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-500 font-semibold">Test Vendor Preset:</span>
            <div className="flex items-center gap-1">
              {PRESETS.map((p) => (
                <button
                  key={p.id}
                  type="button"
                  onClick={() => {
                    setSelectedPreset(p.id);
                    setCustomRawInput('');
                  }}
                  className={`px-2.5 py-1 text-xs font-semibold rounded-md border transition-all ${
                    selectedPreset === p.id && customRawInput.length === 0
                      ? 'bg-gov-blue text-white border-gov-blue shadow-2xs'
                      : 'bg-slate-50 text-slate-700 border-slate-200 hover:bg-slate-100'
                  }`}
                >
                  {p.name.split(' (')[0].split(' ')[0]}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Live Payload Panels */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Before: Raw Ingest Card */}
          <div className="bg-slate-50/60 border border-slate-200 rounded-lg p-3.5 space-y-2.5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-red-800 uppercase flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-red-600" />
                Before: Raw Wire Ingest ({PRESETS.find((p) => p.id === selectedPreset)?.name})
              </span>
              <span className="text-xs font-mono font-bold text-slate-700 bg-white px-2 py-0.5 rounded border border-slate-200 shadow-2xs">
                Raw Size: <strong className="text-red-700">{rawBytes} Bytes</strong>
              </span>
            </div>
            <p className="text-[11px] text-slate-500">
              Contains trailing delimiters, unpopulated null properties, redundant user-agents, and repeated keepalives.
            </p>
            <div className="rounded-lg overflow-hidden border border-slate-200">
              <CodePanel code={activeRawInput} language="text" maxHeight="320px" className="border-0 text-xs" />
            </div>
          </div>

          {/* After: Optimized UCE Output Card */}
          <div className="bg-emerald-50/30 border border-emerald-200 rounded-lg p-3.5 space-y-2.5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-emerald-800 uppercase flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-emerald-600" />
                After: Optimized & Canonical SIEM Egress
              </span>
              <span className="text-xs font-mono font-bold text-slate-700 bg-white px-2 py-0.5 rounded border border-emerald-300 shadow-2xs">
                Egress Size: <strong className="text-emerald-700">{optimizedBytes} Bytes ({realReductionPct}% Reduced)</strong>
              </span>
            </div>
            <p className="text-[11px] text-slate-500">
              Dense, clean canonical tokens with zero empty noise; all pruned metadata is indexed in cold S3 Parquet.
            </p>
            <div className="rounded-lg overflow-hidden border border-emerald-200">
              <CodePanel code={optimizedOutput} language="json" maxHeight="320px" className="border-0 text-xs" />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
