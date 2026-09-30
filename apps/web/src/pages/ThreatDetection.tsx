import React, { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import * as Dialog from '@radix-ui/react-dialog';
import { Card } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import {
  AlertTriangle,
  ShieldCheck,
  Crosshair,
  ArrowRight,
  Activity,
  Zap,
  Play,
  Terminal,
  CheckCircle2,
  RotateCcw,
  Search,
  Eye,
  Filter,
  Lock,
  ExternalLink,
  ShieldAlert,
  X,
  ChevronRight,
  RefreshCw,
  Sparkles,
  FileText,
  Check,
  Cpu,
  Layers,
  Clock,
  Radio,
} from 'lucide-react';

export interface ThreatDetectionItem {
  id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  source: string;
  entity: string;
  mitre: string;
  mitreId: string;
  confidence: string;
  status: 'ACTIVE' | 'CORRELATED' | 'TRIAGED' | 'SUPPRESSED';
  zScore: number;
  timestamp: string;
  recommendedPlaybookId: string;
  recommendedPlaybookName: string;
  blastRadius: 'LOW' | 'MEDIUM' | 'HIGH';
  stages: {
    stage: number;
    name: string;
    tactic: string;
    event: string;
    source: string;
    timeDelta: string;
    mitre: string;
    color: 'amber' | 'red' | 'purple' | 'blue';
  }[];
  explainability: {
    what: string;
    who: string;
    when: string;
    where: string;
    why: string;
  };
  evidenceLogs: {
    sensor: string;
    timestamp: string;
    raw: string;
  }[];
  iocs: {
    type: string;
    value: string;
    verdict: string;
  }[];
  welfordMetrics: {
    mean: number;
    variance: number;
    stdDev: number;
    observedValue: number;
    streamCount: number;
  };
}

const DETECTIONS: ThreatDetectionItem[] = [
  {
    id: 'DET-88192',
    severity: 'CRITICAL',
    title: 'Multi-Stage Lateral Movement Campaign',
    source: 'iptables + sshd + pfSense + suricata_eve',
    entity: '198.51.100.99 → 10.0.1.45',
    mitre: 'T1021.002 Remote Services: SMB',
    mitreId: 'T1021.002',
    confidence: '98.4%',
    status: 'ACTIVE',
    zScore: 3.84,
    timestamp: '2026-09-17 01:28:12 IST',
    recommendedPlaybookId: 'PB-RANSOMWARE-CONTAINMENT',
    recommendedPlaybookName: 'Emergency Host & Lateral Ransomware Containment',
    blastRadius: 'HIGH',
    stages: [
      {
        stage: 1,
        name: 'SSH Brute-Force & Credential Access',
        tactic: 'STAGE 1: CREDENTIAL ACCESS',
        event: 'Failed authentication spike (142 attempts/sec)',
        source: 'sshd_auth',
        timeDelta: 'T+0.00s',
        mitre: 'MITRE: T1110.001',
        color: 'amber',
      },
      {
        stage: 2,
        name: 'SMB Port Sweep & Vulnerability Probe',
        tactic: 'STAGE 2: LATERAL MOVEMENT',
        event: 'TCP port 445 probe across 10.0.1.0/24 subnet (CVE-2020-0796)',
        source: 'iptables + suricata',
        timeDelta: 'T+2.14s',
        mitre: 'MITRE: T1021.002',
        color: 'red',
      },
      {
        stage: 3,
        name: 'C2 Beaconing & Channel Establishment',
        tactic: 'STAGE 3: COMMAND & CONTROL',
        event: 'Encrypted jitter interval connection to 198.51.100.99:443',
        source: 'pfSense_filterlog',
        timeDelta: 'T+4.75s',
        mitre: 'MITRE: T1071.001',
        color: 'purple',
      },
    ],
    explainability: {
      what: 'Multi-stage coordinated attack vector combining brute-force credential stuffing, lateral SMBv2 probing (CVE-2020-0796), and command-and-control heartbeat.',
      who: 'Hostile threat actor from external IP 198.51.100.99 targeting internal database server 10.0.1.45 (srv-fin-db-01).',
      when: 'Observed at 01:28:08 to 01:28:13 IST across a 4.75-second burst sequence.',
      where: 'Perimeter firewall interface igb0 traversing zone untrust to critical tier subnet 10.0.1.0/24.',
      why: 'Matched correlated multi-sensor rule RULE-CORR-SMB-LATERAL with Welford anomaly Z-score of 3.84 (>3.00 threshold), indicating extreme anomaly confidence.',
    },
    evidenceLogs: [
      {
        sensor: 'sshd_auth (Host WIN-DC01)',
        timestamp: '01:28:08.112 IST',
        raw: 'Sep 17 01:28:08 sshd[1420]: Failed password for invalid user admin from 198.51.100.99 port 51234 ssh2',
      },
      {
        sensor: 'iptables (Kernel Netfilter)',
        timestamp: '01:28:10.252 IST',
        raw: 'Sep 17 01:28:10 kernel: [IPTABLES-DROP] IN=eth0 OUT= SRC=198.51.100.99 DST=10.0.1.45 PROTO=TCP DPT=445',
      },
      {
        sensor: 'pfSense (Perimeter Filterlog)',
        timestamp: '01:28:12.890 IST',
        raw: 'Sep 17 01:28:12 filterlog[210]: 5,,,1000000103,igb0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,198.51.100.99,10.0.1.45,49152,445,0,S,12345678,,65535,,mss;sackOK;ts',
      },
    ],
    iocs: [
      { type: 'IPv4 Hostile C2', value: '198.51.100.99', verdict: 'CONFIRMED_MALICIOUS (APT29)' },
      { type: 'CVE Signature', value: 'CVE-2020-0796', verdict: 'SMBv2 Compression Heap Overflow' },
      { type: 'Target Port', value: 'TCP 445 (SMB)', verdict: 'Lateral Service Probe' },
    ],
    welfordMetrics: {
      mean: 18.4,
      variance: 6.2,
      stdDev: 2.49,
      observedValue: 28.0,
      streamCount: 1428920,
    },
  },
  {
    id: 'DET-88191',
    severity: 'HIGH',
    title: 'Distributed Credential Stuffing & SQL Injection',
    source: 'nginx_access + sshd + linux_auditd',
    entity: 'user:admin / 203.0.113.88',
    mitre: 'T1110.001 Brute Force: Password Guessing',
    mitreId: 'T1110.001',
    confidence: '94.2%',
    status: 'CORRELATED',
    zScore: 3.12,
    timestamp: '2026-09-17 01:22:45 IST',
    recommendedPlaybookId: 'PB-CREDENTIAL-REVOCATION',
    recommendedPlaybookName: 'Compromised Identity & Token Revocation',
    blastRadius: 'LOW',
    stages: [
      {
        stage: 1,
        name: 'Web Application Reconnaissance',
        tactic: 'STAGE 1: RECONNAISSANCE',
        event: 'Automated sqlmap user-agent probe on /api/v1/auth/login',
        source: 'nginx_access',
        timeDelta: 'T+0.00s',
        mitre: 'MITRE: T1595.002',
        color: 'blue',
      },
      {
        stage: 2,
        name: 'Rapid Sequential Password Guessing',
        tactic: 'STAGE 2: CREDENTIAL ACCESS',
        event: '48 consecutive login failures within 15 seconds',
        source: 'nginx_access + sshd',
        timeDelta: 'T+8.20s',
        mitre: 'MITRE: T1110.001',
        color: 'amber',
      },
      {
        stage: 3,
        name: 'Account Lockout Threshold Violation',
        tactic: 'STAGE 3: PRIVILEGE ESCALATION',
        event: 'Target account "admin" triggered automatic defense lockout',
        source: 'linux_auditd',
        timeDelta: 'T+14.50s',
        mitre: 'MITRE: T1078.003',
        color: 'red',
      },
    ],
    explainability: {
      what: 'Distributed credential guessing combined with SQL injection attack payloads aimed at the ULPF web authentication endpoint.',
      who: 'Originating from IP 203.0.113.88 targeting administrative accounts.',
      when: 'Detected at 01:22:30 to 01:22:45 IST.',
      where: 'Public reverse proxy gateway /api/v1/auth.',
      why: 'Welford anomaly Z-score reached 3.12 (>3.00), correlating repeated failed auth with exploit signatures.',
    },
    evidenceLogs: [
      {
        sensor: 'nginx_access',
        timestamp: '01:22:30.400 IST',
        raw: '203.0.113.88 - - [17/Sep/2026:01:22:30 +0530] "POST /api/v1/auth/login HTTP/1.1" 401 84 "-" "sqlmap/1.6.11"',
      },
      {
        sensor: 'linux_auditd',
        timestamp: '01:22:44.910 IST',
        raw: 'type=USER_AUTH msg=audit(1789319864.910:412): pid=891 uid=0 auid=4294967295 ses=4294967295 res=failed',
      },
    ],
    iocs: [
      { type: 'IPv4 External Probe', value: '203.0.113.88', verdict: 'MALICIOUS_SCANNER' },
      { type: 'User Agent', value: 'sqlmap/1.6.11', verdict: 'Automated Injection Tool' },
    ],
    welfordMetrics: {
      mean: 12.1,
      variance: 4.8,
      stdDev: 2.19,
      observedValue: 19.0,
      streamCount: 984120,
    },
  },
  {
    id: 'DET-88190',
    severity: 'MEDIUM',
    title: 'Suspicious Base64 Encoded PowerShell Execution',
    source: 'sysmon (EventID 1) + osquery',
    entity: 'host:WIN-DC01 / NT AUTHORITY\\SYSTEM',
    mitre: 'T1059.001 Command & Scripting Interpreter: PowerShell',
    mitreId: 'T1059.001',
    confidence: '91.8%',
    status: 'TRIAGED',
    zScore: 2.76,
    timestamp: '2026-09-17 01:15:35 IST',
    recommendedPlaybookId: 'PB-HOST-ISOLATION',
    recommendedPlaybookName: 'Compromised Node Network Quarantine',
    blastRadius: 'MEDIUM',
    stages: [
      {
        stage: 1,
        name: 'CMD Shell Invocation',
        tactic: 'STAGE 1: EXECUTION',
        event: 'Parent process cmd.exe spawned by scheduled maintenance task',
        source: 'sysmon',
        timeDelta: 'T+0.00s',
        mitre: 'MITRE: T1059.003',
        color: 'blue',
      },
      {
        stage: 2,
        name: 'Hidden Base64 PowerShell Cradle',
        tactic: 'STAGE 2: DEFENSE EVASION',
        event: 'powershell.exe -nop -w hidden -EncodedCommand <payload>',
        source: 'sysmon_event1',
        timeDelta: 'T+0.45s',
        mitre: 'MITRE: T1027 Obfuscated',
        color: 'amber',
      },
      {
        stage: 3,
        name: 'Volatile In-Memory Download Attempt',
        tactic: 'STAGE 3: COMMAND & CONTROL',
        event: 'Net.WebClient DownloadString cradle detected in memory buffer',
        source: 'osquery_process_events',
        timeDelta: 'T+1.10s',
        mitre: 'MITRE: T1105 Ingress Tool',
        color: 'purple',
      },
    ],
    explainability: {
      what: 'Obfuscated PowerShell cradle spawned under SYSTEM privileges attempting remote script fetch.',
      who: 'NT AUTHORITY\\SYSTEM account on Active Directory domain controller.',
      when: '01:15:35.405 IST.',
      where: 'Domain Controller WIN-DC01.ad.ntro.internal.',
      why: 'Process creation command-line regex matched suspicious hidden download cradle pattern with high Shannon entropy.',
    },
    evidenceLogs: [
      {
        sensor: 'sysmon (EventID 1)',
        timestamp: '01:15:35.405 IST',
        raw: 'Process Create: Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe CommandLine="powershell.exe -nop -w hidden -EncodedCommand SQBFAFgA..."',
      },
    ],
    iocs: [
      { type: 'Host', value: 'WIN-DC01.ad.ntro.internal', verdict: 'Core Domain Controller' },
      { type: 'Payload', value: 'Base64 Encoded DownloadString', verdict: 'SUSPICIOUS_OBFUSCATION' },
    ],
    welfordMetrics: {
      mean: 8.5,
      variance: 3.2,
      stdDev: 1.78,
      observedValue: 13.4,
      streamCount: 654210,
    },
  },
  {
    id: 'DET-88189',
    severity: 'LOW',
    title: 'Outbound DNS Tunneling Heuristic',
    source: 'dns_bind + zeek_conn_dns',
    entity: '10.0.1.45 → tunnel.staging-defense.in',
    mitre: 'T1071.004 Application Layer Protocol: DNS',
    mitreId: 'T1071.004',
    confidence: '85.1%',
    status: 'SUPPRESSED',
    zScore: 1.82,
    timestamp: '2026-09-17 01:05:40 IST',
    recommendedPlaybookId: 'PB-C2-NETWORK-BLOCK',
    recommendedPlaybookName: 'Adversary Command & Control (C2) Blackhole',
    blastRadius: 'MEDIUM',
    stages: [
      {
        stage: 1,
        name: 'High-Entropy TXT Query',
        tactic: 'STAGE 1: PROTOCOL ANOMALY',
        event: 'Repeated long label query with Shannon entropy 4.62',
        source: 'zeek_dns',
        timeDelta: 'T+0.00s',
        mitre: 'MITRE: T1071.004',
        color: 'blue',
      },
      {
        stage: 2,
        name: 'Encrypted Answer Payload Transfer',
        tactic: 'STAGE 2: EXFILTRATION CHANNEL',
        event: 'Base64 encoded responses exceeding standard TXT length baseline',
        source: 'dns_bind',
        timeDelta: 'T+3.20s',
        mitre: 'MITRE: T1048 Exfiltration',
        color: 'amber',
      },
    ],
    explainability: {
      what: 'Outbound DNS queries targeting high-entropy TXT records indicative of covert tunnel channel.',
      who: 'Host 10.0.1.45 querying external resolver 1.1.1.1.',
      when: '01:05:40 IST.',
      where: 'Port 53/UDP egress.',
      why: 'Entropy scanner exceeded baseline (4.62 > 3.80 threshold).',
    },
    evidenceLogs: [
      {
        sensor: 'zeek_conn_dns',
        timestamp: '01:05:40.120 IST',
        raw: '{"query":"c2E4OTIxOGFkOGYwMTIz.tunnel.staging-defense.in","qtype_name":"TXT","answers":["dWxwZi1lbmNyeXB0ZWQtcGF5bG9hZA=="]}',
      },
    ],
    iocs: [
      { type: 'Domain', value: 'tunnel.staging-defense.in', verdict: 'SUSPICIOUS_TUNNEL_ENDPOINT' },
    ],
    welfordMetrics: {
      mean: 4.1,
      variance: 1.9,
      stdDev: 1.38,
      observedValue: 6.6,
      streamCount: 421090,
    },
  },
];

export const ThreatDetection: React.FC = () => {
  const navigate = useNavigate();

  // Active state
  const [selectedDetection, setSelectedDetection] = useState<ThreatDetectionItem>(DETECTIONS[0]);
  const [inspectingDetection, setInspectingDetection] = useState<ThreatDetectionItem | null>(null);

  // Search & Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');

  // Dry-Run Simulation Hook State
  const [dryRunModalDetection, setDryRunModalDetection] = useState<ThreatDetectionItem | null>(null);
  const [dryRunExecuting, setDryRunExecuting] = useState(false);
  const [dryRunCurrentStep, setDryRunCurrentStep] = useState(0);
  const [dryRunFinished, setDryRunFinished] = useState(false);
  const [auditHash, setAuditHash] = useState('');

  // Filtered list
  const filteredDetections = useMemo(() => {
    return DETECTIONS.filter((d) => {
      if (severityFilter !== 'ALL' && d.severity !== severityFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        return (
          d.id.toLowerCase().includes(q) ||
          d.title.toLowerCase().includes(q) ||
          d.entity.toLowerCase().includes(q) ||
          d.source.toLowerCase().includes(q) ||
          d.mitre.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [searchQuery, severityFilter]);

  // Launch Dry-Run Hook Modal & execution
  const handleLaunchDryRunHook = (detection: ThreatDetectionItem) => {
    setDryRunModalDetection(detection);
    setDryRunExecuting(false);
    setDryRunCurrentStep(0);
    setDryRunFinished(false);
    setAuditHash('');
  };

  const startDryRunExecution = () => {
    if (!dryRunModalDetection) return;
    setDryRunExecuting(true);
    setDryRunCurrentStep(1);

    setTimeout(() => {
      setDryRunCurrentStep(2);
      setTimeout(() => {
        setDryRunCurrentStep(3);
        setTimeout(() => {
          setDryRunCurrentStep(4);
          setDryRunFinished(true);
          setDryRunExecuting(false);
          setAuditHash('CAS-' + Math.random().toString(16).substring(2, 10).toUpperCase() + '-SHA256');
        }, 500);
      }, 500);
    }, 450);
  };

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-border-light">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-bold text-navy-900 tracking-tight">
              Security Intelligence & Threat Detection
            </h2>
            <Badge variant="ok" dot>
              WELFORD ENGINE: ONLINE
            </Badge>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Sliding-window multi-source correlation engine mapped to MITRE ATT&CK tactics with online Welford anomaly scoring.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Badge variant="danger" dot>
            {DETECTIONS.filter((d) => d.status === 'ACTIVE').length} ACTIVE CORRELATIONS
          </Badge>
          <Button
            variant="outline"
            size="sm"
            onClick={() => navigate('/investigation')}
            icon={<Search className="w-3.5 h-3.5" />}
            className="text-xs h-7.5"
          >
            Investigation Desk
          </Button>
          <Button
            variant="primary"
            size="sm"
            onClick={() => navigate('/playbooks')}
            icon={<Zap className="w-3.5 h-3.5" />}
            className="text-xs h-7.5"
          >
            Response Playbooks
          </Button>
        </div>
      </div>

      {/* Dynamic Multi-Stage Attack Sequence Progression */}
      <Card
        title={
          <div className="flex items-center justify-between">
            <span className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-gov-blue" />
              Multi-Source Attack Sequence Progression — {selectedDetection.id}
            </span>
            <span className="text-[11px] font-mono text-slate-400 font-normal">
              Correlated window: 300s · Z-Score: {selectedDetection.zScore}
            </span>
          </div>
        }
        subtitle={`Correlating ${selectedDetection.title} across disparate vendor telemetry streams`}
      >
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {selectedDetection.stages.map((st) => {
            const borderColors = {
              amber: 'border-amber-200 bg-amber-50/70',
              red: 'border-red-200 bg-red-50/70',
              purple: 'border-purple-200 bg-purple-50/70',
              blue: 'border-blue-200 bg-blue-50/70',
            }[st.color];

            const textColors = {
              amber: 'text-amber-800',
              red: 'text-red-800',
              purple: 'text-purple-800',
              blue: 'text-blue-800',
            }[st.color];

            return (
              <div key={st.stage} className={`p-3 rounded border ${borderColors} space-y-1.5 shadow-2xs`}>
                <div className="flex items-center justify-between">
                  <span className={`text-[10px] font-bold font-mono ${textColors}`}>{st.tactic}</span>
                  <span className="text-[10px] font-mono text-slate-500 font-semibold">{st.timeDelta}</span>
                </div>
                <div className="text-xs font-bold text-navy-900">{st.name}</div>
                <div className="text-[11px] text-slate-600 leading-snug">{st.event}</div>
                <div className="pt-1.5 border-t border-slate-200/60 flex items-center justify-between text-[10px] font-mono">
                  <span className="text-slate-500 font-medium">Sensor: {st.source}</span>
                  <span className={`font-bold ${textColors}`}>{st.mitre}</span>
                </div>
              </div>
            );
          })}
        </div>
      </Card>

      {/* Welford Online Anomaly Engine Live Bar */}
      <div className="bg-slate-900 text-white rounded p-3.5 flex flex-col md:flex-row items-center justify-between gap-3 shadow-sm border border-slate-800">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded bg-gov-blue/20 text-gov-blue flex items-center justify-center border border-gov-blue/40">
            <Cpu className="w-5 h-5" />
          </div>
          <div>
            <div className="text-xs font-bold font-mono tracking-wide text-slate-200 flex items-center gap-2">
              WELFORD RECURSIVE ONLINE ANOMALY SCORER
              <span className="text-[10px] bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 px-1.5 py-0.2 rounded font-sans">
                O(1) Memory
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-mono">
              Streaming variance: μ={selectedDetection.welfordMetrics.mean}, σ²={selectedDetection.welfordMetrics.variance}, N={selectedDetection.welfordMetrics.streamCount.toLocaleString()} items processed
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3 text-xs font-mono">
          <div className="text-right">
            <span className="text-[10px] text-slate-400 uppercase block">Active Z-Score</span>
            <span className="text-sm font-bold text-amber-400">Z = {selectedDetection.zScore}σ</span>
          </div>
          <div className="h-8 w-px bg-slate-700 mx-1 hidden sm:block" />
          <div className="text-right">
            <span className="text-[10px] text-slate-400 uppercase block">Threshold</span>
            <span className="text-sm font-bold text-red-400">&gt; 3.00σ Critical</span>
          </div>
        </div>
      </div>

      {/* Detections Table + Detail Drawer */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Left Column: Detections Table */}
        <div className="lg:col-span-8 bg-white rounded border border-border-light shadow-xs overflow-hidden flex flex-col">
          {/* Table Search & Filter Bar */}
          <div className="p-3 bg-surface-alt border-b border-border-light flex flex-wrap items-center justify-between gap-2.5">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type="text"
                placeholder="Search threat title, ID, entity, or source..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-8 pr-3 py-1.5 text-xs bg-white border border-border-medium rounded text-navy-900 focus:outline-none focus:ring-1 focus:ring-gov-blue"
              />
            </div>

            <div className="flex items-center gap-1.5 text-xs">
              <span className="text-slate-400 text-[11px]">Severity:</span>
              {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'] as const).map((sev) => (
                <button
                  key={sev}
                  type="button"
                  onClick={() => setSeverityFilter(sev)}
                  className={`px-2 py-0.5 rounded text-[10.5px] font-mono font-bold transition-all border ${
                    severityFilter === sev
                      ? 'bg-navy-900 text-white border-navy-900 shadow-2xs'
                      : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-100'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>

          <div className="overflow-hidden">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-surface-alt border-b border-border-light text-[11px] font-bold text-slate-500 uppercase tracking-wider">
                  <th className="py-2.5 px-3 whitespace-nowrap w-[80px]">Severity</th>
                  <th className="py-2.5 px-3">Detection / ID</th>
                  <th className="py-2.5 px-3 whitespace-nowrap">Disparate Sources</th>
                  <th className="py-2.5 px-3 whitespace-nowrap min-w-[170px]">
                    <div>Welford Anomaly</div>
                    <div className="text-[9.5px] font-normal text-slate-400 normal-case">Recursive Z-Score</div>
                  </th>
                  <th className="py-2.5 px-3 text-left whitespace-nowrap w-[155px]">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {filteredDetections.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-slate-500">
                      <ShieldCheck className="w-6 h-6 text-slate-300 mx-auto mb-1" />
                      <div>No active detections match "{searchQuery}".</div>
                    </td>
                  </tr>
                ) : (
                  filteredDetections.map((d) => (
                    <tr
                      key={d.id}
                      onClick={() => setSelectedDetection(d)}
                      className={`hover:bg-slate-50 transition-colors cursor-pointer ${
                        selectedDetection.id === d.id ? 'bg-gov-light/50 font-medium' : ''
                      }`}
                    >
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        <Badge
                          variant={
                            d.severity === 'CRITICAL'
                              ? 'danger'
                              : d.severity === 'HIGH'
                              ? 'warn'
                              : d.severity === 'MEDIUM'
                              ? 'neutral'
                              : 'info'
                          }
                        >
                          {d.severity}
                        </Badge>
                      </td>
                      <td className="py-2.5 px-3">
                        <div className="font-semibold text-navy-900 leading-tight">{d.title}</div>
                        <div className="text-[10.5px] font-mono text-slate-500 flex items-center gap-1.5 mt-0.5">
                          <span>{d.id}</span>
                          <span>•</span>
                          <span className="text-emerald-700 font-semibold">{d.confidence} match</span>
                        </div>
                      </td>
                      <td className="py-2.5 px-3 text-slate-600 font-mono text-[11px] truncate max-w-[140px]" title={d.source}>
                        {d.source}
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        <div className="flex items-center gap-1.5">
                          <span
                            className={`px-1.5 py-0.5 rounded font-mono font-bold text-[11px] border ${
                              d.zScore >= 3.5
                                ? 'bg-red-50 text-red-700 border-red-200'
                                : d.zScore >= 2.5
                                ? 'bg-amber-50 text-amber-800 border-amber-200'
                                : 'bg-blue-50 text-blue-700 border-blue-200'
                            }`}
                          >
                            Z = {d.zScore.toFixed(2)}σ
                          </span>
                          <span
                            className={`text-[10px] font-bold ${
                              d.zScore >= 3.5
                                ? 'text-red-700'
                                : d.zScore >= 2.5
                                ? 'text-amber-800'
                                : 'text-blue-700'
                            }`}
                          >
                            {d.zScore >= 3.5 ? 'Critical Spike' : d.zScore >= 2.5 ? 'High Anomaly' : 'Moderate'}
                          </span>
                        </div>
                        <div className="text-[10px] text-slate-500 font-mono mt-0.5 flex items-center gap-1.5">
                          <span className="text-emerald-700 font-semibold">p &lt; 0.001</span>
                          <span className="text-slate-300">•</span>
                          <span>σ² = {d.welfordMetrics.variance.toFixed(1)}</span>
                        </div>
                      </td>
                      <td className="py-2.5 px-3 text-left whitespace-nowrap">
                        <div className="flex items-center gap-1.5 whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => {
                              setSelectedDetection(d);
                              setInspectingDetection(d);
                            }}
                            className="h-7 !px-2.5 text-xs inline-flex items-center gap-1 text-gov-blue hover:text-navy-900 whitespace-nowrap flex-shrink-0 cursor-pointer"
                            title="Open comprehensive Threat Inspection Dossier"
                          >
                            <Eye className="w-3.5 h-3.5 flex-shrink-0" />
                            <span>Inspect</span>
                          </Button>
                          <Button
                            variant="secondary"
                            size="sm"
                            onClick={() => handleLaunchDryRunHook(d)}
                            className="h-7 !px-2.5 text-xs inline-flex items-center gap-1 bg-amber-50 hover:bg-amber-100 text-amber-900 border border-amber-200 whitespace-nowrap flex-shrink-0 cursor-pointer"
                            title="Dispatch SOAR Dry-Run Hook"
                          >
                            <Zap className="w-3 h-3 text-amber-600 flex-shrink-0" />
                            <span>Dry Run</span>
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right Column: Selected Detection Detail Drawer */}
        <div className="lg:col-span-4">
          <Card
            title={selectedDetection.title}
            subtitle={`Correlation ID: ${selectedDetection.id}`}
            action={
              <Badge variant={selectedDetection.severity === 'CRITICAL' ? 'danger' : 'warn'}>
                {selectedDetection.severity}
              </Badge>
            }
          >
            <div className="space-y-3.5 text-xs">
              <div className="space-y-1">
                <span className="text-[10.5px] text-slate-400 uppercase font-semibold">ATT&CK Technique:</span>
                <div className="font-mono text-xs font-semibold text-gov-blue bg-slate-50 p-1.5 rounded border border-slate-200">
                  {selectedDetection.mitre}
                </div>
              </div>

              <div className="space-y-1">
                <span className="text-[10.5px] text-slate-400 uppercase font-semibold">Primary Target Entity:</span>
                <div className="font-mono text-xs bg-slate-100 p-2 rounded text-navy-900 border border-slate-200 break-all">
                  {selectedDetection.entity}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-2 text-xs">
                <div className="p-2 bg-slate-50 rounded border border-slate-200">
                  <span className="text-[10px] text-slate-400 uppercase block font-semibold">Correlation Conf:</span>
                  <span className="font-bold text-emerald-700 font-mono">{selectedDetection.confidence}</span>
                </div>
                <div className="p-2 bg-slate-50 rounded border border-slate-200">
                  <span className="text-[10px] text-slate-400 uppercase block font-semibold">Anomaly Z-Score:</span>
                  <span className="font-bold text-amber-700 font-mono">{selectedDetection.zScore}σ</span>
                </div>
              </div>

              <div className="space-y-1">
                <span className="text-[10.5px] text-slate-400 uppercase font-semibold">Recommended Playbook:</span>
                <div className="text-[11.5px] font-semibold text-navy-900 flex items-center gap-1.5">
                  <ShieldAlert className="w-3.5 h-3.5 text-red-600 flex-shrink-0" />
                  <span>{selectedDetection.recommendedPlaybookName}</span>
                </div>
                <span className="text-[10.5px] font-mono text-slate-500 block">
                  Blast Radius: <strong className="text-amber-700">{selectedDetection.blastRadius}</strong>
                </span>
              </div>

              {/* Action Buttons */}
              <div className="pt-3 border-t border-slate-200 space-y-2">
                <Button
                  variant="primary"
                  size="sm"
                  onClick={() => handleLaunchDryRunHook(selectedDetection)}
                  className="w-full justify-center text-xs h-8.5 font-semibold flex items-center gap-1.5 !bg-amber-600 hover:!bg-amber-700 !text-white cursor-pointer shadow-xs"
                  title="Execute zero-side-effect SOAR dry run hook"
                >
                  <Zap className="w-3.5 h-3.5" />
                  Dispatch Dry-Run Playbook
                </Button>

                <div className="grid grid-cols-2 gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setInspectingDetection(selectedDetection)}
                    className="justify-center text-xs h-7.5 flex items-center gap-1 cursor-pointer"
                  >
                    <Eye className="w-3.5 h-3.5" />
                    Deep Inspect
                  </Button>

                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={() =>
                      navigate(
                        `/investigation?alertId=${selectedDetection.id}&caseId=CASE-2026-0913`
                      )
                    }
                    className="justify-center text-xs h-7.5 flex items-center gap-1 cursor-pointer"
                  >
                    <ExternalLink className="w-3.5 h-3.5" />
                    Investigation
                  </Button>
                </div>
              </div>
            </div>
          </Card>
        </div>
      </div>

      {/* ===================================================================== */}
      {/* 1. THREAT INSPECTION DOSSIER MODAL                                    */}
      {/* ===================================================================== */}
      {inspectingDetection && (
        <Dialog.Root open={!!inspectingDetection} onOpenChange={(open) => !open && setInspectingDetection(null)}>
          <Dialog.Portal>
            <Dialog.Overlay className="fixed inset-0 bg-slate-900/60 backdrop-blur-2xs z-50 animate-fade-in" />
            <Dialog.Content className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[95vw] max-w-4xl max-h-[90vh] bg-white border border-border-medium rounded-lg shadow-2xl z-50 flex flex-col overflow-hidden animate-scale-in">
              {/* Modal Header */}
              <div className="px-5 py-3.5 bg-navy-900 text-white flex items-center justify-between border-b border-slate-800">
                <div className="flex items-center gap-3">
                  <span className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
                    Threat Intelligence Dossier
                  </span>
                  <span className="font-mono text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-200 border border-slate-700">
                    {inspectingDetection.id}
                  </span>
                  <Badge variant={inspectingDetection.severity === 'CRITICAL' ? 'danger' : 'warn'}>
                    {inspectingDetection.severity}
                  </Badge>
                </div>
                <Dialog.Close asChild>
                  <button className="text-slate-400 hover:text-white p-1 rounded transition-colors cursor-pointer">
                    <X className="w-4 h-4" />
                  </button>
                </Dialog.Close>
              </div>

              {/* Status / Quick Action Ribbon */}
              <div className="px-5 py-2.5 bg-slate-50 border-b border-border-medium flex flex-wrap items-center justify-between gap-2 text-xs">
                <div className="flex items-center gap-2">
                  <span className="text-slate-500">Confidence:</span>
                  <span className="font-bold text-emerald-700 font-mono">{inspectingDetection.confidence}</span>
                  <span className="text-slate-300">•</span>
                  <span className="text-slate-500">Welford Anomaly:</span>
                  <span className="font-bold text-amber-700 font-mono">Z = {inspectingDetection.zScore}σ</span>
                </div>

                <div className="flex items-center gap-2">
                  <Button
                    size="sm"
                    variant="primary"
                    onClick={() => {
                      setInspectingDetection(null);
                      handleLaunchDryRunHook(inspectingDetection);
                    }}
                    className="text-xs h-7 px-2.5 !bg-amber-600 hover:!bg-amber-700 flex items-center gap-1 cursor-pointer"
                  >
                    <Zap className="w-3.5 h-3.5" />
                    Launch Dry-Run Hook
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => {
                      setInspectingDetection(null);
                      navigate(`/investigation?alertId=${inspectingDetection.id}&caseId=CASE-2026-0913`);
                    }}
                    className="text-xs h-7 px-2.5 flex items-center gap-1 cursor-pointer"
                  >
                    <ExternalLink className="w-3.5 h-3.5" />
                    Open Investigation Desk
                  </Button>
                </div>
              </div>

              {/* Modal Body */}
              <div className="p-5 overflow-y-auto space-y-4 text-xs">
                {/* Title & Core Metadata */}
                <div className="p-3 bg-slate-50 rounded border border-border-medium space-y-1">
                  <h3 className="text-sm font-bold text-navy-900">{inspectingDetection.title}</h3>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2 font-mono text-[11px] text-slate-600">
                    <div>
                      <span className="text-[10px] text-slate-400 uppercase block font-sans">Originating Sensors</span>
                      <span className="font-semibold text-slate-800">{inspectingDetection.source}</span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-400 uppercase block font-sans">Timestamp</span>
                      <span>{inspectingDetection.timestamp}</span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-400 uppercase block font-sans">Entity Scope</span>
                      <span className="font-semibold text-slate-800">{inspectingDetection.entity}</span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-400 uppercase block font-sans">ATT&CK Technique</span>
                      <span className="font-semibold text-gov-blue">{inspectingDetection.mitreId}</span>
                    </div>
                  </div>
                </div>

                {/* Grounded Explainability (5W) */}
                <div className="border border-border-medium rounded overflow-hidden">
                  <div className="bg-slate-100 px-3 py-1.5 border-b border-border-medium font-bold text-navy-900 text-xs flex items-center justify-between">
                    <span className="flex items-center gap-1.5">
                      <Sparkles className="w-3.5 h-3.5 text-gov-blue" />
                      Grounded 5W Explainability
                    </span>
                    <span className="text-[10px] font-mono text-slate-500 uppercase">Deterministic Inference</span>
                  </div>
                  <div className="p-3 bg-white space-y-2">
                    <div className="grid grid-cols-1 md:grid-cols-5 gap-1.5">
                      <div className="font-bold text-slate-700 font-mono text-[11px]">WHAT:</div>
                      <div className="md:col-span-4 text-slate-800">{inspectingDetection.explainability.what}</div>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-5 gap-1.5">
                      <div className="font-bold text-slate-700 font-mono text-[11px]">WHO:</div>
                      <div className="md:col-span-4 font-mono text-navy-900 font-semibold">{inspectingDetection.explainability.who}</div>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-5 gap-1.5">
                      <div className="font-bold text-slate-700 font-mono text-[11px]">WHEN:</div>
                      <div className="md:col-span-4 font-mono text-slate-700">{inspectingDetection.explainability.when}</div>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-5 gap-1.5">
                      <div className="font-bold text-slate-700 font-mono text-[11px]">WHERE:</div>
                      <div className="md:col-span-4 text-slate-800">{inspectingDetection.explainability.where}</div>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-5 gap-1.5">
                      <div className="font-bold text-slate-700 font-mono text-[11px]">WHY:</div>
                      <div className="md:col-span-4 text-slate-800">{inspectingDetection.explainability.why}</div>
                    </div>
                  </div>
                </div>

                {/* Correlated Evidence Logs */}
                <div className="space-y-1.5">
                  <span className="text-[11px] font-bold text-slate-700 uppercase tracking-wide flex items-center gap-1">
                    <Terminal className="w-3.5 h-3.5 text-slate-500" />
                    Correlated Sensor Evidence Logs
                  </span>
                  <div className="space-y-1.5 font-mono text-[11px]">
                    {inspectingDetection.evidenceLogs.map((log, idx) => (
                      <div key={idx} className="p-2.5 bg-slate-900 text-slate-200 rounded border border-slate-800">
                        <div className="flex items-center justify-between text-slate-400 text-[10px] pb-1 mb-1 border-b border-slate-800">
                          <span className="text-amber-400">{log.sensor}</span>
                          <span>{log.timestamp}</span>
                        </div>
                        <code className="text-emerald-400 break-all select-all">{log.raw}</code>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Evidence Indicators (IOCs) */}
                <div className="space-y-1.5">
                  <span className="text-[11px] font-bold text-slate-700 uppercase tracking-wide flex items-center gap-1">
                    <Crosshair className="w-3.5 h-3.5 text-slate-500" />
                    Observed Indicators of Compromise (IOCs)
                  </span>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                    {inspectingDetection.iocs.map((ioc, idx) => (
                      <div key={idx} className="p-2 bg-slate-50 rounded border border-slate-200">
                        <span className="text-[10px] text-slate-400 uppercase block font-semibold">{ioc.type}</span>
                        <div className="font-mono font-bold text-navy-900 text-[11px] truncate">{ioc.value}</div>
                        <div className="text-[10px] text-red-700 font-semibold">{ioc.verdict}</div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Modal Footer */}
              <div className="px-5 py-3 bg-slate-100 border-t border-border-medium flex items-center justify-between">
                <span className="text-slate-500 text-[11px] font-mono">
                  Sovereign Air-Gapped Analysis Verified
                </span>
                <Dialog.Close asChild>
                  <Button variant="secondary" size="sm">
                    Close Dossier
                  </Button>
                </Dialog.Close>
              </div>
            </Dialog.Content>
          </Dialog.Portal>
        </Dialog.Root>
      )}

      {/* ===================================================================== */}
      {/* 2. SOAR DRY-RUN DISPATCH SIMULATION MODAL                             */}
      {/* ===================================================================== */}
      {dryRunModalDetection && (
        <Dialog.Root open={!!dryRunModalDetection} onOpenChange={(open) => !open && setDryRunModalDetection(null)}>
          <Dialog.Portal>
            <Dialog.Overlay className="fixed inset-0 bg-slate-900/60 backdrop-blur-2xs z-50 animate-fade-in" />
            <Dialog.Content className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[95vw] max-w-2xl max-h-[90vh] bg-white border border-border-medium rounded-lg shadow-2xl z-50 flex flex-col overflow-hidden animate-scale-in">
              {/* Modal Header */}
              <div className="px-5 py-3.5 bg-navy-900 text-white flex items-center justify-between border-b border-slate-800">
                <div className="flex items-center gap-2.5">
                  <Zap className="w-4 h-4 text-amber-400" />
                  <span className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200">
                    SOAR Dry-Run Hook Dispatch Terminal
                  </span>
                </div>
                <Dialog.Close asChild>
                  <button className="text-slate-400 hover:text-white p-1 rounded transition-colors cursor-pointer">
                    <X className="w-4 h-4" />
                  </button>
                </Dialog.Close>
              </div>

              {/* Body */}
              <div className="p-5 space-y-4 text-xs overflow-y-auto">
                {/* Target context banner */}
                <div className="p-3 bg-slate-50 rounded border border-border-medium space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-bold uppercase text-slate-400">Target Threat:</span>
                    <span className="font-mono text-[10.5px] font-bold text-red-700">{dryRunModalDetection.id}</span>
                  </div>
                  <div className="font-bold text-navy-900 text-sm">{dryRunModalDetection.title}</div>
                  <div className="pt-1 text-[11px] text-slate-600 font-mono">
                    Target Entity: <strong className="text-navy-900">{dryRunModalDetection.entity}</strong>
                  </div>
                  <div className="text-[11px] text-slate-600 font-mono">
                    Linked Playbook: <strong className="text-gov-blue">{dryRunModalDetection.recommendedPlaybookName}</strong>
                  </div>
                </div>

                {/* Safety Guarantee Notice */}
                <div className="p-2.5 bg-emerald-50 rounded border border-emerald-200 flex items-start gap-2">
                  <ShieldCheck className="w-4 h-4 text-emerald-700 flex-shrink-0 mt-0.5" />
                  <div className="text-[11px] text-emerald-900 leading-snug">
                    <strong>Zero Side-Effect Simulation Guarantee:</strong> This hook executes against the dry-run telemetry mirror. No live firewall sockets, network switches, or kernel states will be modified.
                  </div>
                </div>

                {/* Step-by-Step Execution Sequence */}
                <div className="space-y-2">
                  <span className="text-[11px] font-bold uppercase tracking-wide text-slate-500 block">
                    Automated Hook Execution Steps:
                  </span>

                  <div className="space-y-2 font-mono text-xs">
                    {/* Step 1 */}
                    <div
                      className={`p-2.5 rounded border transition-all ${
                        dryRunCurrentStep >= 1
                          ? 'bg-slate-900 text-slate-200 border-slate-700'
                          : 'bg-slate-50 text-slate-400 border-slate-200'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-semibold flex items-center gap-1.5">
                          {dryRunCurrentStep > 1 ? (
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                          ) : dryRunCurrentStep === 1 ? (
                            <RefreshCw className="w-3.5 h-3.5 text-amber-400 animate-spin" />
                          ) : (
                            <span className="w-3.5 h-3.5 rounded-full border border-slate-400 inline-block text-[10px] text-center">1</span>
                          )}
                          STEP 1: Verify RBAC Operator Permission
                        </span>
                        {dryRunCurrentStep >= 1 && <span className="text-[10.5px] text-emerald-400">VALIDATED (0.012ms)</span>}
                      </div>
                      <div className="text-[11px] text-slate-400 mt-1 pl-5">
                        secops.containment.network permission authenticated against sovereign token
                      </div>
                    </div>

                    {/* Step 2 */}
                    <div
                      className={`p-2.5 rounded border transition-all ${
                        dryRunCurrentStep >= 2
                          ? 'bg-slate-900 text-slate-200 border-slate-700'
                          : 'bg-slate-50 text-slate-400 border-slate-200'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-semibold flex items-center gap-1.5">
                          {dryRunCurrentStep > 2 ? (
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                          ) : dryRunCurrentStep === 2 ? (
                            <RefreshCw className="w-3.5 h-3.5 text-amber-400 animate-spin" />
                          ) : (
                            <span className="w-3.5 h-3.5 rounded-full border border-slate-400 inline-block text-[10px] text-center">2</span>
                          )}
                          STEP 2: Compute Containment Blast Radius
                        </span>
                        {dryRunCurrentStep >= 2 && <span className="text-[10.5px] text-emerald-400">ISOLATED SIM (0.024ms)</span>}
                      </div>
                      <div className="text-[11px] text-slate-400 mt-1 pl-5">
                        Pre-flight check: Target host 10.0.1.45 isolation clamp verified with 0 impacted peers
                      </div>
                    </div>

                    {/* Step 3 */}
                    <div
                      className={`p-2.5 rounded border transition-all ${
                        dryRunCurrentStep >= 3
                          ? 'bg-slate-900 text-slate-200 border-slate-700'
                          : 'bg-slate-50 text-slate-400 border-slate-200'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-semibold flex items-center gap-1.5">
                          {dryRunCurrentStep > 3 ? (
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                          ) : dryRunCurrentStep === 3 ? (
                            <RefreshCw className="w-3.5 h-3.5 text-amber-400 animate-spin" />
                          ) : (
                            <span className="w-3.5 h-3.5 rounded-full border border-slate-400 inline-block text-[10px] text-center">3</span>
                          )}
                          STEP 3: Compile Cryptographic CAS Ledger Hash
                        </span>
                        {dryRunCurrentStep >= 3 && <span className="text-[10.5px] text-emerald-400">SIGNED (0.018ms)</span>}
                      </div>
                      <div className="text-[11px] text-slate-400 mt-1 pl-5">
                        Immutable dry-run receipt sealed: {auditHash || 'Computing SHA-256...'}
                      </div>
                    </div>

                    {/* Step 4 */}
                    <div
                      className={`p-2.5 rounded border transition-all ${
                        dryRunCurrentStep >= 4
                          ? 'bg-slate-900 text-slate-200 border-slate-700'
                          : 'bg-slate-50 text-slate-400 border-slate-200'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-semibold flex items-center gap-1.5">
                          {dryRunCurrentStep >= 4 ? (
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <span className="w-3.5 h-3.5 rounded-full border border-slate-400 inline-block text-[10px] text-center">4</span>
                          )}
                          STEP 4: Dispatch Telemetry Event to UCE Bus
                        </span>
                        {dryRunCurrentStep >= 4 && <span className="text-[10.5px] text-emerald-400">DISPATCHED (0.034ms)</span>}
                      </div>
                      <div className="text-[11px] text-slate-400 mt-1 pl-5">
                        Emitted event evt-soar-dryrun-success to sovereign log stream
                      </div>
                    </div>
                  </div>
                </div>

                {/* Audit Certificate when finished */}
                {dryRunFinished && (
                  <div className="p-3 bg-slate-900 rounded border border-emerald-500/40 text-emerald-400 font-mono text-[11px] space-y-1 animate-fade-in">
                    <div className="flex items-center justify-between font-bold text-white">
                      <span className="flex items-center gap-1.5">
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                        DRY-RUN SIMULATION HOOK DISPATCH SUCCESSFUL
                      </span>
                      <span>Total Time: 0.088ms</span>
                    </div>
                    <div className="text-slate-300">
                      Receipt Certificate: <span className="text-amber-400">{auditHash}</span>
                    </div>
                    <div className="text-[10px] text-slate-400">
                      No live state mutated. Ready for deployment review or full manual simulation in SOAR dispatcher.
                    </div>
                  </div>
                )}
              </div>

              {/* Modal Footer */}
              <div className="px-5 py-3 bg-slate-100 border-t border-border-medium flex flex-wrap items-center justify-between gap-2">
                <Dialog.Close asChild>
                  <Button variant="secondary" size="sm">
                    Close
                  </Button>
                </Dialog.Close>

                <div className="flex items-center gap-2">
                  {!dryRunFinished ? (
                    <Button
                      variant="primary"
                      size="sm"
                      onClick={startDryRunExecution}
                      disabled={dryRunExecuting}
                      className="!bg-amber-600 hover:!bg-amber-700 !text-white flex items-center gap-1.5 cursor-pointer"
                    >
                      {dryRunExecuting ? (
                        <>
                          <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                          Simulating Dispatch Hook...
                        </>
                      ) : (
                        <>
                          <Play className="w-3.5 h-3.5" />
                          Run Dry Simulation Hook
                        </>
                      )}
                    </Button>
                  ) : (
                    <>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={startDryRunExecution}
                        className="flex items-center gap-1 text-slate-700 cursor-pointer"
                      >
                        <RotateCcw className="w-3.5 h-3.5" />
                        Rerun Hook
                      </Button>
                      <Button
                        variant="primary"
                        size="sm"
                        onClick={() => {
                          setDryRunModalDetection(null);
                          navigate(
                            `/playbooks?playbook=${dryRunModalDetection.recommendedPlaybookId}&asset=${encodeURIComponent(
                              dryRunModalDetection.entity
                            )}`
                          );
                        }}
                        className="flex items-center gap-1.5 !bg-gov-blue hover:!bg-navy-900 !text-white cursor-pointer"
                      >
                        <Zap className="w-3.5 h-3.5 text-amber-300" />
                        Pivot to SOAR Playbook Simulator
                      </Button>
                    </>
                  )}
                </div>
              </div>
            </Dialog.Content>
          </Dialog.Portal>
        </Dialog.Root>
      )}
    </div>
  );
};
