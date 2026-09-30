/**
 * MITRE ATT&CK Coverage Matrix — 3-Phase Cyber Kill Chain Architecture
 *
 * Re-architected for optimal UI/UX ergonomics:
 * The 12 ATT&CK Enterprise v14.1 tactics are separated into 3 distinct operational phases:
 *   - Phase 1: Infiltration & Foothold (Tactics 1–4 · Warm Crimson/Orange/Amber/Gold)
 *   - Phase 2: Internal Spread & Evasion (Tactics 5–8 · Cool Emerald/Green/Teal/Cyan)
 *   - Phase 3: Mission Target & Impact (Tactics 9–12 · Deep Blue/Indigo/Violet/Rose)
 *
 * Each phase renders exactly 4 spacious columns, eliminating horizontal scrolling
 * while providing rich technique cards, confidence telemetry, live HUD inspection,
 * and slide-over forensic analysis.
 */

import React, { useState, useMemo, useEffect } from 'react';
import { createPortal } from 'react-dom';
import {
  Shield,
  Target,
  Eye,
  AlertTriangle,
  TrendingUp,
  ExternalLink,
  Filter,
  Search,
  X,
  CheckCircle2,
  ChevronRight,
  ChevronLeft,
  ArrowRight,
  Layers,
  ArrowUpRight,
  Zap,
  Info,
  SlidersHorizontal,
  Table,
  Grid,
  Database,
  Check,
  RotateCcw,
} from 'lucide-react';
import { NavLink } from 'react-router-dom';

// ---------------------------------------------------------------------------
// ATT&CK Data Model
// ---------------------------------------------------------------------------

type TechniqueStatus = 'DETECTED' | 'MONITORED' | 'GAP';

interface Technique {
  id: string;
  name: string;
  status: TechniqueStatus;
  logSource?: string;
  confidence?: number; // 0–100
  description?: string;
  ruleId?: string;
  mitigation?: string;
  sampleLog?: string;
}

interface Tactic {
  id: string;
  name: string;
  shortName: string;
  color: string;        // Tailwind bg class for header
  textColor: string;    // Tailwind text class
  badgeColor: string;
  borderColor: string;
  techniques: Technique[];
}

interface AttackPhase {
  id: string;
  number: number;
  name: string;
  shortName: string;
  subtitle: string;
  badge: string;
  activeRing: string;
  topBar: string;
  tacticIds: string[];
}

const ATTACK_PHASES: AttackPhase[] = [
  {
    id: 'phase-1',
    number: 1,
    name: 'Phase 1: Infiltration & Foothold',
    shortName: 'Infiltration & Foothold',
    subtitle: 'Perimeter penetration, payload execution, persistent footholds, and privilege escalation.',
    badge: 'bg-red-50 text-red-700 border-red-200',
    activeRing: 'ring-red-600 border-red-500',
    topBar: 'bg-gradient-to-r from-red-600 via-orange-500 to-amber-500',
    tacticIds: ['TA0001', 'TA0002', 'TA0003', 'TA0004'],
  },
  {
    id: 'phase-2',
    number: 2,
    name: 'Phase 2: Internal Spread & Evasion',
    shortName: 'Internal Spread & Evasion',
    subtitle: 'Security control evasion, credential dumping, host/network discovery, and lateral movement.',
    badge: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    activeRing: 'ring-emerald-600 border-emerald-500',
    topBar: 'bg-gradient-to-r from-emerald-600 via-teal-600 to-cyan-600',
    tacticIds: ['TA0005', 'TA0006', 'TA0007', 'TA0008'],
  },
  {
    id: 'phase-3',
    number: 3,
    name: 'Phase 3: Mission Target & Impact',
    shortName: 'Mission Target & Impact',
    subtitle: 'Sensitive data staging, exfiltration over command channels, C2 communications, and asset sabotage.',
    badge: 'bg-indigo-50 text-indigo-700 border-indigo-200',
    activeRing: 'ring-indigo-600 border-indigo-500',
    topBar: 'bg-gradient-to-r from-blue-600 via-indigo-600 to-rose-600',
    tacticIds: ['TA0009', 'TA0010', 'TA0011', 'TA0040'],
  },
];

const getTechniqueDetails = (tech: Technique, tactic: Tactic) => {
  return {
    ...tech,
    ruleId: tech.ruleId || `ULPF-SIG-${tactic.id}-${tech.id.replace('.', '_')}`,
    description:
      tech.description ||
      `Adversary leverages ${tech.name} (${tech.id}) within the ${tactic.name} phase to achieve operational objectives against mission-critical endpoints and directory controllers.`,
    mitigation:
      tech.mitigation ||
      `Implement strict least-privilege telemetry, restrict execution of unapproved scripts/binaries, and enforce automated real-time ULPF policy contract rules.`,
    sampleLog:
      tech.sampleLog ||
      `{"event_id":"sim-${tech.id.toLowerCase().replace(/[^a-z0-9]/g, '_')}","tactic":"${tactic.name}","technique":"${tech.id}","source":"${tech.logSource || 'Windows EventLog / Sysmon'}","status":"${tech.status}","severity":"HIGH","timestamp":"2026-09-28T19:04:00Z","digest_sha256":"4a9f...e18b"}`,
  };
};

// ---------------------------------------------------------------------------
// Full ATT&CK Enterprise v14.1 Matrix (12 Tactics in 3 Curated Phases)
// ---------------------------------------------------------------------------

const ATTACK_MATRIX: Tactic[] = [
  // ---------------- PHASE 1: INFILTRATION & FOOTHOLD (Warm Spectrum) ----------------
  {
    id: 'TA0001',
    name: 'Initial Access',
    shortName: 'Initial Access',
    color: 'bg-red-700',
    textColor: 'text-red-700',
    badgeColor: 'bg-red-50 text-red-700 border-red-200',
    borderColor: 'border-red-500',
    techniques: [
      { id: 'T1190', name: 'Exploit Public-Facing App', status: 'DETECTED', logSource: 'nginx_access + WAF', confidence: 97 },
      { id: 'T1566.001', name: 'Spearphishing Attachment', status: 'DETECTED', logSource: 'Exchange + Defender', confidence: 94 },
      { id: 'T1566.002', name: 'Spearphishing Link', status: 'DETECTED', logSource: 'Proxy + Email Gateway', confidence: 91 },
      { id: 'T1078', name: 'Valid Accounts', status: 'MONITORED', logSource: 'Okta + AD', confidence: 72 },
      { id: 'T1133', name: 'External Remote Services', status: 'MONITORED', logSource: 'pfSense + VPN', confidence: 68 },
      { id: 'T1200', name: 'Hardware Additions', status: 'GAP' },
      { id: 'T1091', name: 'Replication via Removable Media', status: 'GAP' },
    ],
  },
  {
    id: 'TA0002',
    name: 'Execution',
    shortName: 'Execution',
    color: 'bg-orange-600',
    textColor: 'text-orange-600',
    badgeColor: 'bg-orange-50 text-orange-700 border-orange-200',
    borderColor: 'border-orange-500',
    techniques: [
      { id: 'T1059.001', name: 'PowerShell', status: 'DETECTED', logSource: 'Sysmon EID 1 + 4104', confidence: 98 },
      { id: 'T1059.003', name: 'Windows Command Shell', status: 'DETECTED', logSource: 'Sysmon EID 1', confidence: 96 },
      { id: 'T1059.004', name: 'Unix Shell', status: 'DETECTED', logSource: 'auditd + sshd', confidence: 93 },
      { id: 'T1203', name: 'Exploitation for Execution', status: 'MONITORED', logSource: 'CrowdStrike Falcon', confidence: 78 },
      { id: 'T1053.005', name: 'Scheduled Task', status: 'MONITORED', logSource: 'Windows EID 4698', confidence: 81 },
      { id: 'T1106', name: 'Native API', status: 'GAP' },
      { id: 'T1129', name: 'Shared Modules', status: 'GAP' },
    ],
  },
  {
    id: 'TA0003',
    name: 'Persistence',
    shortName: 'Persistence',
    color: 'bg-amber-600',
    textColor: 'text-amber-600',
    badgeColor: 'bg-amber-50 text-amber-700 border-amber-200',
    borderColor: 'border-amber-500',
    techniques: [
      { id: 'T1136.001', name: 'Local Account Creation', status: 'DETECTED', logSource: 'Windows EID 4720 + AD', confidence: 99 },
      { id: 'T1098', name: 'Account Manipulation', status: 'DETECTED', logSource: 'AD + Okta audit', confidence: 95 },
      { id: 'T1547.001', name: 'Registry Run Keys', status: 'MONITORED', logSource: 'Sysmon EID 13', confidence: 74 },
      { id: 'T1543.003', name: 'Windows Service', status: 'MONITORED', logSource: 'Windows EID 7045', confidence: 69 },
      { id: 'T1505.003', name: 'Web Shell', status: 'DETECTED', logSource: 'nginx + file integrity', confidence: 92 },
      { id: 'T1574', name: 'Hijack Execution Flow', status: 'GAP' },
      { id: 'T1037', name: 'Boot / Logon Init Scripts', status: 'GAP' },
    ],
  },
  {
    id: 'TA0004',
    name: 'Privilege Escalation',
    shortName: 'Priv. Esc.',
    color: 'bg-yellow-600',
    textColor: 'text-yellow-700',
    badgeColor: 'bg-yellow-50 text-yellow-800 border-yellow-200',
    borderColor: 'border-yellow-500',
    techniques: [
      { id: 'T1078.004', name: 'Cloud Accounts', status: 'DETECTED', logSource: 'AWS CloudTrail', confidence: 96 },
      { id: 'T1548.002', name: 'Bypass UAC', status: 'MONITORED', logSource: 'Sysmon + Windows Sec', confidence: 71 },
      { id: 'T1134', name: 'Access Token Manipulation', status: 'MONITORED', logSource: 'Windows EID 4624', confidence: 67 },
      { id: 'T1611', name: 'Escape to Host (Container)', status: 'MONITORED', logSource: 'Docker + k8s audit', confidence: 63 },
      { id: 'T1055', name: 'Process Injection', status: 'GAP' },
      { id: 'T1484', name: 'Domain Policy Modification', status: 'GAP' },
      { id: 'T1068', name: 'Exploit for Priv Escalation', status: 'GAP' },
    ],
  },

  // ---------------- PHASE 2: INTERNAL SPREAD & EVASION (Cool Surveillance Spectrum) ----------------
  {
    id: 'TA0005',
    name: 'Defense Evasion',
    shortName: 'Def. Evasion',
    color: 'bg-emerald-700',
    textColor: 'text-emerald-700',
    badgeColor: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    borderColor: 'border-emerald-600',
    techniques: [
      { id: 'T1562.001', name: 'Disable Security Tools', status: 'DETECTED', logSource: 'Windows EID 1102 + auditd', confidence: 99 },
      { id: 'T1027', name: 'Obfuscated Files', status: 'DETECTED', logSource: 'Sysmon + Defender', confidence: 93 },
      { id: 'T1070.001', name: 'Clear Windows Event Logs', status: 'DETECTED', logSource: 'Windows EID 1102', confidence: 100 },
      { id: 'T1218', name: 'Signed Binary Proxy Exec', status: 'MONITORED', logSource: 'Sysmon EID 1', confidence: 66 },
      { id: 'T1036', name: 'Masquerading', status: 'MONITORED', logSource: 'Sysmon EID 1', confidence: 61 },
      { id: 'T1497', name: 'Virtualization/Sandbox Evasion', status: 'GAP' },
      { id: 'T1620', name: 'Reflective Code Loading', status: 'GAP' },
    ],
  },
  {
    id: 'TA0006',
    name: 'Credential Access',
    shortName: 'Cred. Access',
    color: 'bg-green-700',
    textColor: 'text-green-700',
    badgeColor: 'bg-green-50 text-green-700 border-green-200',
    borderColor: 'border-green-600',
    techniques: [
      { id: 'T1110.001', name: 'Brute Force: Password Spray', status: 'DETECTED', logSource: 'Okta + AD EID 4625', confidence: 98 },
      { id: 'T1110.003', name: 'Brute Force: Password Spray', status: 'DETECTED', logSource: 'Okta + sshd', confidence: 96 },
      { id: 'T1003.001', name: 'OS Credential Dump: LSASS', status: 'DETECTED', logSource: 'Sysmon EID 10', confidence: 97 },
      { id: 'T1557', name: 'Adversary-in-the-Middle', status: 'MONITORED', logSource: 'Network flows', confidence: 59 },
      { id: 'T1539', name: 'Steal Web Session Cookie', status: 'MONITORED', logSource: 'Proxy + browser logs', confidence: 55 },
      { id: 'T1606', name: 'Forge Web Credentials', status: 'GAP' },
      { id: 'T1528', name: 'Steal App Access Token', status: 'GAP' },
    ],
  },
  {
    id: 'TA0007',
    name: 'Discovery',
    shortName: 'Discovery',
    color: 'bg-teal-700',
    textColor: 'text-teal-700',
    badgeColor: 'bg-teal-50 text-teal-700 border-teal-200',
    borderColor: 'border-teal-600',
    techniques: [
      { id: 'T1018', name: 'Remote System Discovery', status: 'DETECTED', logSource: 'iptables + Sysmon', confidence: 88 },
      { id: 'T1087', name: 'Account Discovery', status: 'DETECTED', logSource: 'AD + auditd', confidence: 85 },
      { id: 'T1083', name: 'File and Dir Discovery', status: 'MONITORED', logSource: 'auditd', confidence: 62 },
      { id: 'T1046', name: 'Network Service Discovery', status: 'MONITORED', logSource: 'iptables + pfSense', confidence: 71 },
      { id: 'T1135', name: 'Network Share Discovery', status: 'GAP' },
      { id: 'T1120', name: 'Peripheral Device Discovery', status: 'GAP' },
      { id: 'T1057', name: 'Process Discovery', status: 'GAP' },
    ],
  },
  {
    id: 'TA0008',
    name: 'Lateral Movement',
    shortName: 'Lateral Mvmt',
    color: 'bg-cyan-700',
    textColor: 'text-cyan-700',
    badgeColor: 'bg-cyan-50 text-cyan-700 border-cyan-200',
    borderColor: 'border-cyan-600',
    techniques: [
      { id: 'T1021.002', name: 'Remote Svc: SMB/Windows Admin', status: 'DETECTED', logSource: 'iptables + Sysmon', confidence: 96 },
      { id: 'T1021.001', name: 'Remote Svc: RDP', status: 'DETECTED', logSource: 'Windows EID 4624 Type 10', confidence: 94 },
      { id: 'T1021.004', name: 'Remote Svc: SSH', status: 'DETECTED', logSource: 'sshd auth logs', confidence: 97 },
      { id: 'T1550.002', name: 'Pass the Hash', status: 'MONITORED', logSource: 'Windows EID 4624', confidence: 64 },
      { id: 'T1534', name: 'Internal Spearphishing', status: 'GAP' },
      { id: 'T1570', name: 'Lateral Tool Transfer', status: 'GAP' },
      { id: 'T1080', name: 'Taint Shared Content', status: 'GAP' },
    ],
  },

  // ---------------- PHASE 3: MISSION TARGET & IMPACT (Deep Blue / Purple / Rose Spectrum) ----------------
  {
    id: 'TA0009',
    name: 'Collection',
    shortName: 'Collection',
    color: 'bg-blue-700',
    textColor: 'text-blue-700',
    badgeColor: 'bg-blue-50 text-blue-700 border-blue-200',
    borderColor: 'border-blue-600',
    techniques: [
      { id: 'T1114.001', name: 'Email Collection: Local', status: 'MONITORED', logSource: 'Exchange audit', confidence: 58 },
      { id: 'T1560', name: 'Archive Collected Data', status: 'MONITORED', logSource: 'Sysmon + auditd', confidence: 54 },
      { id: 'T1056.001', name: 'Input Capture: Keylogging', status: 'GAP' },
      { id: 'T1113', name: 'Screen Capture', status: 'GAP' },
      { id: 'T1005', name: 'Data from Local System', status: 'GAP' },
      { id: 'T1039', name: 'Data from Network Shared Drive', status: 'GAP' },
      { id: 'T1025', name: 'Data from Removable Media', status: 'GAP' },
    ],
  },
  {
    id: 'TA0010',
    name: 'Exfiltration',
    shortName: 'Exfiltration',
    color: 'bg-indigo-700',
    textColor: 'text-indigo-700',
    badgeColor: 'bg-indigo-50 text-indigo-700 border-indigo-200',
    borderColor: 'border-indigo-600',
    techniques: [
      { id: 'T1041', name: 'Exfil over C2 Channel', status: 'DETECTED', logSource: 'pfSense + proxy', confidence: 84 },
      { id: 'T1048.003', name: 'Exfil over Unencrypted Protocol', status: 'MONITORED', logSource: 'iptables', confidence: 65 },
      { id: 'T1567', name: 'Exfil over Web Service', status: 'MONITORED', logSource: 'Proxy + DLP', confidence: 61 },
      { id: 'T1052', name: 'Exfil over Physical Medium', status: 'GAP' },
      { id: 'T1030', name: 'Data Transfer Size Limits', status: 'GAP' },
      { id: 'T1029', name: 'Scheduled Transfer', status: 'GAP' },
      { id: 'T1011', name: 'Exfil over Other Network Med', status: 'GAP' },
    ],
  },
  {
    id: 'TA0011',
    name: 'Command & Control',
    shortName: 'C2',
    color: 'bg-violet-700',
    textColor: 'text-violet-700',
    badgeColor: 'bg-violet-50 text-violet-700 border-violet-200',
    borderColor: 'border-violet-600',
    techniques: [
      { id: 'T1071.001', name: 'App Layer Protocol: Web', status: 'DETECTED', logSource: 'pfSense + proxy', confidence: 92 },
      { id: 'T1071.004', name: 'App Layer Protocol: DNS', status: 'DETECTED', logSource: 'dns_bind', confidence: 89 },
      { id: 'T1095', name: 'Non-App Layer Protocol', status: 'MONITORED', logSource: 'iptables', confidence: 66 },
      { id: 'T1573', name: 'Encrypted Channel', status: 'MONITORED', logSource: 'pfSense + SSL inspect', confidence: 58 },
      { id: 'T1090', name: 'Proxy', status: 'MONITORED', logSource: 'pfSense', confidence: 55 },
      { id: 'T1219', name: 'Remote Access Software', status: 'GAP' },
      { id: 'T1104', name: 'Multi-Stage Channels', status: 'GAP' },
    ],
  },
  {
    id: 'TA0040',
    name: 'Impact',
    shortName: 'Impact',
    color: 'bg-rose-700',
    textColor: 'text-rose-700',
    badgeColor: 'bg-rose-50 text-rose-700 border-rose-200',
    borderColor: 'border-rose-600',
    techniques: [
      { id: 'T1486', name: 'Data Encrypted for Impact', status: 'DETECTED', logSource: 'Defender + file integrity', confidence: 95 },
      { id: 'T1489', name: 'Service Stop', status: 'DETECTED', logSource: 'Windows EID 7036 + auditd', confidence: 91 },
      { id: 'T1491', name: 'Defacement', status: 'MONITORED', logSource: 'nginx + file integrity', confidence: 69 },
      { id: 'T1499', name: 'Endpoint Denial of Service', status: 'MONITORED', logSource: 'pfSense + iptables', confidence: 63 },
      { id: 'T1561', name: 'Disk Wipe', status: 'GAP' },
      { id: 'T1485', name: 'Data Destruction', status: 'GAP' },
      { id: 'T1495', name: 'Firmware Corruption', status: 'GAP' },
    ],
  },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const STATUS_STYLE: Record<TechniqueStatus, { cell: string; label: string; badge: string; dot: string }> = {
  DETECTED: {
    cell: 'bg-emerald-50 text-emerald-900 border-emerald-300',
    label: 'Detected',
    badge: 'bg-emerald-100 text-emerald-800 border-emerald-300',
    dot: 'bg-emerald-500',
  },
  MONITORED: {
    cell: 'bg-blue-50 text-blue-900 border-blue-300',
    label: 'Monitored',
    badge: 'bg-blue-100 text-blue-800 border-blue-300',
    dot: 'bg-blue-500',
  },
  GAP: {
    cell: 'bg-slate-50 text-slate-700 border-slate-200',
    label: 'Coverage Gap',
    badge: 'bg-slate-100 text-slate-600 border-slate-300',
    dot: 'bg-slate-300',
  },
};

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export const MitreAttack: React.FC = () => {
  const [selectedItem, setSelectedItem] = useState<{
    technique: Technique;
    tactic: Tactic;
    details: ReturnType<typeof getTechniqueDetails>;
  } | null>(null);

  const [hoveredItem, setHoveredItem] = useState<{
    technique: Technique;
    tactic: Tactic;
  } | null>(null);

  const [filterStatus, setFilterStatus] = useState<TechniqueStatus | 'ALL'>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  
  // View states: 'phase-1' | 'phase-2' | 'phase-3' | 'stacked' | 'table'
  const [activePhase, setActivePhase] = useState<'phase-1' | 'phase-2' | 'phase-3'>('phase-1');
  const [displayMode, setDisplayMode] = useState<'phase' | 'stacked' | 'table'>('phase');

  // Lock body scroll and listen for Escape key when inspector drawer is open
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setSelectedItem(null);
    };
    if (selectedItem) {
      document.addEventListener('keydown', handleKeyDown);
      document.body.style.overflow = 'hidden';
    }
    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      document.body.style.overflow = 'unset';
    };
  }, [selectedItem]);

  // Compute all techniques flattened with tactic info
  const allTechniquesWithTactic = useMemo(() => {
    return ATTACK_MATRIX.flatMap((tactic) =>
      tactic.techniques.map((t) => ({
        ...t,
        tacticId: tactic.id,
        tacticName: tactic.name,
        tacticShortName: tactic.shortName,
        tacticColor: tactic.color,
        tacticTextColor: tactic.textColor,
        details: getTechniqueDetails(t, tactic),
      }))
    );
  }, []);

  const total = allTechniquesWithTactic.length;
  const detected = allTechniquesWithTactic.filter((t) => t.status === 'DETECTED').length;
  const monitored = allTechniquesWithTactic.filter((t) => t.status === 'MONITORED').length;
  const gaps = allTechniquesWithTactic.filter((t) => t.status === 'GAP').length;
  const coverage = Math.round(((detected + monitored) / total) * 100);

  // Filtered flat list for table view & count
  const filteredTechniquesList = useMemo(() => {
    return allTechniquesWithTactic.filter((tech) => {
      const matchStatus = filterStatus === 'ALL' || tech.status === filterStatus;
      const q = searchQuery.toLowerCase().trim();
      const matchSearch =
        !q ||
        tech.id.toLowerCase().includes(q) ||
        tech.name.toLowerCase().includes(q) ||
        (tech.logSource && tech.logSource.toLowerCase().includes(q)) ||
        tech.tacticName.toLowerCase().includes(q);
      return matchStatus && matchSearch;
    });
  }, [allTechniquesWithTactic, filterStatus, searchQuery]);

  // Current active phase object
  const currentPhaseObj = ATTACK_PHASES.find((p) => p.id === activePhase) || ATTACK_PHASES[0];

  // Render a single tactic column (4 columns per phase, 100% width, zero horizontal scroll)
  const renderTacticColumn = (tactic: Tactic) => {
    const detectedCount = tactic.techniques.filter((t) => t.status === 'DETECTED').length;
    const monitoredCount = tactic.techniques.filter((t) => t.status === 'MONITORED').length;
    const pct = Math.round(((detectedCount + monitoredCount) / tactic.techniques.length) * 100);

    return (
      <div key={tactic.id} className="flex flex-col bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
        {/* Tactic Column Header with Related Color */}
        <div className={`p-3.5 ${tactic.color} text-white flex flex-col justify-between shadow-xs`}>
          <div className="flex items-center justify-between gap-1 mb-1">
            <span className="text-[10px] font-mono uppercase tracking-wider text-white/80 font-bold">
              {tactic.id}
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-black/20 text-white font-bold">
              {pct}% Cov
            </span>
          </div>
          <h4 className="text-xs font-bold uppercase tracking-wider text-white leading-tight">
            {tactic.name}
          </h4>
          <div className="mt-2.5 pt-2 border-t border-white/20 flex items-center justify-between text-[10px] font-mono text-white/95">
            <span>{detectedCount}/{tactic.techniques.length} Detected</span>
            <div className="w-16 bg-black/25 rounded-full h-1.5 overflow-hidden">
              <div className="bg-white h-full rounded-full" style={{ width: `${pct}%` }} />
            </div>
          </div>
        </div>

        {/* Technique Cards List */}
        <div className="p-2.5 space-y-2.5 flex-1 bg-slate-50/50">
          {tactic.techniques.map((tech) => {
            const isVisible =
              (filterStatus === 'ALL' || tech.status === filterStatus) &&
              (!searchQuery.trim() ||
                tech.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
                tech.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
                (tech.logSource && tech.logSource.toLowerCase().includes(searchQuery.toLowerCase())));

            const isSelected = selectedItem?.technique.id === tech.id;
            const isHovered = hoveredItem?.technique.id === tech.id;

            return (
              <div
                key={tech.id}
                onClick={() =>
                  setSelectedItem({
                    technique: tech,
                    tactic,
                    details: getTechniqueDetails(tech, tactic),
                  })
                }
                onMouseEnter={() => setHoveredItem({ technique: tech, tactic })}
                onMouseLeave={() => setHoveredItem(null)}
                className={`p-3 rounded-lg border text-left transition-all duration-150 cursor-pointer bg-white relative ${
                  !isVisible
                    ? 'opacity-20 pointer-events-none'
                    : isSelected
                    ? 'ring-2 ring-navy-900 border-navy-900 shadow-md scale-[1.01]'
                    : isHovered
                    ? 'shadow-md border-gov-blue -translate-y-0.5'
                    : 'hover:shadow-sm hover:border-slate-300 border-slate-200'
                }`}
              >
                {/* Left Status Indicator Bar */}
                <div
                  className={`absolute left-0 top-2 bottom-2 w-1.5 rounded-r ${
                    tech.status === 'DETECTED'
                      ? 'bg-emerald-500'
                      : tech.status === 'MONITORED'
                      ? 'bg-blue-500'
                      : 'bg-slate-300'
                  }`}
                />

                <div className="pl-1.5 space-y-1.5">
                  <div className="flex items-center justify-between gap-1.5">
                    <span className="text-xs font-mono font-bold text-navy-900">
                      {tech.id}
                    </span>
                    {tech.status === 'DETECTED' && (
                      <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200 flex items-center gap-1">
                        <CheckCircle2 className="w-2.5 h-2.5 text-emerald-600" />
                        {tech.confidence}%
                      </span>
                    )}
                    {tech.status === 'MONITORED' && (
                      <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded-full bg-blue-50 text-blue-700 border border-blue-200 flex items-center gap-1">
                        <Eye className="w-2.5 h-2.5 text-blue-600" />
                        {tech.confidence}%
                      </span>
                    )}
                    {tech.status === 'GAP' && (
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-100 text-slate-500 border border-slate-200">
                        Blindspot
                      </span>
                    )}
                  </div>

                  <div className="text-xs font-semibold text-navy-900 leading-snug line-clamp-2">
                    {tech.name}
                  </div>

                  {tech.logSource ? (
                    <div className="flex items-center gap-1.5 text-[10.5px] font-mono text-slate-600 bg-slate-50 p-1.5 rounded border border-slate-200/80">
                      <Database className="w-3 h-3 text-slate-400 flex-shrink-0" />
                      <span className="truncate">{tech.logSource}</span>
                    </div>
                  ) : (
                    <div className="text-[10px] text-slate-400 italic">
                      No active telemetry ingest
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    );
  };

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-border-light">
        <div>
          <h2 className="text-lg font-bold text-navy-900 tracking-tight flex items-center gap-2">
            <Target className="w-5 h-5 text-red-600" />
            MITRE ATT&amp;CK® Enterprise Coverage Matrix
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Enterprise v14.1 · Sovereign SOC detection coverage mapped to ULPF telemetry sources
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs font-mono font-bold text-emerald-700 bg-emerald-50 px-2.5 py-1 rounded border border-emerald-200">
            {coverage}% OVERALL COVERAGE
          </span>
          <NavLink
            to="/threat-detection"
            className="text-xs font-semibold text-gov-blue hover:underline flex items-center gap-1"
          >
            <span>Live Detections</span>
            <ExternalLink className="w-3.5 h-3.5" />
          </NavLink>
        </div>
      </div>

      {/* KPI Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: 'Techniques Detected', value: detected, color: 'text-emerald-700', bg: 'bg-emerald-50 border-emerald-200', icon: <Shield className="w-4 h-4 text-emerald-600" /> },
          { label: 'Under Monitoring',     value: monitored, color: 'text-blue-700',    bg: 'bg-blue-50 border-blue-200',       icon: <Eye className="w-4 h-4 text-blue-600" /> },
          { label: 'Coverage Gaps',        value: gaps,      color: 'text-slate-600',   bg: 'bg-slate-50 border-slate-200',     icon: <AlertTriangle className="w-4 h-4 text-slate-500" /> },
          { label: 'Coverage Efficiency',  value: `${coverage}%`, color: 'text-navy-900', bg: 'bg-white border-slate-200',    icon: <TrendingUp className="w-4 h-4 text-gov-blue" /> },
        ].map((kpi) => (
          <div key={kpi.label} className={`flex items-center gap-3 p-3 rounded-lg border ${kpi.bg}`}>
            <div>{kpi.icon}</div>
            <div>
              <div className={`text-lg font-bold font-mono ${kpi.color}`}>{kpi.value}</div>
              <div className="text-[10px] text-slate-500 font-medium uppercase tracking-wide">{kpi.label}</div>
            </div>
          </div>
        ))}
      </div>

      {/* 3-PHASE KILL CHAIN NAVIGATION CARDS (Zero horizontal scrolling, clear visual hierarchy) */}
      <div className="space-y-1.5">
        <div className="flex items-center justify-between">
          <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1.5">
            <Layers className="w-3.5 h-3.5 text-gov-blue" />
            Cyber Attack Kill Chain Phases (Select Phase to Inspect 4 Columns)
          </span>
          <span className="text-[11px] text-slate-400 font-mono hidden sm:inline">
            12 Tactics Divided into 3 Balanced Operational Phases
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {ATTACK_PHASES.map((phase) => {
            const isCurrent = activePhase === phase.id && displayMode === 'phase';
            // Phase metrics
            const phaseTactics = ATTACK_MATRIX.filter((t) => phase.tacticIds.includes(t.id));
            const phaseTechniques = phaseTactics.flatMap((t) => t.techniques);
            const phaseDetected = phaseTechniques.filter((t) => t.status === 'DETECTED').length;
            const phaseMonitored = phaseTechniques.filter((t) => t.status === 'MONITORED').length;
            const phasePct = Math.round(((phaseDetected + phaseMonitored) / phaseTechniques.length) * 100);

            return (
              <button
                key={phase.id}
                type="button"
                onClick={() => {
                  setActivePhase(phase.id as typeof activePhase);
                  setDisplayMode('phase');
                }}
                className={`p-3.5 rounded-xl border text-left transition-all cursor-pointer relative overflow-hidden ${
                  isCurrent
                    ? `bg-white shadow-md ring-2 ${phase.activeRing}`
                    : 'bg-white hover:bg-slate-50 border-slate-200 text-slate-600 hover:shadow-xs'
                }`}
              >
                <div className={`absolute top-0 left-0 right-0 h-1.5 ${phase.topBar}`} />
                <div className="flex items-center justify-between gap-2 mb-1.5 mt-0.5">
                  <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded ${phase.badge}`}>
                    Phase {phase.number} of 3
                  </span>
                  <span className="font-mono text-xs font-bold text-navy-900">
                    {phasePct}% Coverage
                  </span>
                </div>
                <div className="font-bold text-sm text-navy-900 flex items-center justify-between">
                  <span>{phase.shortName}</span>
                  {isCurrent && <span className="text-[10px] font-mono text-gov-blue uppercase font-bold">Active</span>}
                </div>
                <div className="text-[11px] text-slate-500 mt-1 line-clamp-1">{phase.subtitle}</div>

                {/* 4 Tactics included in this phase */}
                <div className="mt-2.5 pt-2 border-t border-slate-100 flex items-center justify-between text-[11px] text-slate-500 font-mono">
                  <span className="truncate pr-2">{phaseTactics.map((t) => t.shortName).join(' · ')}</span>
                  <span className="font-bold text-emerald-700 whitespace-nowrap">{phaseDetected} Detected</span>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Interactive Controls & Filters Bar */}
      <div className="bg-white border border-border-light p-3.5 rounded-lg shadow-xs space-y-3">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          {/* Search Box */}
          <div className="relative flex-1 max-w-md">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search by Technique ID (e.g. T1059), Name, or Log Source..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full text-xs pl-9 pr-8 py-2 bg-slate-50 border border-border-medium rounded-md text-navy-900 focus:outline-none focus:ring-2 focus:ring-gov-blue focus:bg-white transition-colors"
            />
            {searchQuery && (
              <button
                type="button"
                onClick={() => setSearchQuery('')}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          {/* View Mode Toggle */}
          <div className="flex items-center border border-border-medium rounded-md overflow-hidden bg-slate-100 p-0.5">
            <button
              type="button"
              onClick={() => setDisplayMode('phase')}
              className={`px-2.5 py-1 text-xs font-bold rounded flex items-center gap-1.5 transition-colors cursor-pointer ${
                displayMode === 'phase' ? 'bg-white text-navy-900 shadow-xs' : 'text-slate-600 hover:text-navy-900'
              }`}
            >
              <Grid className="w-3.5 h-3.5 text-gov-blue" />
              <span>Phase View (4 Cols)</span>
            </button>
            <button
              type="button"
              onClick={() => setDisplayMode('stacked')}
              className={`px-2.5 py-1 text-xs font-bold rounded flex items-center gap-1.5 transition-colors cursor-pointer ${
                displayMode === 'stacked' ? 'bg-white text-navy-900 shadow-xs' : 'text-slate-600 hover:text-navy-900'
              }`}
            >
              <Layers className="w-3.5 h-3.5 text-gov-blue" />
              <span>All 3 Phases (Stacked)</span>
            </button>
            <button
              type="button"
              onClick={() => setDisplayMode('table')}
              className={`px-2.5 py-1 text-xs font-bold rounded flex items-center gap-1.5 transition-colors cursor-pointer ${
                displayMode === 'table' ? 'bg-white text-navy-900 shadow-xs' : 'text-slate-600 hover:text-navy-900'
              }`}
            >
              <Table className="w-3.5 h-3.5 text-gov-blue" />
              <span>Audit Table ({filteredTechniquesList.length})</span>
            </button>
          </div>
        </div>

        {/* Status Filter Buttons */}
        <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-slate-100 text-xs">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wide">Status:</span>
            {[
              { id: 'ALL', label: `All (${total})` },
              { id: 'DETECTED', label: `Detected (${detected})`, dot: 'bg-emerald-500' },
              { id: 'MONITORED', label: `Monitored (${monitored})`, dot: 'bg-blue-500' },
              { id: 'GAP', label: `Gaps (${gaps})`, dot: 'bg-slate-300' },
            ].map((btn) => {
              const isSelected = filterStatus === btn.id;
              return (
                <button
                  key={btn.id}
                  type="button"
                  onClick={() => setFilterStatus(btn.id as typeof filterStatus)}
                  className={`px-2.5 py-1 rounded text-xs font-medium transition-all flex items-center gap-1.5 cursor-pointer ${
                    isSelected
                      ? 'bg-navy-900 text-white font-bold shadow-xs'
                      : 'bg-slate-100 hover:bg-slate-200 text-slate-700'
                  }`}
                >
                  {btn.dot && <span className={`w-2 h-2 rounded-full ${btn.dot}`} />}
                  <span>{btn.label}</span>
                </button>
              );
            })}
          </div>

          <div className="text-[11px] text-slate-500 font-mono">
            Showing {filteredTechniquesList.length} of {total} techniques
          </div>
        </div>
      </div>

      {/* Live Interactive HUD Preview Bar (Always clamped, zero overflow) */}
      <div className="p-3 bg-navy-900 text-white rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-sm border border-navy-800">
        <div className="flex items-center gap-3 overflow-hidden">
          <div className="w-8 h-8 rounded bg-white/10 flex items-center justify-center flex-shrink-0">
            <Target className="w-4 h-4 text-amber-400" />
          </div>
          <div className="min-w-0">
            {hoveredItem ? (
              <div className="flex items-center gap-2 flex-wrap text-xs">
                <span className="font-mono font-bold text-amber-300">{hoveredItem.technique.id}</span>
                <span className="font-bold text-white truncate">{hoveredItem.technique.name}</span>
                <span className="text-white/40">·</span>
                <span className="text-slate-300">{hoveredItem.tactic.name}</span>
                <span className="text-white/40">·</span>
                <span
                  className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                    hoveredItem.technique.status === 'DETECTED'
                      ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                      : hoveredItem.technique.status === 'MONITORED'
                      ? 'bg-blue-500/20 text-blue-300 border border-blue-500/40'
                      : 'bg-slate-500/20 text-slate-300 border border-slate-500/40'
                  }`}
                >
                  {hoveredItem.technique.status}
                  {hoveredItem.technique.confidence ? ` (${hoveredItem.technique.confidence}%)` : ''}
                </span>
                {hoveredItem.technique.logSource && (
                  <span className="text-slate-400 text-[11px] font-mono truncate hidden md:inline">
                    [{hoveredItem.technique.logSource}]
                  </span>
                )}
                <span className="text-[10px] text-amber-300/90 font-medium ml-1">
                  (Click card to open Full Forensic Inspector)
                </span>
              </div>
            ) : (
              <div className="text-xs text-slate-300">
                <span className="font-semibold text-white">Interactive Telemetry HUD:</span> Hover over or click any technique below to view cryptographic rule telemetry, log sources, and MITRE D3FEND mitigations.
              </div>
            )}
          </div>
        </div>

        <div className="flex items-center gap-2 flex-shrink-0 text-xs text-slate-400 font-mono">
          <span className="px-2 py-0.5 rounded bg-white/10 text-white font-bold">
            {filteredTechniquesList.length} Active in Filter
          </span>
        </div>
      </div>

      {/* DISPLAY MODE 1: SINGLE PHASE VIEW (4 Columns, zero horizontal scroll) */}
      {displayMode === 'phase' && (
        <div className="space-y-4">
          {/* Phase Banner with Stepper Navigation */}
          <div className="p-4 bg-white rounded-xl border border-slate-200 shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded ${currentPhaseObj.badge}`}>
                  Phase {currentPhaseObj.number} of 3
                </span>
                <h3 className="text-sm font-bold text-navy-900">
                  {currentPhaseObj.name}
                </h3>
              </div>
              <p className="text-xs text-slate-500">
                {currentPhaseObj.subtitle}
              </p>
            </div>

            {/* Stepper Buttons to navigate between phases */}
            <div className="flex items-center gap-2 flex-shrink-0">
              {activePhase === 'phase-2' && (
                <button
                  type="button"
                  onClick={() => setActivePhase('phase-1')}
                  className="px-3 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-md text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
                >
                  <ChevronLeft className="w-3.5 h-3.5" />
                  <span>Phase 1 (Infiltration)</span>
                </button>
              )}
              {activePhase === 'phase-3' && (
                <button
                  type="button"
                  onClick={() => setActivePhase('phase-2')}
                  className="px-3 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-md text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
                >
                  <ChevronLeft className="w-3.5 h-3.5" />
                  <span>Phase 2 (Spread &amp; Evasion)</span>
                </button>
              )}

              {activePhase === 'phase-1' && (
                <button
                  type="button"
                  onClick={() => setActivePhase('phase-2')}
                  className="px-3.5 py-1.5 bg-navy-900 hover:bg-gov-blue text-white rounded-md text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
                >
                  <span>Next: Phase 2 (Spread &amp; Evasion)</span>
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
              )}
              {activePhase === 'phase-2' && (
                <button
                  type="button"
                  onClick={() => setActivePhase('phase-3')}
                  className="px-3.5 py-1.5 bg-navy-900 hover:bg-gov-blue text-white rounded-md text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
                >
                  <span>Next: Phase 3 (Mission Target)</span>
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </div>

          {/* 4 Spacious Columns Grid (100% viewport width, zero horizontal scrolling) */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {ATTACK_MATRIX.filter((t) => currentPhaseObj.tacticIds.includes(t.id)).map((tactic) =>
              renderTacticColumn(tactic)
            )}
          </div>
        </div>
      )}

      {/* DISPLAY MODE 2: ALL 3 PHASES (STACKED VERTICALLY - 4 COLUMNS PER PHASE) */}
      {displayMode === 'stacked' && (
        <div className="space-y-8">
          {ATTACK_PHASES.map((phase) => {
            const phaseTactics = ATTACK_MATRIX.filter((t) => phase.tacticIds.includes(t.id));
            const phaseTechniques = phaseTactics.flatMap((t) => t.techniques);
            const phaseDetected = phaseTechniques.filter((t) => t.status === 'DETECTED').length;
            const phaseMonitored = phaseTechniques.filter((t) => t.status === 'MONITORED').length;
            const phasePct = Math.round(((phaseDetected + phaseMonitored) / phaseTechniques.length) * 100);

            return (
              <div key={phase.id} className="space-y-3">
                {/* Phase Section Divider Header */}
                <div className="p-3.5 bg-white rounded-xl border border-slate-200 shadow-xs flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2.5">
                    <span className={`text-[10px] font-bold uppercase tracking-wider px-2.5 py-1 rounded ${phase.badge}`}>
                      Phase {phase.number} of 3
                    </span>
                    <div>
                      <h3 className="text-sm font-bold text-navy-900">{phase.name}</h3>
                      <p className="text-[11px] text-slate-500">{phase.subtitle}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3 text-xs font-mono">
                    <span className="text-emerald-700 font-bold bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200">
                      {phaseDetected} Detected
                    </span>
                    <span className="text-navy-900 font-bold">
                      {phasePct}% Coverage
                    </span>
                  </div>
                </div>

                {/* 4 Columns for this Phase */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                  {phaseTactics.map((tactic) => renderTacticColumn(tactic))}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* DISPLAY MODE 3: AUDIT TABLE VIEW */}
      {displayMode === 'table' && (
        <div className="bg-white border border-border-light rounded-lg overflow-hidden shadow-xs">
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="bg-slate-50 border-b border-slate-200 text-[10.5px] font-bold text-slate-600 uppercase tracking-wider text-left">
                  <th className="py-2.5 px-3">Technique ID</th>
                  <th className="py-2.5 px-3">Technique Name</th>
                  <th className="py-2.5 px-3">Tactic</th>
                  <th className="py-2.5 px-3">Coverage Status</th>
                  <th className="py-2.5 px-3">Telemetry Log Source</th>
                  <th className="py-2.5 px-3 text-right">Confidence</th>
                  <th className="py-2.5 px-3 text-center">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {filteredTechniquesList.map((item) => (
                  <tr
                    key={item.id}
                    onClick={() =>
                      setSelectedItem({
                        technique: item,
                        tactic: ATTACK_MATRIX.find((t) => t.id === item.tacticId) || ATTACK_MATRIX[0],
                        details: item.details,
                      })
                    }
                    className="hover:bg-slate-50 cursor-pointer transition-colors"
                  >
                    <td className="py-2 px-3 font-mono font-bold text-gov-blue">{item.id}</td>
                    <td className="py-2 px-3 font-semibold text-navy-900">{item.name}</td>
                    <td className="py-2 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${item.tacticTextColor} bg-slate-100`}>
                        {item.tacticShortName}
                      </span>
                    </td>
                    <td className="py-2 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${STATUS_STYLE[item.status].badge}`}>
                        {item.status}
                      </span>
                    </td>
                    <td className="py-2 px-3 font-mono text-[11px] text-slate-600">
                      {item.logSource || '—'}
                    </td>
                    <td className="py-2 px-3 text-right font-mono">
                      {item.confidence !== undefined ? (
                        <div className="flex items-center justify-end gap-2">
                          <div className="w-14 bg-slate-100 rounded-full h-1.5">
                            <div
                              className="bg-emerald-500 h-1.5 rounded-full"
                              style={{ width: `${item.confidence}%` }}
                            />
                          </div>
                          <span className="font-bold text-emerald-700">{item.confidence}%</span>
                        </div>
                      ) : (
                        <span className="text-slate-400">—</span>
                      )}
                    </td>
                    <td className="py-2 px-3 text-center">
                      <button
                        type="button"
                        className="px-2 py-1 text-[11px] font-bold text-gov-blue hover:underline cursor-pointer"
                      >
                        Inspect →
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Top Active Detections — Highest Confidence Rules Table */}
      <div className="bg-white border border-border-light rounded-lg overflow-hidden shadow-xs">
        <div className="px-4 py-3 bg-surface-alt border-b border-border-light flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-emerald-600" />
            <span className="text-xs font-bold text-navy-900 uppercase tracking-wider">
              Top Active Detections — Highest Confidence Rules
            </span>
          </div>
          <span className="text-xs font-semibold text-emerald-700 bg-emerald-50 border border-emerald-200 px-2 py-0.5 rounded font-mono">
            {detected} Active Rules
          </span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="bg-slate-50 border-b border-slate-100 text-[10.5px] font-bold text-slate-500 uppercase tracking-wider text-left">
                <th className="py-2 px-3">Technique ID</th>
                <th className="py-2 px-3">Name</th>
                <th className="py-2 px-3">Tactic</th>
                <th className="py-2 px-3">Log Source</th>
                <th className="py-2 px-3 text-right">Confidence</th>
                <th className="py-2 px-3 text-center">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {allTechniquesWithTactic
                .filter((t) => t.status === 'DETECTED')
                .sort((a, b) => (b.confidence ?? 0) - (a.confidence ?? 0))
                .slice(0, 10)
                .map((tech) => (
                  <tr
                    key={tech.id}
                    onClick={() => {
                      const tac = ATTACK_MATRIX.find((t) => t.id === tech.tacticId) || ATTACK_MATRIX[0];
                      setSelectedItem({ technique: tech, tactic: tac, details: tech.details });
                    }}
                    className="hover:bg-slate-50 transition-colors cursor-pointer"
                  >
                    <td className="py-2.5 px-3 font-mono font-bold text-gov-blue">{tech.id}</td>
                    <td className="py-2.5 px-3 font-medium text-navy-900">{tech.name}</td>
                    <td className={`py-2.5 px-3 font-semibold text-xs ${tech.tacticTextColor}`}>{tech.tacticName}</td>
                    <td className="py-2.5 px-3 font-mono text-[11px] text-slate-600">{tech.logSource}</td>
                    <td className="py-2.5 px-3 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <div className="w-16 bg-slate-100 rounded-full h-1.5">
                          <div
                            className="bg-emerald-500 h-1.5 rounded-full"
                            style={{ width: `${tech.confidence}%` }}
                          />
                        </div>
                        <span className="font-bold text-emerald-700 font-mono">{tech.confidence}%</span>
                      </div>
                    </td>
                    <td className="py-2.5 px-3 text-center">
                      <span className="text-gov-blue font-bold text-xs hover:underline flex items-center justify-center gap-1">
                        <span>Details</span>
                        <ChevronRight className="w-3.5 h-3.5" />
                      </span>
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Interactive Technique Inspector Drawer (Rendered via Portal to document.body for full 100vh page height coverage) */}
      {selectedItem &&
        typeof document !== 'undefined' &&
        createPortal(
          <div
            className="fixed inset-0 z-[100] flex justify-end bg-navy-900/50 backdrop-blur-xs transition-opacity animate-in fade-in"
            onClick={() => setSelectedItem(null)}
          >
            <div
              className="w-full max-w-lg bg-white h-screen shadow-2xl flex flex-col border-l border-border-light overflow-hidden animate-in slide-in-from-right duration-200"
              role="dialog"
              aria-modal="true"
              onClick={(e) => e.stopPropagation()}
            >
              {/* Drawer Header */}
              <div className={`p-4 ${selectedItem.tactic.color} text-white flex items-center justify-between shadow-xs flex-shrink-0`}>
                <div className="flex items-center gap-2.5">
                  <Target className="w-5 h-5 text-white/90" />
                  <div>
                    <div className="text-[10px] font-bold uppercase tracking-wider text-white/80 font-mono">
                      {selectedItem.tactic.id} · {selectedItem.tactic.name}
                    </div>
                    <h3 className="text-sm font-bold text-white tracking-tight flex items-center gap-2">
                      <span>{selectedItem.technique.id}</span>
                      <span className="font-normal text-white/90">· {selectedItem.technique.name}</span>
                    </h3>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => setSelectedItem(null)}
                  className="text-white/80 hover:text-white p-1 rounded-md hover:bg-white/10 transition-colors cursor-pointer"
                  aria-label="Close Inspector"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {/* Drawer Body */}
              <div className="p-5 flex-1 overflow-y-auto space-y-4 text-xs">
                {/* Status & Confidence Card */}
                <div className="p-3.5 rounded-lg border bg-slate-50 border-slate-200 flex items-center justify-between">
                  <div>
                    <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wide block mb-1">
                      Coverage Posture
                    </span>
                    <div className="flex items-center gap-2">
                      <span
                        className={`w-2.5 h-2.5 rounded-full ${
                          selectedItem.technique.status === 'DETECTED'
                            ? 'bg-emerald-500'
                            : selectedItem.technique.status === 'MONITORED'
                            ? 'bg-blue-500'
                            : 'bg-slate-400'
                        }`}
                      />
                      <span className="font-bold text-navy-900 text-sm">{selectedItem.technique.status}</span>
                    </div>
                  </div>

                  {selectedItem.technique.confidence !== undefined && (
                    <div className="text-right">
                      <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wide block mb-1">
                        Detection Confidence
                      </span>
                      <span className="text-lg font-bold font-mono text-emerald-700">
                        {selectedItem.technique.confidence}%
                      </span>
                    </div>
                  )}
                </div>

                {/* Ingestion Source */}
                <div className="border border-slate-200 rounded-lg p-3.5 space-y-1.5">
                  <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wide block">
                    Telemetry Ingestion Log Source
                  </span>
                  <div className="font-mono text-xs font-semibold text-navy-900 bg-white p-2.5 rounded border border-slate-200 flex items-center gap-2">
                    <Database className="w-3.5 h-3.5 text-gov-blue flex-shrink-0" />
                    <span>{selectedItem.technique.logSource || 'No telemetry ingested currently (Coverage Gap)'}</span>
                  </div>
                </div>

                {/* Active Detection Rule */}
                <div className="border border-slate-200 rounded-lg p-3.5 space-y-1.5">
                  <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wide block">
                    Active ULPF Detection Rule Signature
                  </span>
                  <div className="font-mono text-xs font-semibold text-gov-blue bg-blue-50/60 p-2.5 rounded border border-blue-100 flex items-center gap-2">
                    <Shield className="w-3.5 h-3.5 text-gov-blue flex-shrink-0" />
                    <span>{selectedItem.details.ruleId}</span>
                  </div>
                </div>

                {/* Description */}
                <div className="border border-slate-200 rounded-lg p-3.5 space-y-1.5">
                  <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wide block">
                    Technique Description & Context
                  </span>
                  <p className="text-slate-700 leading-relaxed text-xs">
                    {selectedItem.details.description}
                  </p>
                </div>

                {/* Mitigation Guidance */}
                <div className="border border-slate-200 rounded-lg p-3.5 space-y-1.5 bg-emerald-50/40 border-emerald-200">
                  <span className="text-[10px] font-bold text-emerald-900 uppercase tracking-wide flex items-center gap-1.5">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                    Recommended Mitigation & Defense
                  </span>
                  <p className="text-slate-700 leading-relaxed text-xs">
                    {selectedItem.details.mitigation}
                  </p>
                </div>

                {/* Raw Normalized Sample */}
                <div className="border border-slate-200 rounded-lg p-3.5 space-y-1.5">
                  <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wide block">
                    Simulated Normalized Telemetry (UCE)
                  </span>
                  <pre className="font-mono text-[11px] bg-navy-900 text-emerald-400 p-3 rounded-md overflow-x-auto leading-relaxed">
                    {selectedItem.details.sampleLog}
                  </pre>
                </div>
              </div>

              {/* Drawer Footer Actions */}
              <div className="p-4 bg-slate-50 border-t border-border-light flex flex-wrap items-center justify-between gap-2 flex-shrink-0">
                <a
                  href={`https://attack.mitre.org/techniques/${selectedItem.technique.id.replace('.', '/')}/`}
                  target="_blank"
                  rel="noreferrer"
                  className="text-xs font-semibold text-gov-blue hover:underline flex items-center gap-1"
                >
                  <span>MITRE ATT&amp;CK Wiki</span>
                  <ExternalLink className="w-3.5 h-3.5" />
                </a>

                <div className="flex items-center gap-2">
                  <NavLink
                    to="/threat-detection"
                    className="px-3 py-1.5 bg-navy-900 hover:bg-gov-blue text-white rounded text-xs font-semibold flex items-center gap-1.5 transition-colors"
                  >
                    <span>Pivot to Detection</span>
                    <ArrowUpRight className="w-3.5 h-3.5" />
                  </NavLink>
                  <button
                    type="button"
                    onClick={() => setSelectedItem(null)}
                    className="px-3 py-1.5 bg-slate-200 hover:bg-slate-300 text-slate-700 rounded text-xs font-semibold transition-colors cursor-pointer"
                  >
                    Close
                  </button>
                </div>
              </div>
            </div>
          </div>,
          document.body
        )}

      {/* Footer note */}
      <p className="text-[10px] text-slate-400 text-center">
        MITRE ATT&amp;CK® is a registered trademark of The MITRE Corporation. Coverage is mapped to ULPF telemetry ingestion sources active in this deployment. Enterprise v14.1.
      </p>
    </div>
  );
};
