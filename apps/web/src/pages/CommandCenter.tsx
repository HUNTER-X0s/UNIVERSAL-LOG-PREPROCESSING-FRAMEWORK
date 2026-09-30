import React, { useState, useEffect } from 'react';
import { jsPDF } from 'jspdf';
import { PipelineVisualization } from '../components/telemetry/PipelineVisualization';
import { PARSERS_DATA } from '../demo/parsersData';
import {
  CheckCircle2,
  Server,
  ArrowRight,
  Shield,
  ShieldCheck,
  Lock,
  Clock,
  Activity,
  Database,
  Cpu,
  FileCheck,
  AlertTriangle,
  ExternalLink,
  Copy,
  Check,
  FileText,
  Download,
  RefreshCw,
  X,
  Layers,
  Link as LinkIcon,
  HardDrive,
  Share2,
  Search,
  Filter
} from 'lucide-react';
import { NavLink } from 'react-router-dom';

interface IncidentAlert {
  id: string;
  timestamp: string;
  severity: 'CRITICAL' | 'HIGH' | 'ELEVATED' | 'MEDIUM';
  mitreTactic: string;
  mitreId: string;
  source: string;
  vendor: string;
  summary: string;
  entity: string;
  rawHash: string;
  uceHash: string;
  blockHeight: number;
}

interface BlockchainBlock {
  blockHeight: number;
  blockHash: string;
  merkleRoot: string;
  previousHash: string;
  timestamp: string;
  eventCount: number;
  validator: string;
  status: 'SEALED' | 'VALIDATED';
}

const SAMPLE_INCIDENTS: IncidentAlert[] = [
  {
    id: 'INC-2026-9812',
    timestamp: '2026-09-20 23:45:12.891 IST',
    severity: 'CRITICAL',
    mitreTactic: 'Credential Access',
    mitreId: 'T1110.001',
    source: 'Okta Identity Engine',
    vendor: 'Okta',
    summary: 'Distributed password spray targeting privileged admin roles',
    entity: 'usr:admin.secops@ulpf.internal',
    rawHash: '8e4c9f1a2b3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f',
    uceHash: '3b7a1e9c5f8d2a4b6c0e1f3a5b7d9e2f4a6b8c0d1e3f5a7b9c1d3e5f7a9b1c3d',
    blockHeight: 48294
  },
  {
    id: 'INC-2026-9811',
    timestamp: '2026-09-20 23:42:04.108 IST',
    severity: 'HIGH',
    mitreTactic: 'Privilege Escalation',
    mitreId: 'T1078.004',
    source: 'AWS CloudTrail',
    vendor: 'Amazon Web Services',
    summary: 'Unauthorized AssumeRole into Core S3 Cryptographic Vault',
    entity: 'arn:aws:iam::091248192:role/SecAuditAdmin',
    rawHash: '1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b',
    uceHash: '4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a',
    blockHeight: 48294
  },
  {
    id: 'INC-2026-9810',
    timestamp: '2026-09-20 23:38:51.442 IST',
    severity: 'HIGH',
    mitreTactic: 'Execution',
    mitreId: 'T1059.001',
    source: 'CrowdStrike Falcon',
    vendor: 'CrowdStrike',
    summary: 'Base64 obfuscated PowerShell spawning from spoolsv.exe',
    entity: 'host:DEL-SRV-DC01 (10.14.8.4)',
    rawHash: '9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b',
    uceHash: '7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d',
    blockHeight: 48293
  },
  {
    id: 'INC-2026-9809',
    timestamp: '2026-09-20 23:31:19.004 IST',
    severity: 'ELEVATED',
    mitreTactic: 'Defense Evasion',
    mitreId: 'T1562.001',
    source: 'Windows Security EventLog',
    vendor: 'Microsoft',
    summary: 'Security log clearing attempt intercepted (EventID 1102)',
    entity: 'account:NT-AUTHORITY\\SYSTEM',
    rawHash: 'f1e2d3c4b5a69f8e7d6c5b4a3928172635445566778899aabbccddeeff001122',
    uceHash: '99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa',
    blockHeight: 48292
  }
];

const SAMPLE_BLOCKS: BlockchainBlock[] = [
  {
    blockHeight: 48294,
    blockHash: '0x7f9a2b8c4d1e0f3a6b5c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a',
    merkleRoot: '0x9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d',
    previousHash: '0x4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e',
    timestamp: '2026-09-20 23:45:00 IST',
    eventCount: 2048,
    validator: 'Consensus-Validator-Node-01',
    status: 'SEALED'
  },
  {
    blockHeight: 48293,
    blockHash: '0x4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e',
    merkleRoot: '0x3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b',
    previousHash: '0x1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b',
    timestamp: '2026-09-20 23:40:00 IST',
    eventCount: 2048,
    validator: 'Relay-Validator-Node-02',
    status: 'SEALED'
  },
  {
    blockHeight: 48292,
    blockHash: '0x1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b',
    merkleRoot: '0x8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e',
    previousHash: '0x5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d',
    timestamp: '2026-09-20 23:35:00 IST',
    eventCount: 2048,
    validator: 'DCA-Witness-Node-03',
    status: 'SEALED'
  }
];

export const CommandCenter: React.FC = () => {
  const [selectedIncident, setSelectedIncident] = useState<IncidentAlert | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [currentTimeIST, setCurrentTimeIST] = useState<string>('');
  const [currentTimeUTC, setCurrentTimeUTC] = useState<string>('');
  const [isExporting, setIsExporting] = useState<boolean>(false);
  const [acknowledgedIds, setAcknowledgedIds] = useState<Set<string>>(() => {
    try {
      const stored = localStorage.getItem('ulpf_acknowledged_incidents');
      if (stored) {
        const list = JSON.parse(stored);
        if (Array.isArray(list)) return new Set(list);
      }
    } catch {}
    return new Set();
  });
  const [incidentSearch, setIncidentSearch] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [liveEps, setLiveEps] = useState(14850);
  const [slaSeconds, setSlaSeconds] = useState(4 * 3600 + 48 * 60); // 4h 48m in seconds

  // Cross-feature incident acknowledgment sync
  useEffect(() => {
    const handleRemoteAck = (e: Event) => {
      const customEvent = e as CustomEvent<{ id: string }>;
      if (customEvent.detail?.id) {
        setAcknowledgedIds((prev) => {
          const updated = new Set(prev);
          updated.add(customEvent.detail.id);
          return updated;
        });
      }
    };
    window.addEventListener('ulpf:incident_acknowledged', handleRemoteAck);
    return () => window.removeEventListener('ulpf:incident_acknowledged', handleRemoteAck);
  }, []);

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setCurrentTimeIST(
        now.toLocaleString('en-IN', {
          timeZone: 'Asia/Kolkata',
          hour12: false,
          year: 'numeric',
          month: '2-digit',
          day: '2-digit',
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit'
        }) + ' IST'
      );
      setCurrentTimeUTC(
        now.toISOString().replace('T', ' ').substring(0, 19) + ' UTC'
      );
    };
    updateTime();
    const timer = setInterval(updateTime, 1000);
    return () => clearInterval(timer);
  }, []);

  // Live EPS jitter animation
  useEffect(() => {
    const epsTimer = setInterval(() => {
      setLiveEps((prev) => {
        const delta = Math.floor(Math.random() * 400) - 200;
        return Math.max(13000, Math.min(16500, prev + delta));
      });
    }, 1800);
    return () => clearInterval(epsTimer);
  }, []);

  // Live SLA countdown
  useEffect(() => {
    const slaTimer = setInterval(() => {
      setSlaSeconds((prev) => Math.max(0, prev - 1));
    }, 1000);
    return () => clearInterval(slaTimer);
  }, []);

  const formatSla = (totalSecs: number) => {
    const h = Math.floor(totalSecs / 3600);
    const m = Math.floor((totalSecs % 3600) / 60);
    const s = totalSecs % 60;
    return `${h}h ${m.toString().padStart(2, '0')}m ${s.toString().padStart(2, '0')}s`;
  };

  const filteredIncidents = SAMPLE_INCIDENTS.filter((inc) => {
    const matchesSeverity = selectedSeverity === 'ALL' || inc.severity === selectedSeverity;
    const q = incidentSearch.toLowerCase();
    const matchesQuery = !q || inc.id.toLowerCase().includes(q) || inc.summary.toLowerCase().includes(q) ||
      inc.mitreTactic.toLowerCase().includes(q) || inc.source.toLowerCase().includes(q) ||
      inc.severity.toLowerCase().includes(q);
    return matchesSeverity && matchesQuery;
  });

  const handleRefreshIncidents = () => {
    setIsRefreshing(true);
    setTimeout(() => setIsRefreshing(false), 600);
  };

  const handleAcknowledge = (id: string) => {
    setAcknowledgedIds((prev) => {
      const updated = new Set(prev);
      updated.add(id);
      try {
        localStorage.setItem('ulpf_acknowledged_incidents', JSON.stringify([...updated]));
      } catch {}
      return updated;
    });
    try {
      window.dispatchEvent(new CustomEvent('ulpf:incident_acknowledged', { detail: { id } }));
    } catch {}
  };

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(id);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const exportForensicCertificate = (incident: IncidentAlert) => {
    setIsExporting(true);
    try {
      const doc = new jsPDF({
        orientation: 'portrait',
        unit: 'mm',
        format: 'a4',
      });

      // Outer & Inner Certificate Framing
      doc.setDrawColor(15, 23, 42); // Navy 900
      doc.setLineWidth(1.2);
      doc.rect(8, 8, 194, 281);

      doc.setDrawColor(203, 213, 225); // Slate 300
      doc.setLineWidth(0.4);
      doc.rect(10, 10, 190, 277);

      // Header Banner
      doc.setFillColor(15, 23, 42);
      doc.rect(10, 10, 190, 28, 'F');

      doc.setTextColor(255, 255, 255);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(13);
      doc.text('UNIVERSAL LOG PREPROCESSING FRAMEWORK', 105, 19, { align: 'center' });

      doc.setFontSize(9);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(226, 232, 240);
      doc.text('CRYPTOGRAPHIC FORENSIC EVIDENCE CERTIFICATE', 105, 25, { align: 'center' });

      doc.setFontSize(7.5);
      doc.setTextColor(148, 163, 184);
      doc.text(`ISSUED: ${new Date().toUTCString()} · CLEARANCE: HIGH-INTEGRITY AUDIT`, 105, 31, { align: 'center' });

      // Section 1: Incident & Target Asset
      doc.setFillColor(248, 250, 252);
      doc.rect(15, 42, 180, 45, 'F');
      doc.setDrawColor(226, 232, 240);
      doc.rect(15, 42, 180, 45, 'S');

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8.5);
      doc.setTextColor(30, 41, 59);
      doc.text('1. INCIDENT IDENTIFICATION & TARGET ASSET', 20, 48);

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8);
      doc.setTextColor(71, 85, 105);

      doc.text('Incident Reference:', 20, 55);
      doc.setFont('courier', 'bold');
      doc.setTextColor(15, 23, 42);
      doc.text(incident.id, 55, 55);

      doc.setFont('helvetica', 'normal');
      doc.setTextColor(71, 85, 105);
      doc.text('Severity Rating:', 120, 55);
      doc.setFont('helvetica', 'bold');
      if (incident.severity === 'CRITICAL') doc.setTextColor(185, 28, 28);
      else if (incident.severity === 'HIGH') doc.setTextColor(194, 65, 12);
      else doc.setTextColor(29, 78, 216);
      doc.text(incident.severity, 150, 55);

      doc.setFont('helvetica', 'normal');
      doc.setTextColor(71, 85, 105);
      doc.text('Ingest Timestamp:', 20, 62);
      doc.setFont('courier', 'normal');
      doc.setTextColor(15, 23, 42);
      doc.text(incident.timestamp, 55, 62);

      doc.setFont('helvetica', 'normal');
      doc.setTextColor(71, 85, 105);
      doc.text('Telemetry Source:', 120, 62);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(15, 23, 42);
      doc.text(`${incident.source} (${incident.vendor})`, 150, 62);

      doc.setFont('helvetica', 'normal');
      doc.setTextColor(71, 85, 105);
      doc.text('Target Entity:', 20, 69);
      doc.setFont('courier', 'normal');
      doc.setTextColor(15, 23, 42);
      doc.text(incident.entity, 55, 69);

      doc.setFont('helvetica', 'normal');
      doc.setTextColor(71, 85, 105);
      doc.text('MITRE ATT&CK:', 120, 69);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(15, 23, 42);
      doc.text(`${incident.mitreId} - ${incident.mitreTactic}`, 150, 69);

      doc.setFont('helvetica', 'normal');
      doc.setTextColor(71, 85, 105);
      doc.text('Threat Summary:', 20, 76);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(15, 23, 42);
      doc.text(incident.summary, 55, 76, { maxWidth: 135 });

      // Section 2: Cryptographic Chain of Custody Proofs
      doc.setFillColor(248, 250, 252);
      doc.rect(15, 92, 180, 64, 'F');
      doc.setDrawColor(226, 232, 240);
      doc.rect(15, 92, 180, 64, 'S');

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8.5);
      doc.setTextColor(30, 41, 59);
      doc.text('2. CRYPTOGRAPHIC CHAIN-OF-CUSTODY AUDIT TRAIL', 20, 98);

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.5);
      doc.setTextColor(100, 116, 139);
      doc.text('Raw Ingest Telemetry Payload SHA-256 Digest:', 20, 105);
      doc.setFont('courier', 'bold');
      doc.setTextColor(15, 23, 42);
      doc.setFontSize(7);
      doc.text(incident.rawHash, 20, 110);

      doc.setFont('helvetica', 'normal');
      doc.setTextColor(100, 116, 139);
      doc.setFontSize(7.5);
      doc.text('Canonical Normalized UCE v1.0 Payload SHA-256 Digest:', 20, 117);
      doc.setFont('courier', 'bold');
      doc.setTextColor(15, 23, 42);
      doc.setFontSize(7);
      doc.text(incident.uceHash, 20, 122);

      doc.setFont('helvetica', 'normal');
      doc.setTextColor(100, 116, 139);
      doc.setFontSize(7.5);
      doc.text('Permissioned Blockchain Anchoring Height:', 20, 129);
      doc.setFont('courier', 'bold');
      doc.setTextColor(29, 78, 216);
      doc.setFontSize(8);
      doc.text(`Block #${incident.blockHeight.toLocaleString()} (NIST FIPS 180-4 SHA-256 Merkle Sealed)`, 20, 134);

      doc.setFont('helvetica', 'normal');
      doc.setTextColor(100, 116, 139);
      doc.setFontSize(7.5);
      doc.text('Consensus Verification State:', 20, 141);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(21, 128, 61);
      doc.setFontSize(8);
      doc.text('CONFIRMED & VALIDATED (4/4 Distributed Consensus Nodes · Zero Fork)', 20, 146);

      // Section 3: High-Integrity Declaration
      doc.setFillColor(240, 249, 255);
      doc.rect(15, 161, 180, 36, 'F');
      doc.setDrawColor(186, 230, 253);
      doc.rect(15, 161, 180, 36, 'S');

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8.5);
      doc.setTextColor(3, 105, 161);
      doc.text('3. CERTIFICATION OF CRYPTOGRAPHIC INTEGRITY', 20, 167);

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.5);
      doc.setTextColor(51, 65, 85);
      const declarationText = `This electronic record was ingested, sanitized, and canonically normalized by the Universal Log Preprocessing Framework operating in high-integrity audit mode. The cryptographic SHA-256 digest of both the raw payload and the sanitized UCE schema representation was permanently committed to the immutable permissioned blockchain at timestamp ${incident.timestamp}. It is certified that no retroactive alteration, tampering, or bit-level corruption has occurred since on-chain consensus confirmation.`;
      doc.text(declarationText, 20, 173, { maxWidth: 170, lineHeightFactor: 1.35 });

      // Section 4: Forensic Authority Signatures & Seals
      doc.setFillColor(248, 250, 252);
      doc.rect(15, 202, 180, 56, 'F');
      doc.setDrawColor(226, 232, 240);
      doc.rect(15, 202, 180, 56, 'S');

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8.5);
      doc.setTextColor(30, 41, 59);
      doc.text('4. FORENSIC ATTESTATION & SIGNATURE VERIFICATION', 20, 208);

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.5);
      doc.setTextColor(71, 85, 105);
      doc.text('Signing Authority:', 20, 216);
      doc.setFont('courier', 'bold');
      doc.setTextColor(15, 23, 42);
      doc.text('ULPF_CYBER_FORENSIC_KEY_01 (RSA-4096 / ED25519)', 55, 216);

      doc.setFont('helvetica', 'normal');
      doc.setTextColor(71, 85, 105);
      doc.text('Storage Proof:', 20, 223);
      doc.setFont('courier', 'normal');
      doc.setTextColor(15, 23, 42);
      doc.text(`cas/immutable_store/sha256/${incident.uceHash.substring(0, 20)}...`, 55, 223);

      doc.setFont('helvetica', 'normal');
      doc.setTextColor(71, 85, 105);
      doc.text('Verification Code:', 20, 230);
      doc.setFont('courier', 'bold');
      doc.setTextColor(29, 78, 216);
      doc.text(`ULPF-VERIFY-${incident.id}-${incident.blockHeight}`, 55, 230);

      // Signature line
      doc.setDrawColor(148, 163, 184);
      doc.setLineWidth(0.5);
      doc.line(135, 244, 185, 244);
      doc.setFont('helvetica', 'italic');
      doc.setFontSize(7);
      doc.setTextColor(100, 116, 139);
      doc.text('Authorized Digital Forensic Officer', 137, 248);

      // Footer
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7);
      doc.setTextColor(148, 163, 184);
      doc.text('Universal Log Preprocessing Framework (ULPF) · Forensic Telemetry & Blockchain Subsystem', 105, 275, { align: 'center' });

      // Save PDF directly to user's downloads
      doc.save(`${incident.id}_Forensic_Evidence_Certificate.pdf`);
    } catch (err) {
      console.error('Failed to generate forensic certificate PDF:', err);
    } finally {
      setTimeout(() => setIsExporting(false), 1000);
    }
  };

  return (
    <div className="space-y-4">
      {/* Telemetry Header & Classification Ribbon */}
      <div className="bg-white border border-border-medium rounded shadow-2xs overflow-hidden">
        <div className="bg-navy-900 text-white px-3.5 py-1.5 flex flex-wrap items-center justify-between text-[11px] font-mono tracking-wide">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-slate-200">
              CYBER TELEMETRY & FORENSIC LEDGER COMMAND
            </span>
          </div>
          <div className="flex items-center gap-4 text-slate-300">
            <span>{currentTimeIST}</span>
            <span className="text-slate-500">|</span>
            <span>{currentTimeUTC}</span>
            <span className="text-slate-500">|</span>
            <span className="text-emerald-400 font-semibold flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              AIR-GAP ENCLAVE ACTIVE
            </span>
          </div>
        </div>

        {/* Operational Scope Declarations */}
        <div className="p-3.5 flex flex-col lg:flex-row lg:items-center justify-between gap-3 bg-surface-alt border-b border-border-light">
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-bold text-navy-900 uppercase tracking-wide">
                Cyber Command & Blockchain Telemetry Operations
              </h1>
            </div>
            <p className="text-xs text-slate-600 mt-1 max-w-4xl leading-relaxed">
              Real-time telemetry ingestion, schema-governed canonical normalization (UCE v1.0), zero-leak privacy sanitization, and 13-stage cryptographic evidence anchoring in compliance with enterprise digital forensics mandates.
            </p>
          </div>
        </div>

        {/* 6-Factor Telemetry & Defense KPI Matrix */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 divide-y sm:divide-y-0 sm:divide-x divide-border-light bg-white">
          <div className="p-3 bg-slate-50/50">
            <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">
              Intake Velocity
            </span>
            <div className="text-lg font-bold font-mono text-gov-blue mt-0.5">{liveEps.toLocaleString()} EPS</div>
            <span className="text-[11px] text-slate-500 block mt-0.5">~18 MB/s · Ingest Active <span className="inline-block w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse ml-1" /></span>
          </div>

          <NavLink to="/parsers" className="p-3 hover:bg-slate-50 transition-colors group block">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block group-hover:text-gov-blue">
                Parser Health
              </span>
              <ArrowRight className="w-2.5 h-2.5 text-slate-300 group-hover:text-gov-blue group-hover:translate-x-0.5 transition-all" />
            </div>
            <div className="text-lg font-bold font-mono text-green-700 mt-0.5">20 / 20 Valid</div>
            <span className="text-[11px] text-slate-500 block mt-0.5">100% Tier A/B/C Ready →</span>
          </NavLink>

          <NavLink to="/data-privacy" className="p-3 hover:bg-slate-50 transition-colors group block">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block group-hover:text-gov-blue">
                Privacy Shield
              </span>
              <ArrowRight className="w-2.5 h-2.5 text-slate-300 group-hover:text-gov-blue group-hover:translate-x-0.5 transition-all" />
            </div>
            <div className="text-lg font-bold font-mono text-navy-900 mt-0.5">100% Scrubbed</div>
            <span className="text-[11px] text-slate-500 block mt-0.5">DPDP · Aadhaar Masked →</span>
          </NavLink>

          <NavLink to="/cost-optimizer" className="p-3 hover:bg-slate-50 transition-colors group block">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block group-hover:text-gov-blue">
                SIEM Ingestion Efficiency
              </span>
              <ArrowRight className="w-2.5 h-2.5 text-slate-300 group-hover:text-gov-blue group-hover:translate-x-0.5 transition-all" />
            </div>
            <div className="text-lg font-bold font-mono text-emerald-700 mt-0.5">54.0% Saved</div>
            <span className="text-[11px] text-slate-500 block mt-0.5">Noise Filtered at Ingest →</span>
          </NavLink>

          <NavLink to="/blockchain" className="p-3 hover:bg-slate-50 transition-colors group block">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block group-hover:text-gov-blue">
                Blockchain Ledger
              </span>
              <ArrowRight className="w-2.5 h-2.5 text-slate-300 group-hover:text-gov-blue group-hover:translate-x-0.5 transition-all" />
            </div>
            <div className="text-lg font-bold font-mono text-navy-900 mt-0.5">Block #48,294</div>
            <span className="text-[11px] text-slate-500 block mt-0.5">2,048 Logs/Block Anchored →</span>
          </NavLink>

          <NavLink to="/forensics" className="p-3 hover:bg-slate-50 transition-colors group block">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block group-hover:text-gov-blue">
                Evidence Lineage
              </span>
              <ArrowRight className="w-2.5 h-2.5 text-slate-300 group-hover:text-gov-blue group-hover:translate-x-0.5 transition-all" />
            </div>
            <div className="text-lg font-bold font-mono text-green-700 mt-0.5">Tamper-Free</div>
            <span className="text-[11px] text-slate-500 block mt-0.5">13-Stage Merkle Verified →</span>
          </NavLink>
        </div>
      </div>

      {/* Real-Time Telemetry Pipeline Flow (Preserved Institutional Architecture) */}
      <PipelineVisualization />

      {/* Permissioned Blockchain Chain-of-Custody & Consensus Cluster */}
      <div className="bg-white border border-border-medium rounded overflow-hidden shadow-2xs">
        <div className="px-4 py-2.5 bg-surface-alt border-b border-border-light flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Lock className="w-4 h-4 text-gov-blue" />
            <span className="text-xs font-bold text-navy-900 uppercase tracking-wider">
              Permissioned Blockchain — Immutable Cryptographic Ledger
            </span>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-[11px] text-slate-600 font-mono">
              Consensus: <strong>Proof-of-Authority (PoA)</strong> · Quorum: <strong className="text-green-700">4/4 Nodes Active</strong>
            </span>
            <NavLink
              to="/blockchain"
              className="text-[11px] font-semibold text-gov-blue hover:underline flex items-center gap-1"
            >
              Full Blockchain Explorer <ArrowRight className="w-3 h-3" />
            </NavLink>
          </div>
        </div>

        {/* Live Sealed Block Strip */}
        <div className="p-4 space-y-3">
          <div className="text-xs font-bold text-navy-900 uppercase tracking-wide flex items-center justify-between">
            <span>Recent Cryptographic Blocks Sealed On-Chain</span>
            <span className="text-[11px] font-normal font-mono text-slate-500">Hash Algorithm: SHA-256 (NIST FIPS 180-4)</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {SAMPLE_BLOCKS.map((block) => (
              <div
                key={block.blockHeight}
                className="p-3 bg-slate-50 border border-slate-200 rounded text-xs space-y-2 hover:border-gov-blue transition-colors"
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono font-bold text-navy-900 text-sm">
                    Block #{block.blockHeight.toLocaleString()}
                  </span>
                  <span className="inline-flex items-center gap-1 text-[10px] font-bold text-emerald-800 bg-emerald-50 px-1.5 py-0.5 rounded border border-emerald-200 uppercase">
                    <ShieldCheck className="w-3 h-3 text-emerald-600" />
                    {block.status}
                  </span>
                </div>

                <div className="space-y-1 font-mono text-[11px]">
                  <div className="text-slate-500 flex items-center justify-between">
                    <span>Block Hash:</span>
                    <button
                      onClick={() => handleCopy(block.blockHash, `block-${block.blockHeight}`)}
                      className="text-gov-blue hover:text-navy-900 flex items-center gap-1"
                      title="Copy SHA-256 Hash"
                    >
                      <span>{block.blockHash.substring(0, 10)}...{block.blockHash.substring(58)}</span>
                      {copiedHash === `block-${block.blockHeight}` ? (
                        <Check className="w-3 h-3 text-green-600" />
                      ) : (
                        <Copy className="w-3 h-3 text-slate-400" />
                      )}
                    </button>
                  </div>
                  <div className="text-slate-500 flex items-center justify-between">
                    <span>Merkle Root:</span>
                    <span className="text-slate-700">{block.merkleRoot.substring(0, 10)}...{block.merkleRoot.substring(58)}</span>
                  </div>
                  <div className="text-slate-500 flex items-center justify-between">
                    <span>Sealed Events:</span>
                    <span className="font-bold text-navy-900">{block.eventCount.toLocaleString()} UCE Records</span>
                  </div>
                </div>

                <div className="pt-2 border-t border-slate-200 text-[10.5px] text-slate-600 flex items-center justify-between">
                  <span>{block.validator}</span>
                  <span className="text-slate-400">{block.timestamp}</span>
                </div>
              </div>
            ))}
          </div>

          {/* 4-Node Consensus Grid */}
          <div className="mt-3 pt-3 border-t border-slate-200">
            <span className="text-[10.5px] font-bold text-slate-500 uppercase tracking-wider block mb-2">
              Consensus Node Cluster Verification Status
            </span>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              <div className="bg-slate-50 border border-slate-200 p-2 rounded text-[11px]">
                <div className="flex items-center justify-between font-semibold text-navy-900">
                  <span>Primary Cluster Node 01</span>
                  <span className="w-2 h-2 rounded-full bg-emerald-600" />
                </div>
                <div className="text-[10px] text-slate-500 font-mono mt-0.5">Proposer · Latency: 2ms</div>
              </div>

              <div className="bg-slate-50 border border-slate-200 p-2 rounded text-[11px]">
                <div className="flex items-center justify-between font-semibold text-navy-900">
                  <span>SecOps Sectoral Node</span>
                  <span className="w-2 h-2 rounded-full bg-emerald-600" />
                </div>
                <div className="text-[10px] text-slate-500 font-mono mt-0.5">Validator · Latency: 4ms</div>
              </div>

              <div className="bg-slate-50 border border-slate-200 p-2 rounded text-[11px]">
                <div className="flex items-center justify-between font-semibold text-navy-900">
                  <span>Enterprise Defense Node</span>
                  <span className="w-2 h-2 rounded-full bg-emerald-600" />
                </div>
                <div className="text-[10px] text-slate-500 font-mono mt-0.5">Witness · Latency: 5ms</div>
              </div>

              <div className="bg-slate-50 border border-slate-200 p-2 rounded text-[11px]">
                <div className="flex items-center justify-between font-semibold text-navy-900">
                  <span>Audit Forensic Vault</span>
                  <span className="w-2 h-2 rounded-full bg-emerald-600" />
                </div>
                <div className="text-[10px] text-slate-500 font-mono mt-0.5">WORM Archival · Latency: 3ms</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Active SIEM Incident & Threat Triage Table */}
      <div className="bg-white border border-border-medium rounded overflow-hidden shadow-2xs">
        <div className="px-4 py-2.5 bg-surface-alt border-b border-border-light flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center gap-2.5">
            <AlertTriangle className="w-4 h-4 text-amber-600" />
            <span className="text-xs font-bold text-navy-900 uppercase tracking-wider">
              Active Security Incidents & Threat Correlation Stream (SIEM Tier)
            </span>
            <span className="inline-flex items-center gap-1 text-[10px] font-bold font-mono text-red-800 bg-red-50 border border-red-200 px-2 py-0.5 rounded-full">
              <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" />
              {SAMPLE_INCIDENTS.length} DETECTED
            </span>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-[11px] text-slate-500 hidden md:inline">Sub-Millisecond MITRE ATT&CK & Sigma Evaluation</span>
            <NavLink
              to="/alerts"
              className="text-[11px] font-semibold text-gov-blue hover:underline flex items-center gap-1"
            >
              All Alerts <ArrowRight className="w-3 h-3" />
            </NavLink>
          </div>
        </div>

        {/* Incident search & severity filter bar */}
        <div className="px-4 py-2 border-b border-slate-100 bg-slate-50/80 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="relative w-full sm:w-80">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              value={incidentSearch}
              onChange={(e) => setIncidentSearch(e.target.value)}
              placeholder="Search by ID, MITRE tactic, entity..."
              className="w-full text-xs bg-white border border-slate-200 rounded pl-8 pr-3 py-1.5 text-slate-800 focus:outline-none focus:ring-1 focus:ring-gov-blue placeholder:text-slate-400"
            />
          </div>

          <div className="flex items-center gap-1.5 w-full sm:w-auto overflow-x-auto">
            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider mr-1">Severity:</span>
            {(['ALL', 'CRITICAL', 'HIGH', 'ELEVATED'] as const).map((sev) => {
              const count = sev === 'ALL' ? SAMPLE_INCIDENTS.length : SAMPLE_INCIDENTS.filter(i => i.severity === sev).length;
              const isActive = selectedSeverity === sev;
              return (
                <button
                  key={sev}
                  onClick={() => setSelectedSeverity(sev)}
                  className={`text-[10.5px] font-medium px-2 py-1 rounded transition-colors cursor-pointer whitespace-nowrap ${
                    isActive
                      ? sev === 'CRITICAL'
                        ? 'bg-red-600 text-white font-semibold'
                        : sev === 'HIGH'
                        ? 'bg-amber-600 text-white font-semibold'
                        : 'bg-navy-900 text-white font-semibold'
                      : 'bg-white text-slate-600 border border-slate-200 hover:bg-slate-100'
                  }`}
                >
                  {sev === 'ALL' ? 'All' : sev} ({count})
                </button>
              );
            })}

            <button
              onClick={handleRefreshIncidents}
              title="Refresh Incident Stream"
              className="ml-1 p-1.5 text-slate-500 hover:text-navy-900 bg-white border border-slate-200 rounded hover:bg-slate-100 transition-colors cursor-pointer shrink-0"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-gov-blue' : ''}`} />
            </button>
          </div>
        </div>

        <div>
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-border-light text-[10.5px] font-bold text-slate-500 uppercase bg-slate-50">
                <th className="py-2.5 px-3">Time (IST)</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Threat Description</th>
                <th className="py-2.5 px-3">MITRE ATT&CK</th>
                <th className="py-2.5 px-3">Source</th>
                <th className="py-2.5 px-3 text-right">Audit</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {filteredIncidents.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-400 text-xs">
                    No security incidents match the current filters.
                  </td>
                </tr>
              ) : (
                filteredIncidents.map((inc) => (
                <tr key={inc.id} className={`hover:bg-slate-50 transition-colors ${acknowledgedIds.has(inc.id) ? 'opacity-60' : ''}`}>
                  <td className="py-2 px-3 font-mono text-[11px] text-slate-600 whitespace-nowrap">
                    {inc.timestamp.replace('2026-09-20 ', '')}
                  </td>
                  <td className="py-2 px-3 whitespace-nowrap">
                    <span
                      className={`inline-block text-[10px] font-bold uppercase px-1.5 py-0.5 rounded border ${
                        inc.severity === 'CRITICAL'
                          ? 'bg-red-50 text-red-800 border-red-200'
                          : inc.severity === 'HIGH'
                          ? 'bg-amber-50 text-amber-800 border-amber-200'
                          : 'bg-blue-50 text-blue-800 border-blue-200'
                      }`}
                    >
                      {inc.severity}
                    </span>
                  </td>
                  <td className="py-2 px-3">
                    <div className="font-medium text-slate-800 text-xs" title={inc.summary}>
                      {inc.summary}
                    </div>
                    <div className="text-[10px] font-mono text-slate-500 mt-0.5">
                      {inc.id} · {inc.entity}
                    </div>
                  </td>
                  <td className="py-2 px-3 whitespace-nowrap">
                    <span className="font-mono text-[10.5px] font-semibold text-gov-blue">{inc.mitreId}</span>
                    <span className="block text-[10px] text-slate-500">{inc.mitreTactic}</span>
                  </td>
                  <td className="py-2 px-3 whitespace-nowrap text-slate-700 font-medium text-[11px]">
                    {inc.source}
                  </td>
                  <td className="py-2 px-3 text-right whitespace-nowrap">
                    <div className="flex items-center gap-1.5 justify-end">
                      {!acknowledgedIds.has(inc.id) && (
                        <button
                          onClick={() => handleAcknowledge(inc.id)}
                          className="inline-flex items-center gap-1 text-[10.5px] font-semibold text-emerald-700 bg-emerald-50 px-2 py-1 rounded border border-emerald-200 hover:bg-emerald-100 transition-colors cursor-pointer"
                        >
                          <CheckCircle2 className="w-3 h-3" />
                          Ack
                        </button>
                      )}
                      {acknowledgedIds.has(inc.id) && (
                        <span className="text-[10px] text-emerald-700 font-semibold">✓ Acknowledged</span>
                      )}
                      <button
                        onClick={() => setSelectedIncident(inc)}
                        className="inline-flex items-center gap-1 text-[10.5px] font-semibold text-gov-blue bg-gov-light px-2 py-1 rounded border border-gov-border hover:bg-slate-100 transition-colors cursor-pointer"
                      >
                        <FileCheck className="w-3 h-3" />
                        Forensic Cert
                      </button>
                    </div>
                  </td>
                </tr>
              )))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Multi-Destination SIEM Dispatch & Downstream Egress Monitor */}
      <div className="bg-white border border-border-medium rounded overflow-hidden shadow-2xs">
        <div className="px-4 py-2.5 bg-surface-alt border-b border-border-light flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Share2 className="w-4 h-4 text-gov-blue" />
            <span className="text-xs font-bold text-navy-900 uppercase tracking-wider">
              Simultaneous Multi-Destination SIEM & Intelligence Egress
            </span>
          </div>
          <span className="text-[11px] font-mono text-slate-500">Universal Dispatcher v1.0.0</span>
        </div>

        <div className="p-3.5 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
          <div className="border border-slate-200 rounded p-3 bg-slate-50 space-y-1.5">
            <div className="flex items-center justify-between font-bold text-navy-900">
              <span>Splunk Enterprise SIEM</span>
              <span className="text-green-700 text-[10.5px]">CONNECTED</span>
            </div>
            <div className="text-slate-600 text-[11px]">Format: <strong>OCSF 1.1 JSON (HEC)</strong></div>
            <div className="text-slate-500 font-mono text-[10.5px]">14,850 EPS · Latency: 3.8ms</div>
            <div className="w-full bg-slate-200 h-1.5 rounded-full overflow-hidden">
              <div className="bg-green-600 h-full w-[100%]" />
            </div>
          </div>

          <div className="border border-slate-200 rounded p-3 bg-slate-50 space-y-1.5">
            <div className="flex items-center justify-between font-bold text-navy-900">
              <span>Threat Intelligence Vault</span>
              <span className="text-green-700 text-[10.5px]">CONNECTED</span>
            </div>
            <div className="text-slate-600 text-[11px]">Format: <strong>STIX 2.1 / TAXII Feed</strong></div>
            <div className="text-slate-500 font-mono text-[10.5px]">Continuous Ingestion · Real-time</div>
            <div className="w-full bg-slate-200 h-1.5 rounded-full overflow-hidden">
              <div className="bg-green-600 h-full w-[100%]" />
            </div>
          </div>

          <div className="border border-slate-200 rounded p-3 bg-slate-50 space-y-1.5">
            <div className="flex items-center justify-between font-bold text-navy-900">
              <span>Elasticsearch SIEM Cluster</span>
              <span className="text-green-700 text-[10.5px]">CONNECTED</span>
            </div>
            <div className="text-slate-600 text-[11px]">Format: <strong>Elastic Common Schema (ECS)</strong></div>
            <div className="text-slate-500 font-mono text-[10.5px]">Bulk Indexing · Latency: 4.1ms</div>
            <div className="w-full bg-slate-200 h-1.5 rounded-full overflow-hidden">
              <div className="bg-green-600 h-full w-[100%]" />
            </div>
          </div>

          <div className="border border-slate-200 rounded p-3 bg-slate-50 space-y-1.5">
            <div className="flex items-center justify-between font-bold text-navy-900">
              <span>Forensic Cold Vault (CAS WORM)</span>
              <span className="text-green-700 text-[10.5px]">LOCKED</span>
            </div>
            <div className="text-slate-600 text-[11px]">Format: <strong>Raw Gzip + Merkle Root</strong></div>
            <div className="text-slate-500 font-mono text-[10.5px]">180-Day Regulatory Retention</div>
            <div className="w-full bg-slate-200 h-1.5 rounded-full overflow-hidden">
              <div className="bg-green-600 h-full w-[100%]" />
            </div>
          </div>
        </div>
      </div>

      {/* Structured Operational Tables Grid (Telemetry Sources Inventory) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Source Status Table */}
        <div className="lg:col-span-8 bg-white border border-border-medium rounded overflow-hidden shadow-2xs">
          <div className="px-4 py-2.5 bg-surface-alt border-b border-border-light flex items-center justify-between">
            <span className="text-xs font-bold text-navy-900 uppercase tracking-wider">
              Configured Telemetry Sources (Tier A, B, C Inventory)
            </span>
            <NavLink
              to="/parsers"
              className="text-[11px] font-semibold text-gov-blue hover:underline flex items-center gap-1"
            >
              Full Parser Registry <ArrowRight className="w-3 h-3" />
            </NavLink>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-border-light text-[10.5px] font-bold text-slate-500 uppercase bg-slate-50">
                  <th className="py-2 px-3">Source Name</th>
                  <th className="py-2 px-3">Vendor</th>
                  <th className="py-2 px-3">Category</th>
                  <th className="py-2 px-3">Format</th>
                  <th className="py-2 px-3 text-right">Ingestion Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {PARSERS_DATA.slice(0, 7).map((p) => (
                  <tr key={p.id} className="hover:bg-slate-50 transition-colors">
                    <td className="py-2 px-3 font-semibold text-navy-900">{p.name}</td>
                    <td className="py-2 px-3 text-slate-600">{p.vendor}</td>
                    <td className="py-2 px-3 text-slate-500">{p.category}</td>
                    <td className="py-2 px-3 font-mono text-[10.5px] text-slate-600">{p.format}</td>
                    <td className="py-2 px-3 text-right">
                      <span className="inline-flex items-center gap-1 text-[10.5px] font-semibold text-green-800 bg-green-50 px-1.5 py-0.5 rounded border border-green-200">
                        <CheckCircle2 className="w-3 h-3 text-green-600" />
                        Operational
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* System Infrastructure & Forensic Lineage Panel */}
        <div className="lg:col-span-4 bg-white border border-border-medium rounded overflow-hidden shadow-2xs flex flex-col justify-between">
          <div className="px-4 py-2.5 bg-surface-alt border-b border-border-light">
            <span className="text-xs font-bold text-navy-900 uppercase tracking-wider">
              Cryptographic Storage & Lineage Specifications
            </span>
          </div>
          <div className="p-3.5 space-y-3 text-xs flex-1">
            <div className="space-y-1">
              <span className="text-[10px] text-slate-400 font-bold uppercase block">
                Content-Addressed Storage (CAS)
              </span>
              <div className="font-mono text-[11px] text-slate-700 bg-slate-50 p-2 rounded border border-slate-200">
                Root: <strong className="text-navy-900">cas/immutable_store/sha256/</strong>
                <span className="block text-[10px] text-slate-500 mt-0.5">WORM Write-Once-Read-Many Storage</span>
              </div>
            </div>

            <div className="space-y-1">
              <span className="text-[10px] text-slate-400 font-bold uppercase block">
                Normalization Standard
              </span>
              <div className="text-[11px] text-slate-700 font-medium">
                Universal Canonical Event (UCE) Specification v1.0.0
              </div>
              <span className="text-[10.5px] text-slate-500 block">
                Enforces ISO 8601 UTC, strict typed actors, client devices, and standardized outcomes.
              </span>
            </div>

            <div className="space-y-1">
              <span className="text-[10px] text-slate-400 font-bold uppercase block">
                Interoperability Projections
              </span>
              <div className="text-[11px] text-slate-700 space-y-0.5 font-mono text-[10.5px]">
                <div>• OCSF v1.1.0 (Class 4001: Network Security)</div>
                <div>• OpenTelemetry Logs v1.0.0 (ResourceLogs)</div>
                <div>• MITRE ATT&CK Enterprise v14.1 Mapping</div>
              </div>
            </div>

            <div className="pt-2 border-t border-slate-100">
              <NavLink
                to="/forensics"
                className="w-full text-center block text-xs font-semibold py-2 rounded bg-gov-light text-gov-blue hover:bg-slate-100 border border-gov-border transition-colors shadow-2xs"
              >
                Inspect 13-Stage Merkle Lineage Chain
              </NavLink>
            </div>
          </div>
        </div>
      </div>

      {/* ── India Regulatory Compliance + MITRE ATT&CK Overview Strip ─────── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* India Compliance Snapshot */}
        <div className="bg-white border border-border-medium rounded overflow-hidden shadow-2xs">
          <div className="px-4 py-2.5 bg-blue-700 text-white flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="text-sm">🇮🇳</span>
              <span className="text-xs font-bold uppercase tracking-wider">India Regulatory Compliance</span>
            </div>
            <NavLink to="/india-compliance" className="text-[11px] font-semibold text-blue-200 hover:text-white flex items-center gap-1">
              Full Dashboard <ArrowRight className="w-3 h-3" />
            </NavLink>
          </div>
          <div className="p-3.5 grid grid-cols-3 gap-2 text-xs">
            {[
              { label: 'CERT-In 2022',    icon: '🛡️', detail: '4/5 controls · 180d retention', color: 'border-blue-200 bg-blue-50 text-blue-900' },
              { label: 'DPDP Act 2023',   icon: '🔒', detail: '3/4 controls · 100% PII masked', color: 'border-purple-200 bg-purple-50 text-purple-900' },
              { label: 'ISO 27001:2022',  icon: '📋', detail: '3/3 controls · Chain sealed',    color: 'border-slate-200 bg-slate-50 text-slate-700' },
            ].map((item) => (
              <div key={item.label} className={`border rounded p-2.5 space-y-1 ${item.color}`}>
                <div className="flex items-center gap-1 font-bold text-[10.5px]">{item.icon} {item.label}</div>
                <div className="text-[10px] font-bold text-green-700">✓ COMPLIANT</div>
                <div className="text-[10px] text-slate-500 leading-tight">{item.detail}</div>
              </div>
            ))}
          </div>
          <div className="px-3.5 pb-3 flex items-center gap-2 text-[11px] border-t border-slate-100 pt-2.5">
            <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse shrink-0" />
            <span className="font-semibold text-red-700">INC-2026-9812 · CERT-In 6h SLA — {formatSla(slaSeconds)} remaining</span>
            <NavLink to="/india-compliance" className="ml-auto text-gov-blue font-semibold hover:underline shrink-0">View SLA →</NavLink>
          </div>
        </div>

        {/* ATT&CK Coverage Snapshot */}
        <div className="bg-white border border-border-medium rounded overflow-hidden shadow-2xs">
          <div className="px-4 py-2.5 bg-red-700 text-white flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Layers className="w-4 h-4" />
              <span className="text-xs font-bold uppercase tracking-wider">MITRE ATT&amp;CK® Coverage</span>
            </div>
            <NavLink to="/mitre-attack" className="text-[11px] font-semibold text-red-200 hover:text-white flex items-center gap-1">
              Full Matrix <ArrowRight className="w-3 h-3" />
            </NavLink>
          </div>
          <div className="p-3.5 grid grid-cols-3 gap-2 text-xs">
            {[
              { label: 'Techniques Detected', value: '22', sub: 'Active rule fires',  color: 'text-emerald-700', bg: 'bg-emerald-50 border-emerald-200' },
              { label: 'Under Monitoring',     value: '17', sub: 'Telemetry ingested', color: 'text-blue-700',    bg: 'bg-blue-50 border-blue-200' },
              { label: 'Coverage Rate',        value: '73%', sub: '14 ATT&CK Tactics', color: 'text-navy-900',   bg: 'bg-white border-slate-200' },
            ].map((kpi) => (
              <div key={kpi.label} className={`border rounded p-2.5 space-y-0.5 ${kpi.bg}`}>
                <div className={`text-xl font-bold font-mono ${kpi.color}`}>{kpi.value}</div>
                <div className="font-semibold text-navy-900 text-[10.5px]">{kpi.label}</div>
                <div className="text-[10px] text-slate-500">{kpi.sub}</div>
              </div>
            ))}
          </div>
          <div className="px-3.5 pb-3 border-t border-slate-100 pt-2.5">
            <div className="flex justify-between text-[10.5px] text-slate-500 mb-1.5">
              <span>Enterprise v14.1 · Sovereign SOC detection coverage</span>
              <span className="font-mono font-bold text-emerald-700">73%</span>
            </div>
            <div className="w-full bg-slate-100 rounded-full h-2">
              <div className="bg-gradient-to-r from-emerald-500 to-green-400 h-2 rounded-full" style={{ width: '73%' }} />
            </div>
          </div>
        </div>
      </div>

      {/* Interactive Section Evidence Certificate Modal */}

      {selectedIncident && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-navy-900/60 backdrop-blur-xs p-4 overflow-y-auto">
          <div className="bg-white border-2 border-navy-900 rounded-lg max-w-2xl w-full shadow-2xl overflow-hidden my-8">
            {/* Certificate Header */}
            <div className="bg-navy-900 text-white px-5 py-3.5 flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <FileCheck className="w-5 h-5 text-amber-400" />
                <div>
                  <h3 className="text-sm font-bold uppercase tracking-wider">
                    Forensic Evidence Certificate
                  </h3>
                  <span className="text-[10px] font-mono text-slate-300">
                    Cryptographic Chain of Custody & Tamper-Evident Mandate
                  </span>
                </div>
              </div>
              <button
                onClick={() => setSelectedIncident(null)}
                className="text-slate-300 hover:text-white p-1 rounded transition-colors cursor-pointer"
                title="Close"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Certificate Body */}
            <div className="p-5 space-y-4 text-xs">
              <div className="border-b border-slate-200 pb-3">
                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">
                  Incident Reference & Asset Target
                </span>
                <div className="flex items-center justify-between mt-1">
                  <span className="text-base font-bold font-mono text-navy-900">{selectedIncident.id}</span>
                  <span className="bg-red-50 text-red-800 font-bold px-2 py-0.5 rounded border border-red-200 font-mono text-[10.5px]">
                    {selectedIncident.severity}
                  </span>
                </div>
                <div className="text-slate-600 mt-1 font-medium">{selectedIncident.summary}</div>
                <div className="text-slate-500 font-mono text-[11px] mt-0.5">Entity: {selectedIncident.entity}</div>
              </div>

              {/* Cryptographic Chain of Custody */}
              <div className="space-y-3 bg-slate-50 p-3.5 rounded border border-slate-200 font-mono text-[11px]">
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-slate-500 text-[10px] uppercase font-bold tracking-wide">
                      1. Raw Telemetry Payload SHA-256:
                    </span>
                    <button
                      onClick={() => handleCopy(selectedIncident.rawHash, 'modal-raw')}
                      className="inline-flex items-center gap-1 text-[10.5px] font-sans font-medium text-gov-blue hover:text-navy-900 transition-colors cursor-pointer"
                      title="Copy Raw Hash"
                    >
                      {copiedHash === 'modal-raw' ? (
                        <>
                          <Check className="w-3 h-3 text-green-600" />
                          <span className="text-green-600 font-bold">Copied!</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3 h-3 text-slate-400" />
                          <span>Copy Hash</span>
                        </>
                      )}
                    </button>
                  </div>
                  <div className="bg-white p-2 rounded border border-slate-200 text-navy-900 break-all select-all font-mono text-[10.5px]">
                    {selectedIncident.rawHash}
                  </div>
                </div>

                <div className="pt-2 border-t border-slate-200">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-slate-500 text-[10px] uppercase font-bold tracking-wide">
                      2. Normalized UCE Payload SHA-256:
                    </span>
                    <button
                      onClick={() => handleCopy(selectedIncident.uceHash, 'modal-uce')}
                      className="inline-flex items-center gap-1 text-[10.5px] font-sans font-medium text-gov-blue hover:text-navy-900 transition-colors cursor-pointer"
                      title="Copy UCE Hash"
                    >
                      {copiedHash === 'modal-uce' ? (
                        <>
                          <Check className="w-3 h-3 text-green-600" />
                          <span className="text-green-600 font-bold">Copied!</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3 h-3 text-slate-400" />
                          <span>Copy Hash</span>
                        </>
                      )}
                    </button>
                  </div>
                  <div className="bg-white p-2 rounded border border-slate-200 text-navy-900 break-all select-all font-mono text-[10.5px]">
                    {selectedIncident.uceHash}
                  </div>
                </div>

                <div className="pt-2 border-t border-slate-200 flex items-center justify-between">
                  <div>
                    <span className="text-slate-500 text-[10px] uppercase font-bold">3. Anchored Block Height:</span>
                    <div className="font-bold text-gov-blue text-xs">Block #{selectedIncident.blockHeight.toLocaleString()}</div>
                  </div>
                  <div>
                    <span className="text-slate-500 text-[10px] uppercase font-bold">Consensus Status:</span>
                    <div className="text-emerald-700 font-bold text-xs">CONFIRMED (4/4 NODES)</div>
                  </div>
                </div>
              </div>

              {/* Certificate Statement of Integrity */}
              <div className="bg-gov-light border border-gov-border p-3 rounded text-[11px] text-slate-700 leading-relaxed">
                <div className="flex items-center justify-between mb-1">
                  <strong className="text-gov-blue font-semibold">
                    Certification of Cryptographic Integrity:
                  </strong>
                  <span className="bg-emerald-100 text-emerald-800 text-[9.5px] font-bold px-1.5 py-0.5 rounded border border-emerald-300 uppercase">
                    §65B IEA / §63 BSA Admissible
                  </span>
                </div>
                This electronic record was ingested, sanitized, and normalized by the Universal Log Preprocessing Framework operating in high-integrity mode. The cryptographic hash was sealed on the institutional blockchain ledger at {selectedIncident.timestamp} without manual alteration or data loss. Certified under Section 65B of the Indian Evidence Act, 1872 / Section 63 Bharatiya Sakshya Adhiniyam (BSA), 2023 for judicial admissibility.
              </div>

              {/* Modal Actions */}
              <div className="flex items-center justify-between pt-2 border-t border-slate-200">
                <span className="text-[10px] font-mono text-slate-400">Authority: ULPF_CYBER_FORENSIC_KEY_01</span>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => exportForensicCertificate(selectedIncident)}
                    disabled={isExporting}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-gov-blue text-white rounded font-semibold text-xs hover:bg-gov-blue-dark transition-colors shadow-2xs cursor-pointer disabled:opacity-75"
                  >
                    {isExporting ? (
                      <>
                        <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                        Generating PDF...
                      </>
                    ) : (
                      <>
                        <Download className="w-3.5 h-3.5" />
                        Export Forensic Certificate (PDF)
                      </>
                    )}
                  </button>
                  <button
                    onClick={() => setSelectedIncident(null)}
                    className="px-3 py-1.5 border border-slate-300 text-slate-700 rounded font-semibold text-xs hover:bg-slate-100 transition-colors cursor-pointer"
                  >
                    Close
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
