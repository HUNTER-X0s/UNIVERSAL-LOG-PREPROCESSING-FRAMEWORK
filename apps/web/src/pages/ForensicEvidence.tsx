import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { LineageTimeline } from '../components/forensic/LineageTimeline';
import { Section65BCertificate } from '../components/forensic/Section65BCertificate';
import { Card } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import {
  ShieldCheck,
  HardDrive,
  FileLock2,
  Scale,
  FileText,
  Clock,
  QrCode,
  Download,
  AlertTriangle,
  Server,
  Activity,
  Layers,
  Sparkles,
} from 'lucide-react';

const SAMPLE_INCIDENTS = [
  {
    id: 'INC-2026-NTRO-88192',
    title: 'Multi-Stage Lateral Movement Campaign',
    source: 'Cisco ASA + pfSense (IP: 198.51.100.99)',
    target: 'Domain Controller WIN-DC01 (10.0.1.50)',
    hash: '3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c',
    blockIndex: 1,
    merkleRoot: '70860df3cc8060cbf30aaa94f441d89cbfb9ecb98b0eaf38acc54470e2c566eb',
    poaSig: 'e698193cfa4a85d6370a5dbb328b6197d51b5e89e8d4afb07218fff97b94dc7e',
    timestamp: '2026-09-17 01:30:00 IST (NPL Synced)',
  },
  {
    id: 'INC-2026-NTRO-88191',
    title: 'Distributed Credential Stuffing & MFA Bypass',
    source: 'Okta Identity Provider + Nginx Access (IP: 203.0.113.88)',
    target: 'Authentication Gateway /auth/v1/token',
    hash: '6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f',
    blockIndex: 1,
    merkleRoot: '70860df3cc8060cbf30aaa94f441d89cbfb9ecb98b0eaf38acc54470e2c566eb',
    poaSig: 'e698193cfa4a85d6370a5dbb328b6197d51b5e89e8d4afb07218fff97b94dc7e',
    timestamp: '2026-09-17 01:30:04 IST (NPL Synced)',
  },
  {
    id: 'INC-2026-NTRO-88190',
    title: 'Suspicious Base64 Encoded PowerShell Execution',
    source: 'Sysmon EventID 1 (Host: WIN-DC01)',
    target: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    hash: '8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a',
    blockIndex: 2,
    merkleRoot: 'f1e2d3c4b5a6978869504132231445566778899aabbccddeeff00112233445566',
    poaSig: 'a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890',
    timestamp: '2026-09-17 01:31:12 IST (NPL Synced)',
  },
];

export const ForensicEvidence: React.FC = () => {
  const [searchParams] = useSearchParams();
  const eventIdParam = searchParams.get('eventId') || searchParams.get('incidentId');

  const [activeTab, setActiveTab] = useState<'lineage' | 'section65b'>('section65b');
  const [selectedIncident, setSelectedIncident] = useState(SAMPLE_INCIDENTS[0]);
  const [activeEventNotice, setActiveEventNotice] = useState<string | null>(null);

  // Sync with incoming eventId / incidentId from Live Logs or Command Center
  useEffect(() => {
    if (!eventIdParam) return;

    // Check if matches sample incidents
    const match = SAMPLE_INCIDENTS.find((i) => i.id === eventIdParam);
    if (match) {
      setSelectedIncident(match);
      setActiveEventNotice(match.id);
      return;
    }

    // Try looking up from simulated events storage or initial telemetry
    try {
      const stored = localStorage.getItem('ulpf_simulated_events');
      let foundEvent: any = null;
      if (stored) {
        const list = JSON.parse(stored);
        if (Array.isArray(list)) {
          foundEvent = list.find((e: any) => e.event_id === eventIdParam);
        }
      }

      if (foundEvent) {
        const synthetic = {
          id: foundEvent.event_id,
          title: `Cryptographic Telemetry Audit: ${foundEvent.vendor || 'Universal'} ${foundEvent.format || 'Log'}`,
          source: `${foundEvent.vendor || 'Unknown'} (${foundEvent.format || 'Standard'})`,
          target: foundEvent.source || 'ULPF Ingest Plane',
          hash: foundEvent.sha256 || '3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c',
          blockIndex: 48294,
          merkleRoot: '70860df3cc8060cbf30aaa94f441d89cbfb9ecb98b0eaf38acc54470e2c566eb',
          poaSig: 'e698193cfa4a85d6370a5dbb328b6197d51b5e89e8d4afb07218fff97b94dc7e',
          timestamp: `${foundEvent.timestamp || new Date().toISOString()} (NPL Synced)`,
        };
        setSelectedIncident(synthetic);
        setActiveEventNotice(foundEvent.event_id);
      }
    } catch {}
  }, [eventIdParam]);

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-border-light print:hidden">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-bold text-navy-900 tracking-tight">
              Forensic Evidence & Judicial Admissibility
            </h2>
            <Badge variant="ok" dot>
              PROVENANCE: 13/13 STAGES BOUND
            </Badge>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Cryptographic Content-Addressed Storage (CAS), Merkle DAG lineage, and statutory Section 65B evidence certification under Indian law.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Badge variant="info">CERT-In 2022 COMPLIANT</Badge>
          <Badge variant="neutral">NPL-IST NTP SYNCHRONIZED</Badge>
        </div>
      </div>

      {/* Active Event Forensics Banner */}
      {activeEventNotice && (
        <div className="bg-blue-50 border border-blue-200 rounded p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs text-navy-900 shadow-2xs print:hidden">
          <div className="flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-gov-blue shrink-0 animate-pulse" />
            <span>
              Connected Cross-Feature View: Generating Section 65B Certificate for Telemetry Event{' '}
              <strong className="font-mono bg-blue-100 text-blue-900 px-1.5 py-0.5 rounded border border-blue-300">
                {activeEventNotice}
              </strong>{' '}
              (Transferred from Live Logs / Command Center)
            </span>
          </div>
          <button
            onClick={() => {
              setActiveEventNotice(null);
              setSelectedIncident(SAMPLE_INCIDENTS[0]);
            }}
            className="text-[11px] font-semibold text-gov-blue hover:text-navy-900 hover:underline cursor-pointer self-end sm:self-auto shrink-0"
          >
            ← Reset to Sample Incidents
          </button>
        </div>
      )}

      {/* Navigation Tabs */}
      <div className="flex items-center gap-1 border-b border-border-light bg-white p-1 rounded-t border-t border-l border-r print:hidden">
        <button
          type="button"
          onClick={() => setActiveTab('section65b')}
          className={`flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold rounded transition-colors ${
            activeTab === 'section65b'
              ? 'bg-gov-blue text-white shadow-xs'
              : 'text-slate-600 hover:text-navy-900 hover:bg-slate-100'
          }`}
        >
          <Scale className="w-3.5 h-3.5" />
          <span>Section 65B Forensic Certificate</span>
        </button>
        <button
          type="button"
          onClick={() => setActiveTab('lineage')}
          className={`flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold rounded transition-colors ${
            activeTab === 'lineage'
              ? 'bg-gov-blue text-white shadow-xs'
              : 'text-slate-600 hover:text-navy-900 hover:bg-slate-100'
          }`}
        >
          <Layers className="w-3.5 h-3.5" />
          <span>13-Stage Merkle DAG Lineage</span>
        </button>
      </div>

      {/* Tab 1: Section 65B Indian Evidence Act Certificate */}
      {activeTab === 'section65b' && (
        <div className="space-y-5 print:space-y-0">
          {/* CERT-In Compliance Meter & Quick Select */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 print:hidden">
            <Card
              title="CERT-In 2022 Compliance Meter"
              subtitle="Statutory compliance under Ministry of Electronics & IT Directive No. 20(3)/2022"
              className="lg:col-span-1"
            >
              <div className="space-y-3 text-xs">
                <div className="flex items-center justify-between pb-2 border-b border-slate-100">
                  <span className="text-slate-600">180-Day Log Retention:</span>
                  <Badge variant="ok">100% COMPLIANT</Badge>
                </div>
                <div className="flex items-center justify-between pb-2 border-b border-slate-100">
                  <span className="text-slate-600">NTP Sync (NPL-CSIR):</span>
                  <Badge variant="ok">±50µs ACCURACY</Badge>
                </div>
                <div className="flex items-center justify-between pb-2 border-b border-slate-100">
                  <span className="text-slate-600">Sovereign Data Residency:</span>
                  <Badge variant="ok">INDIA (AIR-GAP)</Badge>
                </div>
                <div className="flex items-center justify-between pb-2 border-b border-slate-100">
                  <span className="text-slate-600">Cryptographic Non-Repudiation:</span>
                  <Badge variant="ok">PoA BLOCKCHAIN</Badge>
                </div>
                <div className="pt-1 text-[11px] text-slate-500 italic">
                  All electronic records satisfy legal mandates under Section 70B(6) of the IT Act, 2000.
                </div>
              </div>
            </Card>

            <Card
              title="Select Forensic Evidence Incident"
              subtitle="Choose correlated attack evidence to generate statutory court certificate"
              className="lg:col-span-2"
            >
              <div className="space-y-2">
                {SAMPLE_INCIDENTS.map((inc) => (
                  <div
                    key={inc.id}
                    role="button"
                    tabIndex={0}
                    onClick={() => setSelectedIncident(inc)}
                    onKeyDown={(e) => e.key === 'Enter' && setSelectedIncident(inc)}
                    className={`p-2.5 rounded border text-xs cursor-pointer transition-all flex items-center justify-between gap-3 ${
                      selectedIncident.id === inc.id
                        ? 'bg-blue-50/50 border-gov-blue ring-1 ring-gov-blue/20'
                        : 'bg-white border-slate-200 hover:border-slate-300'
                    }`}
                  >
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 mb-0.5">
                        <span className="font-mono font-bold text-gov-blue">{inc.id}</span>
                        <span className="font-semibold text-navy-900 truncate">{inc.title}</span>
                      </div>
                      <div className="text-[11px] text-slate-500 truncate">
                        Source: {inc.source} → Target: {inc.target}
                      </div>
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0">
                      <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200">
                        Block #{inc.blockIndex}
                      </span>
                      {selectedIncident.id === inc.id ? (
                        <span className="text-[10px] font-bold text-gov-blue uppercase">Selected</span>
                      ) : (
                        <span className="text-[10px] text-slate-400">Click to load</span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          </div>

          {/* Render Formal Certificate */}
          <Section65BCertificate
            incidentId={selectedIncident.id}
            incidentTitle={selectedIncident.title}
            sourceDevice={selectedIncident.source}
            targetEntity={selectedIncident.target}
            rawPayloadHash={selectedIncident.hash}
            blockchainBlockHash="7ad87e111a17c372a993a7a4d2559ee6ff72372eb6505eee237bd54975de1c84"
            blockIndex={selectedIncident.blockIndex}
            merkleRoot={selectedIncident.merkleRoot}
            poaSignature={selectedIncident.poaSig}
            timestampIst={selectedIncident.timestamp}
          />
        </div>
      )}

      {/* Tab 2: 13-Stage Lineage Timeline */}
      {activeTab === 'lineage' && (
        <div className="space-y-5 print:hidden">
          {/* 13-Stage Lineage Timeline with interactive tamper detector */}
          <LineageTimeline />

          {/* Judicial Admissibility & Cryptographic Anchors */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-white p-4 rounded border border-border-light shadow-xs space-y-1.5 text-xs">
              <div className="font-bold text-navy-900 flex items-center gap-1.5">
                <Scale className="w-4 h-4 text-gov-blue" />
                Judicial Defensibility
              </div>
              <p className="text-slate-600 text-[11px] leading-relaxed">
                Every log maintains an unbroken chain of custody. The raw payload hash is embedded inside every derived UCE, OCSF, and detection artifact.
              </p>
            </div>

            <div className="bg-white p-4 rounded border border-border-light shadow-xs space-y-1.5 text-xs">
              <div className="font-bold text-navy-900 flex items-center gap-1.5">
                <HardDrive className="w-4 h-4 text-gov-blue" />
                Content-Addressed Storage
              </div>
              <p className="text-slate-600 text-[11px] leading-relaxed">
                Raw logs are stored immutably in a content-addressed directory structure. Files are write-once; in-place overwrites are rejected by the underlying filesystem layer.
              </p>
            </div>

            <div className="bg-white p-4 rounded border border-border-light shadow-xs space-y-1.5 text-xs">
              <div className="font-bold text-navy-900 flex items-center gap-1.5">
                <FileLock2 className="w-4 h-4 text-gov-blue" />
                Instant Tamper Detection
              </div>
              <p className="text-slate-600 text-[11px] leading-relaxed">
                Any modification of even a single byte anywhere in the pipeline invalidates the Merkle root digest, instantly triggering a critical security alert.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
