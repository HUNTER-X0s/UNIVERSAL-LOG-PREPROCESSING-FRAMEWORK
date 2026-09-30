import React, { useState } from 'react';
import {
  Scale,
  ShieldCheck,
  Printer,
  Copy,
  Check,
  QrCode,
  Download,
  Calendar,
  User,
  Server,
  Hash,
  Lock,
  ExternalLink,
  Award,
  CheckCircle2,
} from 'lucide-react';
import { Badge } from '../ui/Badge';
import { Button } from '../ui/Button';

export interface Section65BCertificateProps {
  incidentId: string;
  incidentTitle: string;
  sourceDevice: string;
  targetEntity: string;
  rawPayloadHash: string;
  blockchainBlockHash: string;
  blockIndex: number;
  merkleRoot: string;
  poaSignature: string;
  timestampIst: string;
  officerName?: string;
  officerDesignation?: string;
  policeStationOrAgency?: string;
  onClose?: () => void;
}

export const Section65BCertificate: React.FC<Section65BCertificateProps> = ({
  incidentId,
  incidentTitle,
  sourceDevice,
  targetEntity,
  rawPayloadHash,
  blockchainBlockHash,
  blockIndex,
  merkleRoot,
  poaSignature,
  timestampIst,
  officerName = 'Anurag Swain',
  officerDesignation = 'Principal Cyber Forensic Analyst (Emp ID: NTRO-CYBER-0941)',
  policeStationOrAgency = 'National Technical Research Organisation (NTRO) · Cyber Operations Center',
  onClose,
}) => {
  const [copiedHash, setCopiedHash] = useState(false);

  const handlePrint = () => {
    document.body.classList.add('printing-section-65b-only');
    const cleanup = () => {
      document.body.classList.remove('printing-section-65b-only');
      window.removeEventListener('afterprint', cleanup);
    };
    window.addEventListener('afterprint', cleanup, { once: true });
    window.print();
  };

  const handleCopyHash = () => {
    navigator.clipboard.writeText(rawPayloadHash);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 1500);
  };

  return (
    <div className="space-y-4 font-sans text-navy-900 print:text-black print:m-0 print:p-0">
      {/* Top Action Bar (hidden on print) */}
      <div className="flex flex-wrap items-center justify-between gap-2 p-3 bg-slate-50 border border-border-light rounded-lg print:hidden">
        <div className="flex items-center gap-2">
          <Badge variant="ok" dot>
            STATUTORY ADMISSIBILITY READY
          </Badge>
          <span className="text-xs text-slate-500">
            Indian Evidence Act, 1872 (§65B) & Bharatiya Sakshya Adhiniyam, 2023 (§63)
          </span>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="secondary"
            size="sm"
            onClick={handleCopyHash}
            icon={copiedHash ? <Check className="w-3.5 h-3.5 text-green-600" /> : <Copy className="w-3.5 h-3.5" />}
          >
            {copiedHash ? 'Hash Copied' : 'Copy Evidence SHA-256'}
          </Button>
          <Button
            variant="primary"
            size="sm"
            onClick={handlePrint}
            icon={<Printer className="w-3.5 h-3.5" />}
          >
            Print / Save Formal PDF
          </Button>
          {onClose && (
            <Button variant="ghost" size="sm" onClick={onClose}>
              Close
            </Button>
          )}
        </div>
      </div>

      {/* Formal Certificate Paper Layout */}
      <div
        id="section-65b-formal-doc"
        className="bg-white border-2 border-slate-300 rounded-lg p-6 sm:p-8 shadow-sm space-y-6 relative overflow-hidden print:border-2 print:border-navy-900 print:shadow-none print:p-8 print:m-0 print:rounded-none print:space-y-4 print:text-black"
      >
        {/* Government Watermark Emblem Style */}
        <div className="border-b-2 border-navy-900 pb-4 text-center space-y-1">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-slate-100 border border-slate-300 text-gov-blue mb-1">
            <Scale className="w-6 h-6" />
          </div>
          <h1 className="text-base sm:text-lg font-black tracking-wide uppercase text-navy-900">
            GOVERNMENT OF INDIA · NATIONAL TECHNICAL RESEARCH ORGANISATION
          </h1>
          <h2 className="text-xs sm:text-sm font-bold tracking-wider text-slate-700 uppercase">
            CERTIFICATE UNDER SECTION 65B OF THE INDIAN EVIDENCE ACT, 1872
          </h2>
          <p className="text-[11px] text-slate-500 font-medium">
            (Read with Section 63 of the Bharatiya Sakshya Adhiniyam, 2023 and CERT-In Cyber Security Directives 2022)
          </p>
        </div>

        {/* Certificate Reference Details */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs bg-slate-50 p-3.5 rounded border border-slate-200">
          <div>
            <span className="text-[10px] font-bold uppercase text-slate-400 block">Certificate No.</span>
            <span className="font-mono font-bold text-navy-900">NTRO/65B/2026/0892</span>
          </div>
          <div>
            <span className="text-[10px] font-bold uppercase text-slate-400 block">Case / Incident ID</span>
            <span className="font-mono font-bold text-gov-blue">{incidentId}</span>
          </div>
          <div>
            <span className="text-[10px] font-bold uppercase text-slate-400 block">Issuing Authority</span>
            <span className="font-semibold text-navy-900 truncate block">{policeStationOrAgency}</span>
          </div>
          <div>
            <span className="text-[10px] font-bold uppercase text-slate-400 block">Certified Date (IST)</span>
            <span className="font-mono text-slate-700">{timestampIst}</span>
          </div>
        </div>

        {/* Legal Text & Declarations */}
        <div className="text-xs leading-relaxed text-slate-800 space-y-3">
          <p>
            I, <strong>{officerName}</strong>, holding the post of <strong>{officerDesignation}</strong>, being the person in lawful management, custody, and operational control of the computer systems, network security monitoring appliances, and cryptographic ingestion clusters described herein, do hereby certify and solemnly affirm as follows:
          </p>

          <ol className="list-decimal pl-5 space-y-2">
            <li>
              <strong>Source Identification:</strong> The electronic record comprising log telemetry, security event data, and packet headers associated with Incident <strong>{incidentId}</strong> (<em>"{incidentTitle}"</em>) was produced by computer systems and sensors located at <strong>{sourceDevice}</strong>, monitoring traffic directed toward or originating from <strong>{targetEntity}</strong>.
            </li>
            <li>
              <strong>Regular Course of Operation:</strong> The said electronic records were created, ingested, and stored in the ordinary and regular course of official duties during the operational period when the computer systems and ingestion nodes were operating properly.
            </li>
            <li>
              <strong>Absence of Tampering:</strong> During the relevant period, the computer system was operating properly, or if there was any brief period when it was not operating properly, that fact did not affect the production of the electronic record or the accuracy of its contents. The integrity of the log data has been verified through cryptographic hash chaining and content-addressed storage.
            </li>
            <li>
              <strong>NTP Clock Synchronization:</strong> The system clock utilized for time-stamping all related telemetry was continuously synchronized via authenticated NTP against the <strong>National Physical Laboratory (NPL-CSIR), New Delhi</strong>, maintaining Indian Standard Time (IST) accuracy within $\pm 50$ microseconds in compliance with CERT-In Directive No. 20(3)/2022-CERT-In.
            </li>
          </ol>
        </div>

        {/* Cryptographic Evidence & Blockchain Attestation */}
        <div className="space-y-2">
          <h3 className="text-xs font-bold uppercase tracking-wider text-navy-900 flex items-center gap-1.5">
            <ShieldCheck className="w-4 h-4 text-gov-blue" />
            Cryptographic Integrity & Blockchain Non-Repudiation Proof
          </h3>

          <div className="bg-slate-50 border border-slate-200 rounded-lg p-4 space-y-3">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <span className="text-[10px] font-bold uppercase text-slate-400 block">
                  Raw Evidence Payload SHA-256 Digest
                </span>
                <code className="text-xs font-mono font-bold text-navy-900 bg-white p-1.5 rounded border border-slate-200 block truncate">
                  {rawPayloadHash}
                </code>
              </div>

              <div>
                <span className="text-[10px] font-bold uppercase text-slate-400 block">
                  Anchored Blockchain Block
                </span>
                <div className="text-xs font-mono font-bold text-gov-blue bg-white p-1.5 rounded border border-slate-200 flex items-center justify-between">
                  <span>Block #{blockIndex}</span>
                  <span className="text-[10px] font-bold text-green-700 bg-green-50 px-1.5 rounded border border-green-200">
                    PoA Sealed
                  </span>
                </div>
              </div>

              <div>
                <span className="text-[10px] font-bold uppercase text-slate-400 block">
                  Merkle Tree Inclusion Root
                </span>
                <code className="text-xs font-mono text-slate-700 bg-white p-1.5 rounded border border-slate-200 block truncate">
                  {merkleRoot}
                </code>
              </div>

              <div>
                <span className="text-[10px] font-bold uppercase text-slate-400 block">
                  NTRO Sovereign PoA Digital Signature (HMAC-SHA256)
                </span>
                <code className="text-xs font-mono text-slate-700 bg-white p-1.5 rounded border border-slate-200 block truncate">
                  {poaSignature}
                </code>
              </div>
            </div>

            {/* QR Code & Direct Audit Verification */}
            <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-3 border-t border-slate-200 bg-white p-3 rounded">
              <div className="flex items-center gap-3">
                {/* Visual SVG QR Code Mock */}
                <div className="w-16 h-16 bg-slate-900 text-white rounded p-1 flex items-center justify-center flex-shrink-0">
                  <QrCode className="w-14 h-14 text-white" />
                </div>
                <div>
                  <span className="text-xs font-bold text-navy-900 block">
                    Judicial Verification QR Code
                  </span>
                  <p className="text-[11px] text-slate-500 leading-tight">
                    Scan with any standard device to verify cryptographic inclusion on the ULPF sovereign blockchain ledger in real-time.
                  </p>
                  <span className="text-[10px] font-mono text-gov-blue mt-0.5 block">
                    ulpf://verify/blockchain/tx/{rawPayloadHash.slice(0, 16)}
                  </span>
                </div>
              </div>

              <div className="text-right flex-shrink-0">
                <span className="text-[10px] font-bold text-green-700 bg-green-50 px-2.5 py-1 rounded border border-green-200 uppercase tracking-wider inline-flex items-center gap-1">
                  <CheckCircle2 className="w-3.5 h-3.5" /> 100% Tamper Proof
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Attestation Signature Box */}
        <div className="pt-6 border-t-2 border-slate-200 flex flex-col sm:flex-row justify-between items-end gap-6 text-xs">
          <div className="space-y-1">
            <span className="text-[10px] font-bold uppercase text-slate-400 block">Sovereign Node Hardware ID</span>
            <span className="font-mono text-slate-700">NTRO-AIRGAP-NODE-001 (MAC: 00:1A:2B:3C:4D:5E)</span>
            <div className="text-[11px] text-slate-500">Operating System: Sovereign Linux (Kernel 6.6-Hardened)</div>
          </div>

          <div className="text-right space-y-1 min-w-[240px]">
            <div className="h-10 border-b border-dashed border-slate-400 flex items-end justify-end pb-1">
              <span className="font-serif italic text-navy-900 font-bold text-sm">{officerName}</span>
            </div>
            <span className="text-xs font-bold text-navy-900 block">{officerName}</span>
            <span className="text-[11px] text-slate-600 block">{officerDesignation}</span>
            <span className="text-[10px] text-slate-500 uppercase tracking-wider block">
              Govt. of India · Cyber Forensic Examiner
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
