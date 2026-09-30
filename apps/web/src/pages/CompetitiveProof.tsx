import React from 'react';
import { Card } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Award, CheckCircle2, XCircle } from 'lucide-react';

const COMPARISON_MATRIX = [
  { feature: 'Raw Telemetry Immutability', traditional: 'Discarded after regex parsing or modified in-place', ulpf: 'SHA-256 Content-Addressed Storage (CAS) write-once', advantage: 'Judicially defensible chain of custody' },
  { feature: 'Unmapped Field Handling', traditional: 'Silently dropped / discarded if not in hardcoded schema', ulpf: 'Preserved losslessly in unmapped_residue envelope', advantage: '100% forensic recall across all 20 vendors' },
  { feature: 'Open Standards Interop', traditional: 'Proprietary agent format with vendor lock-in', ulpf: 'Simultaneous dual projection to OCSF v1.1.0 & OTel Logs', advantage: 'Zero re-parsing overhead for lakehouse export' },
  { feature: 'Unknown Source Onboarding', traditional: 'Manual code changes, testing, and multi-week deployment', ulpf: 'AI-assisted token profiling with ReDoS safety (< 30s)', advantage: 'Rapid operationalization with human review gate' },
  { feature: 'Cryptographic Lineage', traditional: 'Limited to basic ingestion timestamp metadata', ulpf: '13-stage Merkle DAG binding capture to delivery', advantage: 'Instant detection of unauthorized field tampering' },
  { feature: 'Air-Gap Sovereignty', traditional: 'Requires cloud licensing or outbound heartbeat telemetry', ulpf: '100% self-contained with zero outbound network sockets', advantage: 'Strict national defense isolation compliance' },
];

export const CompetitiveProof: React.FC = () => {
  return (
    <div className="space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-border-light">
        <div>
          <h2 className="text-lg font-bold text-navy-900 tracking-tight">Competitive Architectural Superiority</h2>
          <p className="text-xs text-slate-500">
            Factual engineering comparison of ULPF against conventional log parsers and legacy SIEM ingestion pipelines.
          </p>
        </div>
        <Badge variant="ok" dot>FACTUAL BENCHMARK MATRIX</Badge>
      </div>

      <div className="bg-white rounded border border-border-light shadow-xs overflow-hidden">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="bg-surface-alt border-b border-border-light text-[11px] font-bold text-slate-500 uppercase tracking-wider">
              <th className="py-2.5 px-3">Architectural Dimension</th>
              <th className="py-2.5 px-3">Conventional Parsers / SIEM Agents</th>
              <th className="py-2.5 px-3">ULPF National Defense Platform</th>
              <th className="py-2.5 px-3">Sovereign Operational Advantage</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 font-sans">
            {COMPARISON_MATRIX.map((row, idx) => (
              <tr key={idx} className="hover:bg-slate-50 transition-colors">
                <td className="py-2.5 px-3 font-semibold text-navy-900">{row.feature}</td>
                <td className="py-2.5 px-3 text-slate-500 flex items-center gap-1.5">
                  <XCircle className="w-3.5 h-3.5 text-red-500 flex-shrink-0" />
                  <span>{row.traditional}</span>
                </td>
                <td className="py-2.5 px-3 text-navy-900 font-medium">
                  <div className="flex items-center gap-1.5 text-green-900 font-semibold">
                    <CheckCircle2 className="w-3.5 h-3.5 text-green-600 flex-shrink-0" />
                    <span>{row.ulpf}</span>
                  </div>
                </td>
                <td className="py-2.5 px-3 text-gov-blue font-mono text-[11px]">{row.advantage}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
