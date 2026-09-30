import React from 'react';
import { NTRO_REQUIREMENTS } from '../demo/ntroData';
import { Card } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { ClipboardCheck, CheckCircle2, FileCode, Shield } from 'lucide-react';

export const NtroTraceability: React.FC = () => {
  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-border-light">
        <div>
          <h2 className="text-lg font-bold text-navy-900 tracking-tight">NTRO Problem Statement Traceability Matrix</h2>
          <p className="text-xs text-slate-500">
            NTRO Scope Verification: 16 of 16 scope items mapped, implemented, and validated in continuous regression.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="ok" dot>16 / 16 REQUIREMENTS FULLY_VERIFIED</Badge>
          <Badge variant="info">100.0% COVERAGE</Badge>
        </div>
      </div>

      {/* Scope Table */}
      <div className="bg-white rounded border border-border-light shadow-xs overflow-hidden">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="bg-surface-alt border-b border-border-light text-[11px] font-bold text-slate-500 uppercase tracking-wider">
              <th className="py-2.5 px-3">ID / Requirement</th>
              <th className="py-2.5 px-3">ULPF Implemented Capability</th>
              <th className="py-2.5 px-3">Implementation Module</th>
              <th className="py-2.5 px-3">Validation Evidence</th>
              <th className="py-2.5 px-3 text-right">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 font-sans">
            {NTRO_REQUIREMENTS.map((req) => (
              <tr key={req.id} className="hover:bg-slate-50 transition-colors">
                <td className="py-2.5 px-3">
                  <div className="font-mono font-bold text-gov-blue">{req.id}</div>
                  <div className="font-semibold text-navy-900 mt-0.5">{req.requirement}</div>
                </td>
                <td className="py-2.5 px-3 text-slate-600 leading-relaxed">{req.ulpfCapability}</td>
                <td className="py-2.5 px-3 font-mono text-[11px] text-slate-500">
                  <code>{req.implementationModule}</code>
                </td>
                <td className="py-2.5 px-3 font-mono text-[11px] text-green-700">
                  {req.validationMethod}
                </td>
                <td className="py-2.5 px-3 text-right">
                  <span className="inline-flex items-center gap-1 font-mono font-bold text-[10.5px] px-2 py-0.5 rounded bg-green-50 text-green-800 border border-green-200">
                    <CheckCircle2 className="w-3 h-3 text-green-600" />
                    {req.status}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
