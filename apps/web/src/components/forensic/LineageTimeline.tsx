import React, { useState } from 'react';
import { FORENSIC_LINEAGE_13 } from '../../demo/pipelineData';
import { ShieldCheck, ShieldAlert, CheckCircle2, Copy } from 'lucide-react';
import { Button } from '../ui/Button';

export const LineageTimeline: React.FC = () => {
  const [tampered, setTampered] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState<'clean' | 'tampered' | null>('clean');

  const handleVerify = () => {
    setVerifying(true);
    setTimeout(() => {
      setVerifying(false);
      setVerificationResult(tampered ? 'tampered' : 'clean');
    }, 400);
  };

  const handleSimulateTampering = () => {
    setTampered((prev) => !prev);
    setVerificationResult(null);
  };

  return (
    <div className="bg-white p-5 rounded border border-border-light shadow-xs space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-border-light">
        <div>
          <h4 className="text-xs font-bold uppercase tracking-wider text-navy-900 flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-gov-blue" />
            <span>13-Stage Cryptographic Evidence Chain (Merkle Lineage)</span>
          </h4>
          <p className="text-[11px] text-slate-500">
            End-to-end cryptographic hash binding from raw telemetry ingestion to outbox delivery.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant={tampered ? 'danger' : 'outline'}
            size="sm"
            onClick={handleSimulateTampering}
          >
            {tampered ? 'Revert Tamper Injection' : 'Inject 1-Byte Tamper'}
          </Button>
          <Button
            variant="primary"
            size="sm"
            onClick={handleVerify}
            disabled={verifying}
          >
            {verifying ? 'Verifying Hashes...' : 'Verify Cryptographic Integrity'}
          </Button>
        </div>
      </div>

      {/* Verification Status Banner */}
      {verificationResult && (
        <div
          className={`p-3 rounded border text-xs flex items-center gap-2.5 ${
            verificationResult === 'clean'
              ? 'bg-green-50 border-green-200 text-green-900'
              : 'bg-red-50 border-red-200 text-red-900'
          }`}
        >
          {verificationResult === 'clean' ? (
            <>
              <CheckCircle2 className="w-4 h-4 text-green-600 flex-shrink-0" />
              <span>
                <strong>INTEGRITY VERIFIED:</strong> Merkle root digest matching CAS receipt. All 13 stages intact with zero alterations.
              </span>
            </>
          ) : (
            <>
              <ShieldAlert className="w-4 h-4 text-red-600 flex-shrink-0" />
              <span>
                <strong>CRITICAL SECURITY ALERT — TAMPER DETECTED:</strong> Stage 06 field hash mismatch. Digest does not match root anchor! Evidence chain broken.
              </span>
            </>
          )}
        </div>
      )}

      {/* Timeline stages list */}
      <div className="space-y-1.5 max-h-[360px] overflow-y-auto pr-1">
        {FORENSIC_LINEAGE_13.map((item) => {
          const isItemTampered = tampered && item.stage === 6;
          return (
            <div
              key={item.stage}
              className={`p-2.5 rounded border text-xs flex flex-col md:flex-row md:items-center justify-between gap-2 transition-colors ${
                isItemTampered
                  ? 'bg-red-50 border-red-300 ring-1 ring-red-400'
                  : 'bg-slate-50 border-slate-200 hover:bg-slate-100'
              }`}
            >
              <div className="flex items-center gap-2.5">
                <span className="w-5 h-5 rounded-full bg-slate-200 text-slate-700 font-mono font-bold text-[10px] flex items-center justify-center flex-shrink-0">
                  {String(item.stage).padStart(2, '0')}
                </span>
                <div>
                  <div className="font-semibold text-navy-900 flex items-center gap-2">
                    <span>{item.name}</span>
                    <span className="text-[10px] font-mono text-slate-500 font-normal">
                      [{item.component}]
                    </span>
                  </div>
                  <div className="text-[10.5px] text-slate-500">{item.details}</div>
                </div>
              </div>

              <div className="flex items-center gap-3 font-mono text-[10.5px]">
                <span className="text-slate-400 hidden lg:inline">{item.timestamp}</span>
                <span
                  className={`px-1.5 py-0.5 rounded font-mono ${
                    isItemTampered
                      ? 'bg-red-100 text-red-800 font-bold'
                      : 'bg-white border border-slate-200 text-slate-600'
                  }`}
                  title={item.hash}
                >
                  {isItemTampered ? 'MUTATED_DIGEST_FAIL' : `${item.hash.substring(0, 16)}...`}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
