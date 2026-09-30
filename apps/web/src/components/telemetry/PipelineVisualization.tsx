import React, { useState } from 'react';
import { PIPELINE_STAGES } from '../../demo/pipelineData';
import { CheckCircle2, ChevronRight, Info } from 'lucide-react';

export const PipelineVisualization: React.FC = () => {
  const [selectedStage, setSelectedStage] = useState(PIPELINE_STAGES[0]);

  return (
    <div className="bg-white p-4 rounded border border-border-light shadow-xs space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <h4 className="text-xs font-bold uppercase tracking-wider text-navy-900">
            End-to-End Deterministic Telemetry Processing Pipeline (9 Stages)
          </h4>
          <p className="text-[11px] text-slate-500">
            Click any stage to inspect its operational guarantees and cryptographic boundary.
          </p>
        </div>
        <span className="text-[11px] font-mono font-semibold px-2 py-0.5 rounded bg-green-50 text-green-700 border border-green-200">
          ALL 9 STAGES VERIFIED
        </span>
      </div>

      {/* Horizontal Pipeline Steps */}
      <div className="grid grid-cols-3 sm:grid-cols-5 lg:grid-cols-9 gap-1.5 pt-1">
        {PIPELINE_STAGES.map((s) => {
          const isSelected = selectedStage.id === s.id;
          return (
            <button
              key={s.id}
              onClick={() => setSelectedStage(s)}
              className={`text-left p-2 rounded border transition-all relative ${
                isSelected
                  ? 'bg-gov-light border-gov-blue shadow-xs ring-1 ring-gov-blue'
                  : 'bg-slate-50 border-slate-200 hover:bg-slate-100'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="text-[10px] font-mono font-bold text-gov-blue">{s.number}</span>
                <CheckCircle2 className="w-3 h-3 text-green-600" />
              </div>
              <div className="text-[11px] font-bold text-navy-900 leading-tight truncate">
                {s.name}
              </div>
              <div className="text-[10px] font-mono text-slate-400 mt-1">
                {s.latencyMs} ms
              </div>
            </button>
          );
        })}
      </div>

      {/* Selected Stage Detail Panel */}
      <div className="bg-slate-50 p-3 rounded border border-slate-200 flex items-start gap-3">
        <Info className="w-4 h-4 text-gov-blue mt-0.5 flex-shrink-0" />
        <div className="text-xs space-y-1">
          <div className="flex items-center gap-2">
            <strong className="text-navy-900 font-bold">
              Stage {selectedStage.number} — {selectedStage.name}
            </strong>
            <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-white border border-slate-200 text-slate-600">
              Avg Latency: {selectedStage.latencyMs} ms
            </span>
          </div>
          <p className="text-slate-600">{selectedStage.shortDesc}</p>
          <div className="text-[11px] text-gov-blue font-semibold">
            Architectural Guarantee: {selectedStage.guarantee}
          </div>
        </div>
      </div>
    </div>
  );
};
