import React, { useState } from 'react';
import { Modal } from '../ui/Modal';
import { Button } from '../ui/Button';
import { CodePanel } from '../ui/CodePanel';
import { JUDGE_STEPS } from '../../demo/judgeData';
import { ChevronLeft, ChevronRight, Clock, Award, ShieldCheck } from 'lucide-react';

export interface JudgeModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const JudgeModal: React.FC<JudgeModalProps> = ({ isOpen, onClose }) => {
  const [currentStepIdx, setCurrentStepIdx] = useState(0);
  const step = JUDGE_STEPS[currentStepIdx];

  const handlePrev = () => {
    setCurrentStepIdx((prev) => Math.max(0, prev - 1));
  };

  const handleNext = () => {
    setCurrentStepIdx((prev) => Math.min(JUDGE_STEPS.length - 1, prev + 1));
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={
        <div className="flex items-center gap-2">
          <Award className="w-4 h-4 text-gov-blue" />
          <span>SIH26156 / NTRO — Dedicated 2-Minute Judge Demonstration</span>
        </div>
      }
      maxWidth="max-w-5xl"
      footer={
        <div className="flex items-center justify-between w-full">
          <div className="flex items-center gap-2 text-xs text-slate-500 font-mono">
            <span>STAGE {currentStepIdx + 1} OF 10</span>
            <span>•</span>
            <span className="text-gov-blue font-semibold">{step.timeRange}</span>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="secondary"
              size="sm"
              onClick={handlePrev}
              disabled={currentStepIdx === 0}
              icon={<ChevronLeft className="w-3.5 h-3.5" />}
            >
              Previous Stage
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={handleNext}
              disabled={currentStepIdx === JUDGE_STEPS.length - 1}
              icon={<ChevronRight className="w-3.5 h-3.5" />}
            >
              Next Stage
            </Button>
          </div>
        </div>
      }
    >
      <div className="grid grid-cols-1 md:grid-cols-12 gap-5">
        {/* Step Navigation Rail */}
        <div className="md:col-span-4 border-r border-slate-200 pr-3 space-y-1">
          <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-2">
            EVALUATION STAGES (00:00 - 02:00)
          </div>
          {JUDGE_STEPS.map((s, idx) => (
            <button
              key={s.index}
              onClick={() => setCurrentStepIdx(idx)}
              className={`w-full text-left px-2.5 py-1.5 rounded text-xs transition-colors flex items-center justify-between ${
                currentStepIdx === idx
                  ? 'bg-gov-blue text-white font-semibold shadow-xs'
                  : 'text-slate-700 hover:bg-slate-100'
              }`}
            >
              <span className="truncate">{s.title.split('—')[1]?.trim() || s.title}</span>
              <span
                className={`text-[10px] font-mono px-1.5 py-0.2 rounded ${
                  currentStepIdx === idx ? 'bg-gov-dark text-white' : 'bg-slate-100 text-slate-500'
                }`}
              >
                {s.timeRange.split('–')[0].trim()}
              </span>
            </button>
          ))}
        </div>

        {/* Stage Content Detail */}
        <div className="md:col-span-8 space-y-4">
          <div className="flex items-center justify-between pb-2 border-b border-slate-200">
            <div>
              <h3 className="text-sm font-bold text-navy-900">{step.title}</h3>
              <div className="flex items-center gap-1.5 text-xs text-slate-500 mt-0.5">
                <Clock className="w-3 h-3 text-gov-blue" />
                <span>Elapsed Window: <strong className="text-navy-900">{step.timeRange}</strong></span>
              </div>
            </div>
            <span className="px-2 py-0.5 rounded bg-blue-50 text-gov-blue text-xs font-semibold border border-blue-200">
              STAGE {String(currentStepIdx + 1).padStart(2, '0')}
            </span>
          </div>

          <p className="text-xs text-slate-700 leading-relaxed font-sans">{step.summary}</p>

          <CodePanel
            code={step.proofSnippet}
            title="VERIFIED TELEMETRY PROOF / SCHEMA EVIDENCE"
            maxHeight="220px"
          />

          {/* Key Metrics Chips */}
          <div className="grid grid-cols-3 gap-2">
            {step.metrics.map((m, i) => (
              <div key={i} className="bg-slate-50 p-2 rounded border border-slate-200 text-center">
                <div className="text-[10px] text-slate-500 uppercase font-semibold">{m.label}</div>
                <div className="text-xs font-bold font-mono text-navy-900 mt-0.5">{m.value}</div>
              </div>
            ))}
          </div>

          {/* Speaker Notes */}
          <div className="p-3 bg-amber-50 rounded border border-amber-200 text-amber-900 text-xs">
            <div className="font-semibold mb-0.5 flex items-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5 text-amber-700" />
              <span>PRESENTER GUIDANCE (2-MIN SCRIPT):</span>
            </div>
            <p className="text-[11px] leading-relaxed text-amber-800">{step.speakerNotes}</p>
          </div>
        </div>
      </div>
    </Modal>
  );
};
