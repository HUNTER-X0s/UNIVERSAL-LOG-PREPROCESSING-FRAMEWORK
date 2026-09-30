import React, { useState } from 'react';
import { JUDGE_STEPS } from '../demo/judgeData';
import { CodePanel } from '../components/ui/CodePanel';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { ChevronLeft, ChevronRight, Clock, Award, ShieldCheck, CheckCircle2 } from 'lucide-react';

export const JudgeMode: React.FC = () => {
  const [currentStepIdx, setCurrentStepIdx] = useState(0);
  const step = JUDGE_STEPS[currentStepIdx];

  const handlePrev = () => setCurrentStepIdx((prev) => Math.max(0, prev - 1));
  const handleNext = () => setCurrentStepIdx((prev) => Math.min(JUDGE_STEPS.length - 1, prev + 1));

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="pb-2.5 border-b border-border-medium flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div>
          <h1 className="text-sm font-bold text-navy-900 uppercase tracking-wide flex items-center gap-2">
            <Award className="w-4 h-4 text-gov-blue" />
            <span>Problem Statement Demonstration — NTRO</span>
          </h1>
          <p className="text-xs text-slate-500 mt-0.5">
            Contextual 2-minute chronological walkthrough demonstrating compliance with all 16 technical evaluation requirements.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono font-bold text-gov-blue bg-blue-50 px-2 py-0.5 rounded border border-blue-200">
            {step.timeRange}
          </span>
          <Badge variant="ok" dot>STAGE {currentStepIdx + 1} OF 10</Badge>
        </div>
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Navigation Rail */}
        <div className="lg:col-span-4 bg-white border border-border-medium rounded p-3 space-y-1 shadow-2xs">
          <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-2">
            10-STAGE DEMONSTRATION WORKFLOW
          </div>
          {JUDGE_STEPS.map((s, idx) => (
            <button
              key={s.index}
              onClick={() => setCurrentStepIdx(idx)}
              className={`w-full text-left px-2.5 py-2 rounded text-xs transition-colors flex items-center justify-between ${
                currentStepIdx === idx
                  ? 'bg-gov-blue text-white font-semibold shadow-xs'
                  : 'text-slate-700 hover:bg-slate-100'
              }`}
            >
              <div className="truncate pr-2">
                <span className="font-mono text-[10px] mr-1.5 opacity-80">
                  {String(idx + 1).padStart(2, '0')}.
                </span>
                <span>{s.title.split('—')[1]?.trim() || s.title}</span>
              </div>
              <span
                className={`text-[10px] font-mono px-1.5 py-0.2 rounded flex-shrink-0 ${
                  currentStepIdx === idx ? 'bg-gov-dark text-white' : 'bg-slate-100 text-slate-500'
                }`}
              >
                {s.timeRange.split('–')[0].trim()}
              </span>
            </button>
          ))}
        </div>

        {/* Detail Panel */}
        <div className="lg:col-span-8 space-y-4">
          <Card
            title={step.title}
            subtitle={`Elapsed Demo Window: ${step.timeRange}`}
            action={
              <div className="flex items-center gap-2">
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={handlePrev}
                  disabled={currentStepIdx === 0}
                  icon={<ChevronLeft className="w-3.5 h-3.5" />}
                >
                  Previous
                </Button>
                <Button
                  variant="primary"
                  size="sm"
                  onClick={handleNext}
                  disabled={currentStepIdx === JUDGE_STEPS.length - 1}
                  icon={<ChevronRight className="w-3.5 h-3.5" />}
                >
                  Next
                </Button>
              </div>
            }
          >
            <div className="space-y-3.5 text-xs">
              <p className="text-slate-700 leading-relaxed font-sans">{step.summary}</p>

              <CodePanel
                code={step.proofSnippet}
                title="VERIFIED ENGINEERING PROOF / SCHEMA EVIDENCE"
                maxHeight="240px"
              />

              <div className="grid grid-cols-3 gap-2">
                {step.metrics.map((m, i) => (
                  <div key={i} className="bg-slate-50 p-2 rounded border border-slate-200 text-center">
                    <div className="text-[10px] text-slate-500 uppercase font-semibold">{m.label}</div>
                    <div className="text-xs font-bold font-mono text-navy-900 mt-0.5">{m.value}</div>
                  </div>
                ))}
              </div>

              <div className="p-3 bg-amber-50 rounded border border-amber-200 text-amber-900 text-xs">
                <div className="font-semibold mb-0.5 flex items-center gap-1.5">
                  <ShieldCheck className="w-3.5 h-3.5 text-amber-700" />
                  <span>PRESENTER SCRIPT GUIDANCE:</span>
                </div>
                <p className="text-[11px] leading-relaxed text-amber-800">{step.speakerNotes}</p>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
};
