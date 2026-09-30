import React from 'react';

export interface MetricCardProps {
  label: string;
  value: string | number;
  subtext?: string;
  category?: string;
  badge?: React.ReactNode;
  icon?: React.ReactNode;
}

export const MetricCard: React.FC<MetricCardProps> = ({
  label,
  value,
  subtext,
  category,
  badge,
  icon,
}) => {
  return (
    <div className="bg-white p-3.5 rounded border border-border-light shadow-sm flex flex-col justify-between">
      <div className="flex items-center justify-between gap-2 mb-1.5">
        <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider truncate" title={label}>{label}</span>
        {badge ? (
          <div className="flex-shrink-0">{badge}</div>
        ) : icon ? (
          <span className="text-slate-400 flex-shrink-0">{icon}</span>
        ) : null}
      </div>
      <div className="text-xl font-bold font-mono text-navy-900 tracking-tight my-1">{value}</div>
      <div className="flex items-center justify-between text-[11px] text-slate-500 pt-1 border-t border-slate-100 gap-2">
        <span className="truncate min-w-0 flex-1" title={typeof subtext === 'string' ? subtext : undefined}>{subtext}</span>
        {category && <span className="font-medium text-gov-blue text-right ml-auto flex-shrink-0 whitespace-nowrap">{category}</span>}
      </div>
    </div>
  );
};
