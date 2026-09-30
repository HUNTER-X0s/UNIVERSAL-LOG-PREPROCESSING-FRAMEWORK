import React from 'react';

export const Footer: React.FC = () => {
  return (
    <footer className="h-8 bg-white border-t border-border-medium px-5 flex items-center justify-between text-[11px] text-slate-500 font-sans flex-shrink-0 z-20">
      <div className="flex items-center gap-2">
        <span className="font-semibold text-navy-900">
          © Universal Log Pre-processing Framework
        </span>
        <span className="text-slate-300">|</span>
        <span className="text-slate-500 hidden sm:inline">
          Security Telemetry Processing Platform
        </span>
      </div>

      <div className="flex items-center gap-4 text-slate-500">
        <a href="#privacy" className="hover:text-navy-900 hover:underline transition-colors">
          Privacy
        </a>
        <span>·</span>
        <a href="#accessibility" className="hover:text-navy-900 hover:underline transition-colors">
          Accessibility
        </a>
        <span>·</span>
        <a href="#docs" className="hover:text-navy-900 hover:underline transition-colors">
          Documentation
        </a>
        <span>·</span>
        <a href="#help" className="hover:text-navy-900 hover:underline transition-colors">
          Help
        </a>
      </div>
    </footer>
  );
};
