import React, { useState } from 'react';
import { Copy, Check, WrapText } from 'lucide-react';

export interface CodePanelProps {
  code: string;
  title?: string;
  language?: string;
  maxHeight?: string;
  className?: string;
  defaultWrap?: boolean;
}

export const CodePanel: React.FC<CodePanelProps> = ({
  code,
  title,
  language,
  maxHeight,
  className = '',
  defaultWrap = false,
}) => {
  const [copied, setCopied] = useState(false);
  const [wrap, setWrap] = useState(defaultWrap);

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className={`rounded border border-border-medium bg-slate-900 text-slate-100 overflow-hidden flex flex-col ${className}`}>
      {(title || language) && (
        <div className="flex items-center justify-between px-3 py-1.5 bg-slate-950 border-b border-slate-800 text-[11px] font-mono text-slate-400 flex-shrink-0">
          <span className="truncate pr-2">{title || language}</span>
          <div className="flex items-center gap-1.5 flex-shrink-0">
            <button
              type="button"
              onClick={() => setWrap((w) => !w)}
              className={`flex items-center gap-1 transition-colors text-[10px] px-1.5 py-0.5 rounded cursor-pointer ${
                wrap ? 'bg-gov-blue text-white' : 'bg-slate-800 hover:text-white text-slate-300'
              }`}
              title="Toggle line wrapping"
            >
              <WrapText className="w-3 h-3" />
              <span>{wrap ? 'Wrapped' : 'Wrap'}</span>
            </button>
            <button
              type="button"
              onClick={handleCopy}
              className="flex items-center gap-1 hover:text-white transition-colors text-[10px] px-1.5 py-0.5 rounded bg-slate-800 cursor-pointer"
              title="Copy code"
            >
              {copied ? <Check className="w-3 h-3 text-green-400" /> : <Copy className="w-3 h-3" />}
              {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
        </div>
      )}
      <pre
        className={`p-3 text-[11.5px] font-mono leading-relaxed overflow-auto selection:bg-gov-blue selection:text-white flex-1 ${
          wrap ? 'whitespace-pre-wrap break-all' : 'whitespace-pre'
        }`}
        style={maxHeight ? { maxHeight } : undefined}
      >
        <code>{code}</code>
      </pre>
    </div>
  );
};
