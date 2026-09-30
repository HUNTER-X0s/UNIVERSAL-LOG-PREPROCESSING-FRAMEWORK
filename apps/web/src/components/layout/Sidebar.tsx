/**
 * Sidebar — RBAC-aware collapsible navigation
 *
 * Nav items are gated by permission. Items the current user cannot access
 * are hidden (not merely disabled) so the UI reflects their actual access surface.
 *
 * Supports two states:
 *   - Expanded (w-60): shows group labels + nav item text
 *   - Collapsed (w-14): shows only icons in a compact rail with tooltips
 *
 * The collapse toggle button lives at the bottom of the sidebar.
 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { NavLink } from 'react-router-dom';
import {
  Activity,
  AlertTriangle,
  ArrowLeftRight,
  Bot,
  ChevronLeft,
  ChevronRight,
  Clock,
  Cpu,
  Crosshair,
  Database,
  DollarSign,
  Download,
  EyeOff,
  FileCheck,
  FileCode,
  Flame,
  GitFork,
  Globe,
  Inbox,
  LayoutDashboard,
  Layers,
  Link2,
  Network,
  PanelLeftClose,
  PanelLeftOpen,
  Radio,
  Search,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Target,
  Zap,
} from 'lucide-react';
import { useAuth } from '../../auth/AuthProvider';
import type { Permission } from '../../auth/auth.types';

// ---------------------------------------------------------------------------
// Nav data model
// ---------------------------------------------------------------------------

interface NavItemDef {
  path: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  /** If set, user must have this permission to see this item */
  requiredPermission?: Permission;
}

interface NavGroupDef {
  group: string;
  items: NavItemDef[];
  /** If set, user must have this permission to see any item in the group */
  requiredPermission?: Permission;
}

const NAV_GROUPS: NavGroupDef[] = [
  // ── 1. OPERATIONS HUB ──────────────────────────────────────────────────────
  // Core dashboard, AI copilot, real-time monitoring and streaming
  {
    group: 'OPERATIONS HUB',
    items: [
      { path: '/command-center',      label: 'Command Center',          icon: LayoutDashboard, requiredPermission: 'event.read' },
      { path: '/ai-copilot',          label: 'AI Pipeline Copilot',     icon: Bot,             requiredPermission: 'event.read' },
      { path: '/live-logs',           label: 'Live Logs Stream',        icon: Radio,           requiredPermission: 'event.read' },
      { path: '/log-intake',          label: 'Log Intake Plane',        icon: Inbox,           requiredPermission: 'event.read' },
      { path: '/health',              label: 'System Health & SLAs',    icon: Activity,        requiredPermission: 'event.read' },
      { path: '/telemetry-simulator', label: 'Telemetry Simulator',     icon: Flame,           requiredPermission: 'event.read' },
    ],
  },

  // ── 2. PARSERS & PIPELINE ──────────────────────────────────────────────────
  // All parser engineering, routing, cost and SIEM export tools
  {
    group: 'PARSERS & PIPELINE',
    items: [
      { path: '/parsers',             label: 'Parser Registry',         icon: Database,    requiredPermission: 'mapping.read' },
      { path: '/parser-workbench',    label: 'Parser Workbench',        icon: FileCode,    requiredPermission: 'mapping.read' },
      { path: '/parser-synthesizer',  label: 'Parser Auto-Synthesizer', icon: Sparkles,    requiredPermission: 'mapping.read' },
      { path: '/redos-debugger',      label: 'ReDoS Shield & Debugger', icon: ShieldAlert, requiredPermission: 'mapping.read' },
      { path: '/pipeline-routing',    label: 'Pipeline Routing & Replay', icon: GitFork,   requiredPermission: 'event.read' },
      { path: '/cost-optimizer',      label: 'SIEM Cost & Data Reduction', icon: DollarSign, requiredPermission: 'event.read' },
      { path: '/agent-exporter',      label: 'SIEM Agent Exporter',     icon: Download,    requiredPermission: 'event.read' },
    ],
  },

  // ── 3. UNIFIED CORE ────────────────────────────────────────────────────────
  // Normalization, PII, timestamp, quality, standards and schema management
  {
    group: 'UNIFIED CORE',
    items: [
      { path: '/universal-converter', label: 'Universal Transpiler',       icon: ArrowLeftRight, requiredPermission: 'uce.read' },
      { path: '/uce',                 label: 'UCE Normalization',          icon: Layers,      requiredPermission: 'uce.read' },
      { path: '/data-privacy',        label: 'Data Privacy & PII Shield',  icon: EyeOff,      requiredPermission: 'uce.read' },
      { path: '/timestamp-chronos',   label: 'Timestamp & Chronos Engine', icon: Clock,       requiredPermission: 'uce.read' },
      { path: '/log-quality',         label: 'Log Quality & Conformance',  icon: ShieldCheck, requiredPermission: 'uce.read' },
      { path: '/standards',           label: 'Standards Interoperability', icon: Network,     requiredPermission: 'uce.read' },
      { path: '/schemas-export',      label: 'Schemas & Export',           icon: Download,    requiredPermission: 'uce.read' },
      { path: '/onboarding',          label: 'Schema Drift & Onboarding',  icon: Cpu,         requiredPermission: 'config.read' },
      { path: '/query-translator',    label: 'Cross-SIEM Query Translator',icon: ArrowLeftRight, requiredPermission: 'uce.read' },
    ],
  },

  // ── 4. SECURITY INTELLIGENCE ───────────────────────────────────────────────
  // Threat detection, alerts, hunting, and GeoIP enrichment
  {
    group: 'SECURITY INTELLIGENCE',
    requiredPermission: 'intelligence.read',
    items: [
      { path: '/alerts',              label: 'Alerts & Detection',      icon: ShieldAlert,  requiredPermission: 'intelligence.read' },
      { path: '/threat-detection',    label: 'Threat Detection',        icon: AlertTriangle, requiredPermission: 'intelligence.read' },
      { path: '/threat-intelligence', label: 'Threat Intel & GeoIP',    icon: Crosshair,    requiredPermission: 'intelligence.read' },
      { path: '/investigation',       label: 'Investigation Desk',      icon: Search,       requiredPermission: 'intelligence.investigate' },
      { path: '/playbooks',           label: 'Response Playbooks',      icon: Zap,          requiredPermission: 'intelligence.read' },
    ],
  },

  // ── 5. COMPLIANCE & FORENSICS ──────────────────────────────────────────────
  // Legal admissibility, MITRE ATT&CK coverage, Indian regulatory compliance
  {
    group: 'COMPLIANCE & FORENSICS',
    items: [
      { path: '/forensics',           label: 'Forensic Lineage & §65B',  icon: FileCheck,    requiredPermission: 'intelligence.investigate' },
      { path: '/mitre-attack',        label: 'MITRE ATT&CK® Coverage',   icon: Target,       requiredPermission: 'intelligence.read' },
      { path: '/india-compliance',    label: 'India Regulatory Compliance', icon: Globe,     requiredPermission: 'event.read' },
    ],
  },

  // ── 6. BLOCKCHAIN & TRUST ──────────────────────────────────────────────────
  // Cryptographic audit chain and chain of custody
  {
    group: 'BLOCKCHAIN & TRUST',
    items: [
      { path: '/blockchain',          label: 'Blockchain Ledger',       icon: Link2,        requiredPermission: 'event.read' },
    ],
  },
];


// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface SidebarProps {
  collapsed: boolean;
  onToggleCollapse: () => void;
  className?: string;
}

// ---------------------------------------------------------------------------
// Sidebar
// ---------------------------------------------------------------------------

export const Sidebar: React.FC<SidebarProps> = ({ collapsed, onToggleCollapse, className }) => {
  const { hasPermission, isAuthenticated } = useAuth();

  // Dynamic user-controlled width with persistent memory
  const [width, setWidth] = useState<number>(() => {
    try {
      const saved = localStorage.getItem('ulpf_sidebar_width');
      if (saved) {
        const parsed = parseInt(saved, 10);
        if (!isNaN(parsed) && parsed >= 220 && parsed <= 520) {
          return parsed;
        }
      }
    } catch {
      // ignore
    }
    return 280; // comfortable default width to display long labels cleanly
  });

  const [isDragging, setIsDragging] = useState(false);
  const widthRef = useRef(width);
  widthRef.current = width;

  // Handle dragging right edge to resize
  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  useEffect(() => {
    if (!isDragging) return;

    const handleMouseMove = (e: MouseEvent) => {
      const clamped = Math.max(220, Math.min(e.clientX, 520));
      setWidth(clamped);
    };

    const handleMouseUp = () => {
      setIsDragging(false);
      try {
        localStorage.setItem('ulpf_sidebar_width', widthRef.current.toString());
      } catch {
        // ignore
      }
    };

    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';

    return () => {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    };
  }, [isDragging]);

  return (
    <aside
      className={`relative bg-white border-r border-border-medium flex flex-col flex-shrink-0 h-full min-h-0 overflow-hidden ${
        isDragging ? 'select-none' : 'transition-[width] duration-200 ease-in-out'
      } ${className || ''}`}
      style={{
        width: collapsed ? '56px' : `${width}px`,
      }}
    >
      {/* ── Top Header UI: Institutional Brand Label + Top-Right Collapse ── */}
      {collapsed ? (
        <div className="flex-shrink-0 h-11 border-b border-slate-100 flex items-center justify-center">
          <button
            id="sidebar-collapse-btn"
            type="button"
            onClick={onToggleCollapse}
            title="Expand sidebar"
            aria-label="Expand sidebar"
            className="p-1.5 text-slate-400 hover:text-navy-900 hover:bg-slate-100 rounded-md transition-colors cursor-pointer"
          >
            <PanelLeftOpen className="w-4 h-4 flex-shrink-0" />
          </button>
        </div>
      ) : (
        <div className="flex-shrink-0 h-11 border-b border-slate-100 flex items-center justify-between px-3">
          <div className="flex items-center gap-2 select-none">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
            <span className="text-xs font-bold text-slate-500 tracking-wider uppercase">
              ULPF PANEL
            </span>
          </div>
          <button
            id="sidebar-collapse-btn"
            type="button"
            onClick={onToggleCollapse}
            title="Collapse sidebar"
            aria-label="Collapse sidebar"
            className="p-1.5 text-slate-400 hover:text-navy-900 hover:bg-slate-100 rounded-md transition-colors cursor-pointer"
          >
            <PanelLeftClose className="w-4 h-4 flex-shrink-0" />
          </button>
        </div>
      )}

      {/* ── Drag resizer handle on border edge (does not overlap the scrollbar) ── */}
      {!collapsed && (
        <div
          onMouseDown={handleMouseDown}
          onDoubleClick={() => {
            setWidth(280);
            try {
              localStorage.setItem('ulpf_sidebar_width', '280');
            } catch {}
          }}
          title="Drag right edge to enlarge/compress sidebar · Double-click to reset"
          className={`absolute top-0 -right-1 w-2 h-full cursor-col-resize z-20 group hover:bg-gov-blue/20 transition-colors ${
            isDragging ? 'bg-gov-blue/40 w-2' : 'bg-transparent'
          }`}
        >
          <div className="w-0.5 h-full mx-auto bg-transparent group-hover:bg-gov-blue/60 transition-colors" />
        </div>
      )}

      {/* Scrollable nav area with persistent mouse scrollbar */}
      <div className="flex-1 min-h-0 overflow-y-scroll overflow-x-hidden ulpf-panel-scrollbar select-text">
        <nav className={`py-3 space-y-4 ${collapsed ? 'px-1.5' : 'px-2.5'}`}>
          {NAV_GROUPS.map((grp) => {
            // Hide entire group if user lacks the group-level permission
            if (grp.requiredPermission && !hasPermission(grp.requiredPermission)) {
              return null;
            }

            // Filter items by permission
            const visibleItems = isAuthenticated
              ? grp.items.filter(
                  (item) => !item.requiredPermission || hasPermission(item.requiredPermission),
                )
              : [];

            if (visibleItems.length === 0) return null;

            return (
              <div key={grp.group}>
                {/* Group label — only shown in expanded mode */}
                {!collapsed && (
                  <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider px-2 pb-1.5 mb-1 border-b border-slate-100">
                    {grp.group}
                  </div>
                )}

                {/* Collapsed mode: thin separator line instead of label */}
                {collapsed && (
                  <div className="border-b border-slate-100 mb-1 mx-1" />
                )}

                <div className="space-y-0.5">
                  {visibleItems.map((item) => {
                    const Icon = item.icon;
                    return collapsed ? (
                      /* ── Collapsed: icon-only rail with native tooltip ── */
                      <NavLink
                        key={item.path}
                        to={item.path}
                        title={item.label}
                        className={({ isActive }) =>
                          `flex items-center justify-center w-9 h-9 mx-auto rounded-lg transition-all duration-150 ${
                            isActive
                              ? 'bg-gov-light text-gov-blue border border-gov-border shadow-sm'
                              : 'text-slate-500 hover:bg-slate-100 hover:text-navy-900'
                          }`
                        }
                      >
                        <Icon className="w-4 h-4 flex-shrink-0" />
                      </NavLink>
                    ) : (
                      /* ── Expanded: icon + label ── */
                      <NavLink
                        key={item.path}
                        to={item.path}
                        className={({ isActive }) =>
                          `flex items-center gap-3 px-2.5 py-2 rounded-sm text-sm font-medium transition-colors ${
                            isActive
                              ? 'bg-gov-light text-navy-900 border-l-2 border-gov-blue font-semibold'
                              : 'text-slate-600 hover:bg-slate-100 hover:text-navy-900 border-l-2 border-transparent'
                          }`
                        }
                      >
                        <Icon className="w-4 h-4 flex-shrink-0 text-slate-500" />
                        <span className="truncate whitespace-nowrap">{item.label}</span>
                      </NavLink>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </nav>
      </div>

    </aside>
  );
};
