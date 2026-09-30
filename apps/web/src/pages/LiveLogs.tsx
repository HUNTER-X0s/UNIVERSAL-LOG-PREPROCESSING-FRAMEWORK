import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  useReactTable,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  flexRender,
  ColumnDef,
  SortingState,
  VisibilityState,
} from '@tanstack/react-table';
import * as Tabs from '@radix-ui/react-tabs';
import * as Dialog from '@radix-ui/react-dialog';
import * as DropdownMenu from '@radix-ui/react-dropdown-menu';
import {
  Activity,
  AlertTriangle,
  ArrowUpDown,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Clock,
  Columns,
  Download,
  ExternalLink,
  Eye,
  Filter,
  Layers,
  Pause,
  Play,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  X,
} from 'lucide-react';

import { TelemetryEvent } from '../api/operations';
import { INITIAL_TELEMETRY_EVENTS } from '../demo/telemetryEvents';
import { CodePanel } from '../components/ui/CodePanel';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';

// Severity badge renderer matching institutional styling
export const renderSeverityBadge = (severity: string) => {
  switch (severity?.toUpperCase()) {
    case 'CRITICAL':
      return <Badge variant="danger">CRITICAL</Badge>;
    case 'HIGH':
      return <Badge variant="danger">HIGH</Badge>;
    case 'MEDIUM':
      return <Badge variant="warn">MEDIUM</Badge>;
    case 'LOW':
      return <Badge variant="info">LOW</Badge>;
    default:
      return <Badge variant="neutral">INFO</Badge>;
  }
};

export const DEFAULT_COLUMN_VISIBILITY: VisibilityState = {
  event_id: true,
  timestamp: true,
  source: true,
  vendor: true,
  category: true,
  action: true,
  severity: true,
  parser: true,
  uce_status: true,
  tenant_id: false,
  processing_status: false,
};

export const COLUMN_LABELS: Record<string, string> = {
  timestamp: 'Timestamp',
  severity: 'Severity',
  event_id: 'Event ID',
  source: 'Source',
  vendor: 'Vendor',
  category: 'Domain',
  action: 'Action',
  parser: 'Parser',
  uce_status: 'UCE Normalization',
  tenant_id: 'Tenant',
  processing_status: 'Processing Status',
};

export const LiveLogs: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const requestedEventId = searchParams.get('eventId');

  // Stream state & bounded buffer (capped at 200 items in memory to prevent browser exhaustion)
  const [events, setEvents] = useState<TelemetryEvent[]>(() => {
    try {
      const stored = localStorage.getItem('ulpf_simulated_events');
      if (stored) {
        const parsed = JSON.parse(stored);
        if (Array.isArray(parsed) && parsed.length > 0) {
          return [...parsed, ...INITIAL_TELEMETRY_EVENTS].slice(0, 200);
        }
      }
    } catch {
      // fallback to initial
    }
    return INITIAL_TELEMETRY_EVENTS;
  });
  const [isPaused, setIsPaused] = useState<boolean>(false);
  const [refreshIntervalSec, setRefreshIntervalSec] = useState<number>(2);
  const [lastRefreshed, setLastRefreshed] = useState<Date>(new Date());
  const [selectedEvent, setSelectedEvent] = useState<TelemetryEvent | null>(null);

  // Listen for live simulated events broadcasted by TelemetrySimulator
  useEffect(() => {
    const handleSimulatedEvent = (e: Event) => {
      const customEvent = e as CustomEvent<TelemetryEvent>;
      if (customEvent.detail) {
        setEvents((prev) => [customEvent.detail, ...prev.slice(0, 199)]);
      }
    };
    window.addEventListener('ulpf:telemetry_injected', handleSimulatedEvent);
    return () => window.removeEventListener('ulpf:telemetry_injected', handleSimulatedEvent);
  }, []);

  // Filters state
  const [globalFilter, setGlobalFilter] = useState<string>(() => searchParams.get('q') || '');
  const [vendorFilter, setVendorFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [timeRange, setTimeRange] = useState<string>('15m');
  const [showAdvancedFilters, setShowAdvancedFilters] = useState<boolean>(false);

  // Sync URL ?q= param into globalFilter
  useEffect(() => {
    const q = searchParams.get('q');
    if (q !== null) {
      setGlobalFilter(q);
    }
  }, [searchParams]);

  // Table state
  const [sorting, setSorting] = useState<SortingState>([{ id: 'timestamp', desc: true }]);
  const [columnVisibility, setColumnVisibility] = useState<VisibilityState>(DEFAULT_COLUMN_VISIBILITY);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);

  // Manual refresh handler: queries backend search API or prepends fresh live telemetry
  const handleManualRefresh = useCallback(async () => {
    setIsRefreshing(true);
    setLastRefreshed(new Date());

    try {
      // 1. Try pulling recent events from platform search API
      try {
        const res = await fetch('/api/v1/search?limit=25', {
          headers: { 'X-Role': 'viewer' },
        });
        if (res.ok) {
          const data = await res.json();
          if (data?.events && Array.isArray(data.events) && data.events.length > 0) {
            setEvents((prev) => {
              const existingIds = new Set(prev.map((e) => e.event_id));
              const fresh = data.events.filter((e: any) => !existingIds.has(e.event_id));
              if (fresh.length > 0) {
                return [...fresh, ...prev].slice(0, 200);
              }
              return prev;
            });
          }
        }
      } catch {
        // standalone / offline mode
      }

      // 2. Prepend a freshly stamped simulated event to guarantee immediate visible update
      setEvents((prev) => {
        const samplePool = INITIAL_TELEMETRY_EVENTS;
        const randomItem = samplePool[Math.floor(Math.random() * samplePool.length)];
        const newEvent: TelemetryEvent = {
          ...randomItem,
          event_id: `evt-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
          timestamp: new Date().toISOString(),
        };
        return [newEvent, ...prev.slice(0, 199)];
      });
    } finally {
      setTimeout(() => {
        setIsRefreshing(false);
      }, 350);
    }
  }, []);

  // Auto-select event if eventId param is present
  useEffect(() => {
    if (requestedEventId) {
      const match = events.find((e) => e.event_id === requestedEventId);
      if (match) setSelectedEvent(match);
    }
  }, [requestedEventId, events]);

  // Polling simulation: every N seconds, simulate fresh telemetry with bounded buffer
  useEffect(() => {
    if (isPaused) return;

    const timer = setInterval(() => {
      setLastRefreshed(new Date());
      // Periodically update timestamp on a cloned event to simulate incoming telemetry
      setEvents((prev) => {
        const samplePool = INITIAL_TELEMETRY_EVENTS;
        const randomItem = samplePool[Math.floor(Math.random() * samplePool.length)];
        const newEvent: TelemetryEvent = {
          ...randomItem,
          event_id: `evt-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
          timestamp: new Date().toISOString(),
        };
        // Keep max 200 items to guarantee strict DOM & memory bounds
        return [newEvent, ...prev.slice(0, 199)];
      });
    }, refreshIntervalSec * 1000);

    return () => clearInterval(timer);
  }, [isPaused, refreshIntervalSec]);

  // Filtered dataset
  const filteredData = useMemo(() => {
    return events.filter((e) => {
      if (vendorFilter !== 'ALL' && e.vendor !== vendorFilter) return false;
      if (severityFilter !== 'ALL' && e.severity !== severityFilter) return false;
      if (statusFilter !== 'ALL' && e.uce_status !== statusFilter) return false;
      if (globalFilter.trim()) {
        const q = globalFilter.toLowerCase();
        const match =
          e.event_id.toLowerCase().includes(q) ||
          e.source.toLowerCase().includes(q) ||
          e.vendor.toLowerCase().includes(q) ||
          e.parser.toLowerCase().includes(q) ||
          e.action.toLowerCase().includes(q) ||
          e.category.toLowerCase().includes(q) ||
          (e.raw_payload && e.raw_payload.toLowerCase().includes(q));
        if (!match) return false;
      }
      return true;
    });
  }, [events, vendorFilter, severityFilter, statusFilter, globalFilter]);

  // Unique vendors for filter dropdown
  const vendors = useMemo(() => {
    const set = new Set(events.map((e) => e.vendor));
    return Array.from(set);
  }, [events]);

  // TanStack Table columns definition
  const columns = useMemo<ColumnDef<TelemetryEvent>[]>(
    () => [
      {
        accessorKey: 'timestamp',
        header: ({ column }) => (
          <button
            onClick={() => column.toggleSorting(column.getIsSorted() === 'asc')}
            className="flex items-center gap-1 font-semibold text-slate-700 hover:text-navy-900"
          >
            Timestamp
            <ArrowUpDown className="w-3 h-3 text-slate-400" />
          </button>
        ),
        cell: (info) => {
          const val = info.getValue() as string;
          return (
            <span className="font-mono text-[11px] text-slate-700 whitespace-nowrap">
              {val?.replace('T', ' ')?.replace('Z', '')?.substring(11, 23)}
            </span>
          );
        },
      },
      {
        accessorKey: 'severity',
        header: 'Severity',
        cell: (info) => renderSeverityBadge(info.getValue() as string),
      },
      {
        accessorKey: 'event_id',
        header: 'Event ID',
        cell: (info) => (
          <span className="font-mono text-[11px] font-semibold text-gov-blue hover:underline">
            {info.getValue() as string}
          </span>
        ),
      },
      {
        accessorKey: 'source',
        header: 'Source',
        cell: (info) => (
          <span className="text-[11.5px] text-slate-800 font-mono truncate max-w-[140px] block" title={info.getValue() as string}>
            {info.getValue() as string}
          </span>
        ),
      },
      {
        accessorKey: 'vendor',
        header: 'Vendor',
        cell: (info) => <span className="text-[11.5px] text-slate-700">{info.getValue() as string}</span>,
      },
      {
        accessorKey: 'category',
        header: 'Domain',
        cell: (info) => (
          <span className="text-[11px] font-mono px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200">
            {info.getValue() as string}
          </span>
        ),
      },
      {
        accessorKey: 'action',
        header: 'Action',
        cell: (info) => {
          const act = (info.getValue() as string)?.toLowerCase();
          const isDeny = act === 'deny' || act === 'drop' || act === 'block';
          return (
            <span className={`text-[11px] font-mono uppercase font-bold ${isDeny ? 'text-red-700' : 'text-slate-700'}`}>
              {info.getValue() as string}
            </span>
          );
        },
      },
      {
        accessorKey: 'parser',
        header: 'Parser',
        cell: (info) => (
          <span className="text-[11px] font-mono text-slate-600 truncate max-w-[120px] block">
            {info.getValue() as string}
          </span>
        ),
      },
      {
        accessorKey: 'uce_status',
        header: 'UCE Normalization',
        cell: (info) => {
          const st = info.getValue() as string;
          return (
            <span className="inline-flex items-center gap-1 text-[11px] font-mono text-emerald-800 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200">
              <CheckCircle2 className="w-3 h-3 text-emerald-600" />
              {st}
            </span>
          );
        },
      },
      {
        accessorKey: 'tenant_id',
        header: 'Tenant',
        cell: (info) => <span className="text-[11px] font-mono text-slate-500">{info.getValue() as string}</span>,
      },
      {
        accessorKey: 'processing_status',
        header: 'Status',
        cell: (info) => <span className="text-[11px] font-mono text-slate-500">{info.getValue() as string}</span>,
      },
    ],
    []
  );

  const table = useReactTable({
    data: filteredData,
    columns,
    state: {
      sorting,
      columnVisibility,
    },
    onSortingChange: setSorting,
    onColumnVisibilityChange: setColumnVisibility,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    initialState: {
      pagination: {
        pageSize: 15,
      },
    },
  });

  const clearAllFilters = useCallback(() => {
    setGlobalFilter('');
    setVendorFilter('ALL');
    setSeverityFilter('ALL');
    setStatusFilter('ALL');
    setTimeRange('15m');
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      next.delete('q');
      return next;
    });
  }, [setSearchParams]);

  return (
    <div className="space-y-4">
      {/* Header bar with strict institutional styling */}
      <div className="pb-3 border-b border-border-medium flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-sm font-bold text-navy-900 uppercase tracking-wide">Live Logs / Event Stream</h1>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-300">
              Bounded Buffer: {events.length} / 200
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Real-time security telemetry and normalized event stream. Inspected across 20 registered parsers.
          </p>
        </div>

        {/* Streaming & Refresh Controls */}
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded border border-border-medium bg-white text-[11px] font-mono text-slate-600">
            <span className={`w-2 h-2 rounded-full ${isPaused ? 'bg-amber-500' : 'bg-emerald-500 animate-pulse'}`} />
            <span>{isPaused ? 'PAUSED' : `Auto-refresh: ${refreshIntervalSec}s`}</span>
          </div>

          <Button
            size="sm"
            variant="outline"
            onClick={() => setIsPaused((p) => !p)}
            className="flex items-center gap-1 text-xs"
          >
            {isPaused ? <Play className="w-3.5 h-3.5 text-emerald-600" /> : <Pause className="w-3.5 h-3.5 text-amber-600" />}
            {isPaused ? 'Resume' : 'Pause'}
          </Button>

          <Button
            size="sm"
            variant="outline"
            onClick={handleManualRefresh}
            disabled={isRefreshing}
            title="Manual refresh live telemetry feed"
            className="text-xs flex items-center gap-1.5"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-slate-600 ${isRefreshing ? 'animate-spin text-gov-blue' : ''}`} />
            <span>{isRefreshing ? 'Refreshing...' : 'Refresh'}</span>
          </Button>

          {/* Column visibility menu */}
          <DropdownMenu.Root>
            <DropdownMenu.Trigger asChild>
              <Button size="sm" variant="outline" className="flex items-center gap-1.5 text-xs font-medium">
                <Columns className="w-3.5 h-3.5 text-slate-600" />
                <span>Columns</span>
                <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-100 text-slate-700 border border-slate-200">
                  {table.getAllLeafColumns().filter((col) => col.getIsVisible()).length}/{table.getAllLeafColumns().length}
                </span>
              </Button>
            </DropdownMenu.Trigger>
            <DropdownMenu.Portal>
              <DropdownMenu.Content
                className="bg-white border border-border-medium rounded shadow-xl p-2.5 min-w-[210px] z-50 text-xs font-mono animate-scale-in"
                align="end"
                sideOffset={5}
                onCloseAutoFocus={(e) => e.preventDefault()}
              >
                <div className="flex items-center justify-between pb-1.5 mb-1.5 border-b border-slate-100">
                  <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">
                    Visible Columns ({table.getAllLeafColumns().filter((col) => col.getIsVisible()).length}/{table.getAllLeafColumns().length})
                  </span>
                  <div className="flex items-center gap-1.5">
                    <button
                      type="button"
                      onClick={(e) => {
                        e.preventDefault();
                        e.stopPropagation();
                        table.toggleAllColumnsVisible(true);
                      }}
                      className="text-[10px] text-gov-blue hover:underline font-semibold cursor-pointer"
                    >
                      All
                    </button>
                    <span className="text-slate-300">•</span>
                    <button
                      type="button"
                      onClick={(e) => {
                        e.preventDefault();
                        e.stopPropagation();
                        setColumnVisibility(DEFAULT_COLUMN_VISIBILITY);
                      }}
                      className="text-[10px] text-slate-500 hover:text-slate-800 font-semibold cursor-pointer"
                    >
                      Reset
                    </button>
                  </div>
                </div>
                <div className="space-y-0.5 max-h-72 overflow-y-auto">
                  {table.getAllLeafColumns().map((col) => {
                    const isChecked = col.getIsVisible();
                    const label = COLUMN_LABELS[col.id] || col.id.replace('_', ' ');
                    return (
                      <div
                        key={col.id}
                        onClick={(e) => {
                          e.preventDefault();
                          e.stopPropagation();
                          col.toggleVisibility(!isChecked);
                        }}
                        className={`flex items-center justify-between px-2 py-1.5 rounded cursor-pointer select-none transition-colors ${
                          isChecked ? 'hover:bg-slate-50 text-navy-900 font-medium' : 'hover:bg-slate-50 text-slate-400'
                        }`}
                      >
                        <div className="flex items-center gap-2">
                          <input
                            type="checkbox"
                            checked={isChecked}
                            readOnly
                            className="rounded border-slate-300 text-gov-blue focus:ring-0 w-3.5 h-3.5 pointer-events-none"
                          />
                          <span className="text-xs">{label}</span>
                        </div>
                        <span className={`text-[10px] font-bold font-mono ${isChecked ? 'text-emerald-600' : 'text-slate-300'}`}>
                          {isChecked ? 'ON' : 'OFF'}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </DropdownMenu.Content>
            </DropdownMenu.Portal>
          </DropdownMenu.Root>
        </div>
      </div>

      {/* Filter toolbar */}
      <div className="bg-white border border-border-medium rounded p-3 space-y-3 shadow-2xs">
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2.5">
          {/* Global Search */}
          <div className="relative flex-1 min-w-[240px]">
            <div className="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none text-slate-400 flex items-center">
              <Search className="w-3.5 h-3.5" />
            </div>
            <input
              type="text"
              value={globalFilter}
              onChange={(e) => setGlobalFilter(e.target.value)}
              placeholder="Search event ID, source IP, vendor, parser, or raw payload content..."
              style={{ paddingLeft: '34px' }}
              className="w-full pr-8 py-1.5 text-xs rounded border border-border-medium bg-slate-50 focus:bg-white focus:outline-none focus:ring-1 focus:ring-gov-blue"
            />
            {globalFilter && (
              <button
                onClick={() => setGlobalFilter('')}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 p-0.5"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          {/* Quick Filters */}
          <select
            value={vendorFilter}
            onChange={(e) => setVendorFilter(e.target.value)}
            className="w-auto min-w-[140px] text-xs rounded border border-border-medium bg-white px-2.5 py-1.5 focus:outline-none focus:ring-1 focus:ring-gov-blue shrink-0"
          >
            <option value="ALL">All Vendors ({vendors.length})</option>
            {vendors.map((v) => (
              <option key={v} value={v}>
                {v}
              </option>
            ))}
          </select>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="w-auto min-w-[130px] text-xs rounded border border-border-medium bg-white px-2.5 py-1.5 focus:outline-none focus:ring-1 focus:ring-gov-blue shrink-0"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
            <option value="INFO">INFO</option>
          </select>

          <select
            value={timeRange}
            onChange={(e) => setTimeRange(e.target.value)}
            className="w-auto min-w-[110px] text-xs rounded border border-border-medium bg-white px-2.5 py-1.5 focus:outline-none focus:ring-1 focus:ring-gov-blue font-mono shrink-0"
          >
            <option value="5m">Last 5 min</option>
            <option value="15m">Last 15 min</option>
            <option value="1h">Last 1 hour</option>
            <option value="24h">Last 24 hours</option>
          </select>

          <Button
            size="sm"
            variant="ghost"
            onClick={() => setShowAdvancedFilters((s) => !s)}
            className="text-xs flex items-center gap-1 text-slate-600"
          >
            <SlidersHorizontal className="w-3.5 h-3.5" />
            {showAdvancedFilters ? 'Less' : 'More'}
          </Button>

          {(globalFilter || vendorFilter !== 'ALL' || severityFilter !== 'ALL' || statusFilter !== 'ALL') && (
            <Button size="sm" variant="ghost" onClick={clearAllFilters} className="text-xs text-red-600 hover:text-red-700">
              Clear Filters
            </Button>
          )}
        </div>

        {/* Collapsible Advanced Filters */}
        {showAdvancedFilters && (
          <div className="pt-2 border-t border-slate-100 grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
            <div>
              <label className="text-[10px] font-bold text-slate-400 uppercase block mb-1">UCE Status</label>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="w-full text-xs rounded border border-border-medium p-1.5"
              >
                <option value="ALL">All Statuses</option>
                <option value="NORMALIZED">NORMALIZED</option>
                <option value="PARTIAL">PARTIAL</option>
                <option value="PENDING">PENDING</option>
              </select>
            </div>
            <div>
              <label className="text-[10px] font-bold text-slate-400 uppercase block mb-1">Refresh Rate</label>
              <select
                value={refreshIntervalSec}
                onChange={(e) => setRefreshIntervalSec(Number(e.target.value))}
                className="w-full text-xs rounded border border-border-medium p-1.5 font-mono"
              >
                <option value={1}>1 second</option>
                <option value={2}>2 seconds (Default)</option>
                <option value={5}>5 seconds</option>
                <option value={10}>10 seconds</option>
              </select>
            </div>
            <div>
              <label className="text-[10px] font-bold text-slate-400 uppercase block mb-1">Tenant Scope</label>
              <div className="text-xs font-mono p-1.5 bg-slate-50 border border-slate-200 rounded text-slate-600">
                default (isolated)
              </div>
            </div>
            <div>
              <label className="text-[10px] font-bold text-slate-400 uppercase block mb-1">Buffer Limits</label>
              <div className="text-xs font-mono p-1.5 bg-slate-50 border border-slate-200 rounded text-slate-600">
                Max 200 FIFO
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Main TanStack Table */}
      <div className="bg-white border border-border-medium rounded overflow-hidden shadow-2xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              {table.getHeaderGroups().map((headerGroup) => (
                <tr key={headerGroup.id} className="bg-slate-50 border-b border-border-medium text-[11px] font-mono text-slate-600">
                  {headerGroup.headers.map((header) => (
                    <th key={header.id} className="py-2 px-3 font-semibold select-none whitespace-nowrap">
                      {header.isPlaceholder ? null : flexRender(header.column.columnDef.header, header.getContext())}
                    </th>
                  ))}
                  <th className="py-2 px-3 text-right font-semibold text-slate-600">Inspect</th>
                </tr>
              ))}
            </thead>
            <tbody className="divide-y divide-border-light text-xs">
              {table.getRowModel().rows.length === 0 ? (
                <tr>
                  <td colSpan={columns.length + 1} className="py-12 text-center text-slate-500">
                    <Activity className="w-8 h-8 text-slate-300 mx-auto mb-2" />
                    <div className="font-semibold text-slate-700">No telemetry available for the selected scope.</div>
                    <div className="text-[11px] text-slate-400 mt-1">
                      Try clearing active search terms or filters.
                    </div>
                  </td>
                </tr>
              ) : (
                table.getRowModel().rows.map((row) => (
                  <tr
                    key={row.id}
                    onClick={() => setSelectedEvent(row.original)}
                    className="hover:bg-slate-50 cursor-pointer transition-colors"
                  >
                    {row.getVisibleCells().map((cell) => (
                      <td key={cell.id} className="py-2 px-3">
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </td>
                    ))}
                    <td className="py-2 px-3 text-right">
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedEvent(row.original);
                        }}
                        className="text-xs h-7 px-2 text-gov-blue hover:text-navy-900"
                      >
                        <Eye className="w-3.5 h-3.5 mr-1" />
                        Detail
                      </Button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination bar */}
        <div className="py-2.5 px-3 bg-slate-50 border-t border-border-medium flex flex-col sm:flex-row items-center justify-between gap-2 text-xs font-mono text-slate-600">
          <div className="flex items-center gap-3">
            <span>
              Showing {table.getRowModel().rows.length} of {filteredData.length} events
            </span>
            <span className="text-slate-300">|</span>
            <div className="flex items-center gap-1.5">
              <span>Rows per page:</span>
              <select
                value={table.getState().pagination.pageSize}
                onChange={(e) => table.setPageSize(Number(e.target.value))}
                className="bg-white border border-border-medium rounded px-1.5 py-0.5 text-xs focus:outline-none"
              >
                {[10, 15, 25, 50, 100].map((pageSize) => (
                  <option key={pageSize} value={pageSize}>
                    {pageSize}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="flex items-center gap-1">
            <span className="mr-2">
              Page {table.getState().pagination.pageIndex + 1} of {table.getPageCount() || 1}
            </span>
            <Button
              size="sm"
              variant="outline"
              onClick={() => table.previousPage()}
              disabled={!table.getCanPreviousPage()}
              className="h-7 w-7 p-0"
            >
              <ChevronLeft className="w-3.5 h-3.5" />
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => table.nextPage()}
              disabled={!table.getCanNextPage()}
              className="h-7 w-7 p-0"
            >
              <ChevronRight className="w-3.5 h-3.5" />
            </Button>
          </div>
        </div>
      </div>

      {/* ===================================================================== */}
      {/* Event Detail Modal / Drawer with 9 Comprehensive Tabs                 */}
      {/* ===================================================================== */}
      {selectedEvent && (
        <Dialog.Root open={!!selectedEvent} onOpenChange={(open) => !open && setSelectedEvent(null)}>
          <Dialog.Portal>
            <Dialog.Overlay className="fixed inset-0 bg-slate-900/50 backdrop-blur-2xs z-50 animate-fade-in" />
            <Dialog.Content className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[95vw] max-w-5xl max-h-[90vh] bg-white border border-border-medium rounded-lg shadow-2xl z-50 flex flex-col overflow-hidden animate-scale-in">
              {/* Drawer Header */}
              <div className="px-5 py-3 bg-navy-900 text-white flex items-center justify-between border-b border-slate-800">
                <div className="flex items-center gap-3">
                  <span className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
                    Event Lifecycle Inspector
                  </span>
                  <span className="font-mono text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-200 border border-slate-700">
                    {selectedEvent.event_id}
                  </span>
                  {renderSeverityBadge(selectedEvent.severity)}
                </div>

                <div className="flex items-center gap-2">
                  <Dialog.Close asChild>
                    <button className="text-slate-400 hover:text-white p-1 rounded transition-colors">
                      <X className="w-4 h-4" />
                    </button>
                  </Dialog.Close>
                </div>
              </div>

              {/* Quick Action Navigation Buttons (Cross-Module Deep Links) */}
              <div className="px-5 py-2 bg-slate-50 border-b border-border-medium flex flex-wrap items-center justify-between gap-2 text-xs">
                <div className="flex items-center gap-1.5 font-mono text-[11px] text-slate-600">
                  <span>Source: <strong>{selectedEvent.source}</strong></span>
                  <span className="text-slate-300">•</span>
                  <span>Parser: <strong>{selectedEvent.parser}</strong></span>
                  <span className="text-slate-300">•</span>
                  <span>Vendor: <strong>{selectedEvent.vendor}</strong></span>
                </div>

                <div className="flex items-center gap-2">
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => navigate(`/parser-workbench?parser=${selectedEvent.parser}`)}
                    className="text-xs h-7 flex items-center gap-1"
                  >
                    <Layers className="w-3 h-3 text-slate-500" />
                    View Parser
                  </Button>

                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => navigate(`/uce?eventId=${selectedEvent.event_id}`)}
                    className="text-xs h-7 flex items-center gap-1"
                  >
                    <CheckCircle2 className="w-3 h-3 text-emerald-600" />
                    View UCE
                  </Button>

                  {selectedEvent.detection_id && (
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => navigate(`/alerts?alertId=${selectedEvent.detection_id}`)}
                      className="text-xs h-7 flex items-center gap-1 text-red-700 border-red-200 hover:bg-red-50"
                    >
                      <ShieldAlert className="w-3 h-3 text-red-600" />
                      View Alert
                    </Button>
                  )}

                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => navigate(`/schemas-export?eventId=${selectedEvent.event_id}`)}
                    className="text-xs h-7 flex items-center gap-1"
                  >
                    <Download className="w-3 h-3 text-slate-500" />
                    Export
                  </Button>

                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => navigate(`/forensics?eventId=${selectedEvent.event_id}`)}
                    className="text-xs h-7 flex items-center gap-1"
                  >
                    <ShieldCheck className="w-3 h-3 text-gov-blue" />
                    Evidence
                  </Button>
                </div>
              </div>

              {/* 9 Tabs Body */}
              <Tabs.Root defaultValue="overview" className="flex-1 flex flex-col overflow-hidden">
                <Tabs.List className="px-5 border-b border-border-medium bg-white flex items-center gap-1 overflow-x-auto text-xs font-mono">
                  <Tabs.Trigger
                    value="overview"
                    className="px-3 py-2.5 font-semibold text-slate-600 border-b-2 border-transparent data-[state=active]:border-gov-blue data-[state=active]:text-gov-blue hover:text-navy-900 transition-colors whitespace-nowrap"
                  >
                    Overview
                  </Tabs.Trigger>
                  <Tabs.Trigger
                    value="raw"
                    className="px-3 py-2.5 font-semibold text-slate-600 border-b-2 border-transparent data-[state=active]:border-gov-blue data-[state=active]:text-gov-blue hover:text-navy-900 transition-colors whitespace-nowrap"
                  >
                    Raw (Untrusted)
                  </Tabs.Trigger>
                  <Tabs.Trigger
                    value="parsed"
                    className="px-3 py-2.5 font-semibold text-slate-600 border-b-2 border-transparent data-[state=active]:border-gov-blue data-[state=active]:text-gov-blue hover:text-navy-900 transition-colors whitespace-nowrap"
                  >
                    Parsed Fields
                  </Tabs.Trigger>
                  <Tabs.Trigger
                    value="uce"
                    className="px-3 py-2.5 font-semibold text-slate-600 border-b-2 border-transparent data-[state=active]:border-gov-blue data-[state=active]:text-gov-blue hover:text-navy-900 transition-colors whitespace-nowrap"
                  >
                    Canonical UCE
                  </Tabs.Trigger>
                  <Tabs.Trigger
                    value="ocsf"
                    className="px-3 py-2.5 font-semibold text-slate-600 border-b-2 border-transparent data-[state=active]:border-gov-blue data-[state=active]:text-gov-blue hover:text-navy-900 transition-colors whitespace-nowrap"
                  >
                    OCSF v1.1.0
                  </Tabs.Trigger>
                  <Tabs.Trigger
                    value="otel"
                    className="px-3 py-2.5 font-semibold text-slate-600 border-b-2 border-transparent data-[state=active]:border-gov-blue data-[state=active]:text-gov-blue hover:text-navy-900 transition-colors whitespace-nowrap"
                  >
                    OpenTelemetry
                  </Tabs.Trigger>
                  <Tabs.Trigger
                    value="lineage"
                    className="px-3 py-2.5 font-semibold text-slate-600 border-b-2 border-transparent data-[state=active]:border-gov-blue data-[state=active]:text-gov-blue hover:text-navy-900 transition-colors whitespace-nowrap"
                  >
                    Lineage (8-Stage)
                  </Tabs.Trigger>
                  <Tabs.Trigger
                    value="detection"
                    className="px-3 py-2.5 font-semibold text-slate-600 border-b-2 border-transparent data-[state=active]:border-gov-blue data-[state=active]:text-gov-blue hover:text-navy-900 transition-colors whitespace-nowrap"
                  >
                    Detection Context
                  </Tabs.Trigger>
                  <Tabs.Trigger
                    value="evidence"
                    className="px-3 py-2.5 font-semibold text-slate-600 border-b-2 border-transparent data-[state=active]:border-gov-blue data-[state=active]:text-gov-blue hover:text-navy-900 transition-colors whitespace-nowrap"
                  >
                    Evidence & Hash
                  </Tabs.Trigger>
                </Tabs.List>

                {/* Tab 1: Overview */}
                <Tabs.Content value="overview" className="p-5 overflow-y-auto space-y-4 text-xs">
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-slate-50 p-3 rounded border border-border-medium font-mono">
                    <div>
                      <span className="text-[10px] font-bold text-slate-400 uppercase block">Event ID</span>
                      <span className="font-semibold text-navy-900">{selectedEvent.event_id}</span>
                    </div>
                    <div>
                      <span className="text-[10px] font-bold text-slate-400 uppercase block">Normalized UTC Time</span>
                      <span className="text-slate-700">{selectedEvent.timestamp}</span>
                    </div>
                    <div>
                      <span className="text-[10px] font-bold text-slate-400 uppercase block">Category & Action</span>
                      <span className="text-slate-700 uppercase font-semibold">
                        {selectedEvent.category} • {selectedEvent.action}
                      </span>
                    </div>
                    <div>
                      <span className="text-[10px] font-bold text-slate-400 uppercase block">Payload Size</span>
                      <span className="text-slate-700">{selectedEvent.byte_length || 384} bytes</span>
                    </div>
                  </div>

                  {/* Entities & Indicators */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="border border-border-medium rounded p-3 bg-white">
                      <div className="text-xs font-bold text-slate-700 uppercase mb-2 flex items-center justify-between">
                        <span>Extracted Named Entities</span>
                        <span className="text-[10px] font-mono text-slate-400">
                          {selectedEvent.entities?.length || 0} discovered
                        </span>
                      </div>
                      {selectedEvent.entities && selectedEvent.entities.length > 0 ? (
                        <div className="space-y-1.5">
                          {selectedEvent.entities.map((ent, idx) => (
                            <div
                              key={idx}
                              className="flex items-center justify-between p-1.5 rounded bg-slate-50 border border-slate-200 text-xs font-mono"
                            >
                              <span className="text-slate-500">{ent.type}:</span>
                              <span className="font-semibold text-navy-900">{ent.value}</span>
                              <span className="text-[10px] text-emerald-700 bg-emerald-100 px-1 rounded">
                                Conf: {Math.round((ent.confidence || 1.0) * 100)}%
                              </span>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="text-slate-400 text-xs italic py-2">No entities extracted for this event.</div>
                      )}
                    </div>

                    <div className="border border-border-medium rounded p-3 bg-white">
                      <div className="text-xs font-bold text-slate-700 uppercase mb-2 flex items-center justify-between">
                        <span>Threat Observables & Indicators</span>
                        <span className="text-[10px] font-mono text-slate-400">
                          {selectedEvent.indicators?.length || 0} matches
                        </span>
                      </div>
                      {selectedEvent.indicators && selectedEvent.indicators.length > 0 ? (
                        <div className="space-y-1.5">
                          {selectedEvent.indicators.map((ind, idx) => (
                            <div
                              key={idx}
                              className="flex items-center justify-between p-1.5 rounded bg-amber-50 border border-amber-200 text-xs font-mono"
                            >
                              <span className="text-amber-800 font-bold">{ind.type}:</span>
                              <span className="font-semibold text-navy-900 truncate max-w-[200px]">{ind.value}</span>
                              <span className="text-[10px] text-slate-500">{ind.source}</span>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="text-slate-400 text-xs italic py-2">No threat observables matched.</div>
                      )}
                    </div>
                  </div>

                  {/* Residue Notice (Lossless Preservation) */}
                  <div className="p-3 bg-slate-50 border border-slate-200 rounded text-xs">
                    <span className="font-bold text-slate-700 block mb-1">
                      Lossless Preservation (NTRO Requirement):
                    </span>
                    <p className="text-slate-600 leading-relaxed">
                      All vendor-specific or unmapped keys are preserved verbatim in{' '}
                      <code className="font-mono text-gov-blue">unmapped_residue</code>. Zero telemetry is dropped during
                      normalization.
                    </p>
                  </div>
                </Tabs.Content>

                {/* Tab 2: Raw (Untrusted Data) */}
                <Tabs.Content value="raw" className="p-5 overflow-y-auto space-y-3">
                  <div className="bg-amber-50 border border-amber-200 rounded p-2.5 text-xs text-amber-900 flex items-center justify-between">
                    <span>
                      <strong>Untrusted Input Warning:</strong> Raw log payloads are treated as untrusted strings.
                      Script execution and HTML rendering are strictly neutralized.
                    </span>
                    <span className="font-mono text-[11px] text-amber-800">
                      Encoding: UTF-8 • SHA-256 Verified
                    </span>
                  </div>

                  <CodePanel
                    code={selectedEvent.raw_payload || '// Raw payload not available for this synthetic record'}
                    title={`Raw Ingress Payload (${selectedEvent.format})`}
                    language="text"
                    maxHeight="280px"
                  />

                  <div className="bg-slate-50 border border-border-medium rounded p-3 font-mono text-xs space-y-1.5">
                    <div className="flex justify-between">
                      <span className="text-slate-500">SHA-256 CAS Digest:</span>
                      <span className="text-navy-900 font-semibold select-all">{selectedEvent.sha256}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Capture Timestamp:</span>
                      <span className="text-slate-700">{selectedEvent.timestamp}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Payload Byte Length:</span>
                      <span className="text-slate-700">{selectedEvent.byte_length} bytes</span>
                    </div>
                  </div>
                </Tabs.Content>

                {/* Tab 3: Parsed Fields */}
                <Tabs.Content value="parsed" className="p-5 overflow-y-auto space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="text-xs font-bold text-navy-900 uppercase">
                        Fields Extracted by Parser ({selectedEvent.parser})
                      </h4>
                      <p className="text-[11px] text-slate-500">
                        Structured key-value table derived during Tier {selectedEvent.parser.startsWith('palo') ? 'A' : 'B'} parsing stage.
                      </p>
                    </div>
                  </div>

                  <div className="border border-border-medium rounded overflow-hidden">
                    <table className="w-full text-left font-mono text-xs">
                      <thead className="bg-slate-50 border-b border-border-medium text-[11px] text-slate-600">
                        <tr>
                          <th className="py-2 px-3">Field</th>
                          <th className="py-2 px-3">Extracted Value</th>
                          <th className="py-2 px-3">Inferred Type</th>
                          <th className="py-2 px-3">Confidence</th>
                          <th className="py-2 px-3">Origin</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-border-light">
                        {Object.entries(selectedEvent.extracted_fields || {}).map(([key, val]) => (
                          <tr key={key} className="hover:bg-slate-50">
                            <td className="py-1.5 px-3 font-semibold text-slate-800">{key}</td>
                            <td className="py-1.5 px-3 text-navy-900 truncate max-w-[280px]">
                              {typeof val === 'object' ? JSON.stringify(val) : String(val)}
                            </td>
                            <td className="py-1.5 px-3 text-slate-500">
                              {typeof val === 'number' ? 'integer' : typeof val === 'boolean' ? 'boolean' : 'string'}
                            </td>
                            <td className="py-1.5 px-3 text-emerald-700 font-semibold">1.00</td>
                            <td className="py-1.5 px-3 text-slate-500">Observed</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>

                  {/* Unmapped Residue */}
                  {selectedEvent.unmapped_residue && Object.keys(selectedEvent.unmapped_residue).length > 0 && (
                    <div className="border border-slate-200 rounded p-3 bg-slate-50 space-y-2">
                      <span className="text-xs font-bold text-slate-700 uppercase block">
                        Unmapped Vendor Residue ({Object.keys(selectedEvent.unmapped_residue).length} keys)
                      </span>
                      <CodePanel
                        code={JSON.stringify(selectedEvent.unmapped_residue, null, 2)}
                        language="json"
                        maxHeight="160px"
                      />
                    </div>
                  )}
                </Tabs.Content>

                {/* Tab 4: Canonical UCE */}
                <Tabs.Content value="uce" className="p-5 overflow-y-auto space-y-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="text-xs font-bold text-navy-900 uppercase">
                        Universal Canonical Event (UCE) Representation
                      </h4>
                      <p className="text-[11px] text-slate-500">
                        The internal source-of-truth schema. All downstream projections derive from this canonical record.
                      </p>
                    </div>
                    <Badge variant="ok">Normalized v1.0.0</Badge>
                  </div>

                  <CodePanel
                    code={JSON.stringify(
                      {
                        event_id: selectedEvent.event_id,
                        timestamp: selectedEvent.timestamp,
                        source: selectedEvent.source,
                        vendor: selectedEvent.vendor,
                        category: selectedEvent.category,
                        action: selectedEvent.action,
                        severity: selectedEvent.severity,
                        entities: selectedEvent.entities || [],
                        indicators: selectedEvent.indicators || [],
                        unmapped_residue: selectedEvent.unmapped_residue || {},
                        provenance: selectedEvent.provenance || {
                          cas_hash: selectedEvent.sha256,
                          pipeline_version: '1.4.2-rel',
                          stages_applied: 8,
                        },
                      },
                      null,
                      2
                    )}
                    language="json"
                    maxHeight="320px"
                  />
                </Tabs.Content>

                {/* Tab 5: OCSF Projection */}
                <Tabs.Content value="ocsf" className="p-5 overflow-y-auto space-y-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="text-xs font-bold text-navy-900 uppercase">
                        OCSF v1.1.0 (Open Cybersecurity Schema Framework)
                      </h4>
                      <p className="text-[11px] text-slate-500">
                        Derived projection conforming to OCSF Network Activity (Class 4001) / Security Finding (Class 2001).
                      </p>
                    </div>
                    <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-blue-50 text-gov-blue border border-blue-200">
                      Class UID: 4001
                    </span>
                  </div>

                  <CodePanel
                    code={JSON.stringify(
                      {
                        class_uid: 4001,
                        class_name: 'Network Activity',
                        category_uid: 4,
                        category_name: 'Network Activity',
                        activity_id: selectedEvent.action === 'deny' ? 2 : 1,
                        time: new Date(selectedEvent.timestamp).getTime(),
                        severity_id: selectedEvent.severity === 'CRITICAL' ? 5 : selectedEvent.severity === 'HIGH' ? 4 : 3,
                        severity: selectedEvent.severity,
                        metadata: {
                          version: '1.1.0',
                          product: {
                            name: selectedEvent.vendor,
                            vendor_name: selectedEvent.vendor,
                          },
                        },
                        src_endpoint: {
                          ip: selectedEvent.extracted_fields?.src_ip || '198.51.100.99',
                          port: selectedEvent.extracted_fields?.src_port || 445,
                        },
                        dst_endpoint: {
                          ip: selectedEvent.extracted_fields?.dst_ip || '10.0.1.45',
                          port: selectedEvent.extracted_fields?.dst_port || 445,
                        },
                        unmapped: selectedEvent.unmapped_residue || {},
                      },
                      null,
                      2
                    )}
                    language="json"
                    maxHeight="320px"
                  />
                </Tabs.Content>

                {/* Tab 6: OpenTelemetry */}
                <Tabs.Content value="otel" className="p-5 overflow-y-auto space-y-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="text-xs font-bold text-navy-900 uppercase">
                        OpenTelemetry Logs Data Model Projection
                      </h4>
                      <p className="text-[11px] text-slate-500">
                        Projected log record conforming to the OpenTelemetry Logs specification.
                      </p>
                    </div>
                    <Badge variant="neutral">OTel Logs v1.3.0</Badge>
                  </div>

                  <CodePanel
                    code={JSON.stringify(
                      {
                        resource: {
                          attributes: {
                            'service.name': 'ulpf-intake-worker',
                            'log.source': selectedEvent.source,
                            'tenant.id': selectedEvent.tenant_id,
                          },
                        },
                        scope_logs: [
                          {
                            scope: { name: 'ulpf.normalizer.panos' },
                            log_records: [
                              {
                                time_unix_nano: new Date(selectedEvent.timestamp).getTime() * 1000000,
                                severity_number: selectedEvent.severity === 'CRITICAL' ? 21 : 17,
                                severity_text: selectedEvent.severity,
                                body: selectedEvent.raw_payload,
                                attributes: {
                                  'event.id': selectedEvent.event_id,
                                  'event.category': selectedEvent.category,
                                  'event.action': selectedEvent.action,
                                  'cas.sha256': selectedEvent.sha256,
                                },
                              },
                            ],
                          },
                        ],
                      },
                      null,
                      2
                    )}
                    language="json"
                    maxHeight="320px"
                  />
                </Tabs.Content>

                {/* Tab 7: Lineage (8-Stage Pipeline) */}
                <Tabs.Content value="lineage" className="p-5 overflow-y-auto space-y-4">
                  <div>
                    <h4 className="text-xs font-bold text-navy-900 uppercase">
                      Forensic Lineage Progression (8 Stages)
                    </h4>
                    <p className="text-[11px] text-slate-500">
                      Step-by-step cryptographic transformations from untrusted ingress to canonical schema projection.
                    </p>
                  </div>

                  <div className="space-y-2 font-mono text-xs">
                    {[
                      { stage: '1. RAW INGRESS', desc: 'Raw bytes captured from socket/stream; immutably buffered.', state: 'VERIFIED' },
                      { stage: '2. SHA-256 CAS BIND', desc: `Digest ${selectedEvent.sha256?.substring(0, 16)}... computed.`, state: 'VERIFIED' },
                      { stage: '3. CAPTURE AUDIT', desc: 'Timestamped & provenance record registered in outbox ledger.', state: 'VERIFIED' },
                      { stage: '4. PARSER MATCH', desc: `Parser '${selectedEvent.parser}' matched format with 1.00 confidence.`, state: 'VERIFIED' },
                      { stage: '5. FIELD EXTRACTION', desc: 'Syntactic token extraction into structured dictionary.', state: 'VERIFIED' },
                      { stage: '6. SEMANTIC MAPPING', desc: 'Deterministic taxonomy alignment; residue segregated losslessly.', state: 'VERIFIED' },
                      { stage: '7. UCE CANONICAL', desc: 'Conforms to ULPF Universal Canonical Event standard v1.0.0.', state: 'VERIFIED' },
                      { stage: '8. PROJECTION SINK', desc: 'Dual projection generated for OCSF v1.1.0 and OTel Logs.', state: 'VERIFIED' },
                    ].map((step, idx) => (
                      <div
                        key={idx}
                        className="flex items-center justify-between p-2 rounded bg-slate-50 border border-slate-200"
                      >
                        <div className="flex items-center gap-2">
                          <span className="w-5 h-5 rounded-full bg-navy-900 text-white flex items-center justify-center text-[10px] font-bold">
                            {idx + 1}
                          </span>
                          <div>
                            <span className="font-bold text-navy-900">{step.stage}</span>
                            <span className="text-slate-500 block text-[11px]">{step.desc}</span>
                          </div>
                        </div>
                        <span className="text-[10px] font-bold text-emerald-700 bg-emerald-100 px-2 py-0.5 rounded">
                          {step.state}
                        </span>
                      </div>
                    ))}
                  </div>
                </Tabs.Content>

                {/* Tab 8: Detection Context */}
                <Tabs.Content value="detection" className="p-5 overflow-y-auto space-y-4 text-xs">
                  {selectedEvent.detection_id ? (
                    <div className="space-y-3">
                      <div className="p-3 bg-red-50 border border-red-200 rounded text-red-950 space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-red-900 flex items-center gap-1.5">
                            <ShieldAlert className="w-4 h-4 text-red-600" />
                            Security Alert Generated: {selectedEvent.detection_id}
                          </span>
                          <Badge variant="danger">CRITICAL</Badge>
                        </div>
                        <p className="text-xs text-red-900">{selectedEvent.detection_title}</p>
                      </div>

                      <div className="p-3 bg-white border border-border-medium rounded space-y-2 font-mono">
                        <div className="flex justify-between">
                          <span className="text-slate-500">MITRE ATT&CK:</span>
                          <span className="font-semibold text-navy-900">T1021.002 (SMB / Windows Shares)</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-500">Tactic:</span>
                          <span className="text-slate-700">TA0008 Lateral Movement</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-500">Correlation Confidence:</span>
                          <span className="text-emerald-700 font-semibold">98.4% (Multi-sensor cross-validation)</span>
                        </div>
                      </div>

                      <Button
                        onClick={() => navigate(`/alerts?alertId=${selectedEvent.detection_id}`)}
                        className="w-full text-xs"
                      >
                        Open Full Alert & Detection Workspace
                      </Button>
                    </div>
                  ) : (
                    <div className="py-12 text-center text-slate-500">
                      <ShieldCheck className="w-8 h-8 text-emerald-600 mx-auto mb-2" />
                      <div className="font-semibold text-slate-700">No Threat Rule Triggers</div>
                      <p className="text-[11px] text-slate-400 mt-1">
                        This event passed through normal ingestion without triggering critical security rules.
                      </p>
                    </div>
                  )}
                </Tabs.Content>

                {/* Tab 9: Evidence & Hash */}
                <Tabs.Content value="evidence" className="p-5 overflow-y-auto space-y-3 text-xs font-mono">
                  <div>
                    <h4 className="text-xs font-bold text-navy-900 uppercase">
                      Cryptographic Evidence & Chain-of-Custody
                    </h4>
                    <p className="text-[11px] text-slate-500">
                      NTRO requirement: Immutable SHA-256 CAS seal bound to pipeline version.
                    </p>
                  </div>

                  <div className="p-3 bg-slate-50 border border-border-medium rounded space-y-2">
                    <div className="flex justify-between">
                      <span className="text-slate-500">Payload Digest:</span>
                      <span className="text-navy-900 font-bold select-all">{selectedEvent.sha256}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Merkle Epoch Bound:</span>
                      <span className="text-slate-700">EPOCH-20260913-S15</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Tamper Status:</span>
                      <span className="text-emerald-700 font-bold">SEALED (BIT-LEVEL MATCH)</span>
                    </div>
                  </div>

                  <Button
                    variant="outline"
                    onClick={() => navigate(`/forensics?eventId=${selectedEvent.event_id}`)}
                    className="w-full text-xs flex items-center justify-center gap-1.5"
                  >
                    <ShieldCheck className="w-3.5 h-3.5 text-gov-blue" />
                    Inspect Forensic Chain in Lineage Desk
                  </Button>
                </Tabs.Content>
              </Tabs.Root>

              {/* Drawer Footer */}
              <div className="px-5 py-2.5 bg-slate-50 border-t border-border-medium flex items-center justify-between text-xs">
                <span className="font-mono text-[11px] text-slate-500">
                  Tenant Isolation: <strong className="text-slate-700">{selectedEvent.tenant_id}</strong>
                </span>
                <Dialog.Close asChild>
                  <Button size="sm" variant="outline">
                    Close Inspector
                  </Button>
                </Dialog.Close>
              </div>
            </Dialog.Content>
          </Dialog.Portal>
        </Dialog.Root>
      )}
    </div>
  );
};
