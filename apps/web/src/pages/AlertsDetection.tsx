import React, { useState, useMemo, useCallback, useEffect } from 'react';
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
  PaginationState,
} from '@tanstack/react-table';
import * as Dialog from '@radix-ui/react-dialog';
import {
  AlertTriangle,
  ArrowUpDown,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Crosshair,
  ExternalLink,
  Eye,
  FileCheck,
  Filter,
  Flame,
  HelpCircle,
  Info,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  X,
  Zap,
} from 'lucide-react';

import { AlertItem } from '../api/operations';
import { INITIAL_ALERTS } from '../demo/telemetryEvents';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { CodePanel } from '../components/ui/CodePanel';

export const AlertsDetection: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const requestedAlertId = searchParams.get('alertId');

  const [alerts, setAlerts] = useState<AlertItem[]>(() => {
    try {
      const stored = localStorage.getItem('ulpf_acknowledged_incidents');
      if (stored) {
        const ackedList: string[] = JSON.parse(stored);
        const ackedSet = new Set(ackedList);
        return INITIAL_ALERTS.map((a) =>
          ackedSet.has(a.alert_id) ? { ...a, status: 'ACKNOWLEDGED' as const } : a
        );
      }
    } catch {}
    return INITIAL_ALERTS;
  });
  const [selectedAlert, setSelectedAlert] = useState<AlertItem | null>(null);

  // Cross-feature incident acknowledgment listener from Command Center
  useEffect(() => {
    const handleRemoteAck = (e: Event) => {
      const customEvent = e as CustomEvent<{ id: string }>;
      if (customEvent.detail?.id) {
        const ackId = customEvent.detail.id;
        setAlerts((prev) =>
          prev.map((item) =>
            item.alert_id === ackId || item.event_id === ackId
              ? { ...item, status: 'ACKNOWLEDGED' as const }
              : item
          )
        );
      }
    };
    window.addEventListener('ulpf:incident_acknowledged', handleRemoteAck);
    return () => window.removeEventListener('ulpf:incident_acknowledged', handleRemoteAck);
  }, []);

  // Filters
  const [globalFilter, setGlobalFilter] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [sourceFilter, setSourceFilter] = useState<string>('ALL');

  // Sorting
  const [sorting, setSorting] = useState<SortingState>([{ id: 'timestamp', desc: true }]);

  // Pagination (controlled for reactive page navigation)
  const [pagination, setPagination] = useState<PaginationState>({ pageIndex: 0, pageSize: 5 });

  // Reset to first page whenever search or filters change
  useEffect(() => {
    setPagination((prev) => ({ ...prev, pageIndex: 0 }));
  }, [globalFilter, severityFilter, statusFilter, sourceFilter]);

  // Safe triage notification message
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  useEffect(() => {
    if (requestedAlertId) {
      const match = alerts.find((a) => a.alert_id === requestedAlertId);
      if (match) setSelectedAlert(match);
    }
  }, [requestedAlertId, alerts]);

  // Handle status update with cross-feature sync
  const handleUpdateStatus = useCallback((alertId: string, newStatus: AlertItem['status']) => {
    setAlerts((prev) =>
      prev.map((item) => (item.alert_id === alertId ? { ...item, status: newStatus } : item))
    );
    if (selectedAlert?.alert_id === alertId) {
      setSelectedAlert((prev) => (prev ? { ...prev, status: newStatus } : null));
    }

    if (newStatus === 'ACKNOWLEDGED' || newStatus === 'RESOLVED') {
      try {
        const stored = localStorage.getItem('ulpf_acknowledged_incidents');
        const acked: string[] = stored ? JSON.parse(stored) : [];
        if (!acked.includes(alertId)) {
          acked.push(alertId);
          localStorage.setItem('ulpf_acknowledged_incidents', JSON.stringify(acked));
        }
        window.dispatchEvent(new CustomEvent('ulpf:incident_acknowledged', { detail: { id: alertId } }));
      } catch {}
    }

    setActionNotice(`[DRY RUN] Alert ${alertId} updated to status '${newStatus}'. Safe orchestration verified.`);
    setTimeout(() => setActionNotice(null), 4000);
  }, [selectedAlert]);

  const filteredData = useMemo(() => {
    return alerts.filter((a) => {
      if (severityFilter !== 'ALL' && a.severity !== severityFilter) return false;
      if (statusFilter !== 'ALL' && a.status !== statusFilter) return false;
      if (sourceFilter !== 'ALL' && a.source !== sourceFilter) return false;
      if (globalFilter.trim()) {
        const q = globalFilter.toLowerCase();
        const match =
          a.alert_id.toLowerCase().includes(q) ||
          a.title.toLowerCase().includes(q) ||
          a.entity.toLowerCase().includes(q) ||
          a.source.toLowerCase().includes(q) ||
          (a.mitre_technique && a.mitre_technique.toLowerCase().includes(q)) ||
          (a.mitre_id && a.mitre_id.toLowerCase().includes(q));
        if (!match) return false;
      }
      return true;
    });
  }, [alerts, severityFilter, statusFilter, sourceFilter, globalFilter]);

  const columns = useMemo<ColumnDef<AlertItem>[]>(
    () => [
      {
        accessorKey: 'severity',
        header: 'Severity',
        cell: (info) => {
          const s = info.getValue() as string;
          switch (s) {
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
        },
      },
      {
        accessorKey: 'alert_id',
        header: 'Alert ID',
        cell: (info) => (
          <span className="font-mono text-[11px] font-semibold text-gov-blue hover:underline">
            {info.getValue() as string}
          </span>
        ),
      },
      {
        accessorKey: 'title',
        header: 'Detection Title',
        cell: (info) => (
          <div className="max-w-[260px]">
            <span className="font-semibold text-navy-900 block text-xs">{info.getValue() as string}</span>
            <span className="text-[10px] text-slate-500 truncate block">
              {info.row.original.rule_name || 'Standard Detection Rule'}
            </span>
          </div>
        ),
      },
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
        accessorKey: 'source',
        header: 'Originating Source',
        cell: (info) => (
          <span className="text-[11px] font-mono text-slate-600 truncate max-w-[130px] block" title={info.getValue() as string}>
            {info.getValue() as string}
          </span>
        ),
      },
      {
        accessorKey: 'entity',
        header: 'Impacted Entity',
        cell: (info) => (
          <span className="font-mono text-[11px] text-navy-900 font-semibold truncate max-w-[160px] block">
            {info.getValue() as string}
          </span>
        ),
      },
      {
        accessorKey: 'mitre_id',
        header: 'MITRE ATT&CK',
        cell: (info) => {
          const id = info.getValue() as string;
          return (
            <div className="font-mono text-[10.5px]">
              <span className="font-bold text-slate-800">{id || 'T1059'}</span>
              <span className="text-slate-400 block truncate max-w-[140px]">
                {info.row.original.mitre_technique}
              </span>
            </div>
          );
        },
      },
      {
        accessorKey: 'confidence',
        header: 'Confidence',
        cell: (info) => (
          <span className="text-[11px] font-mono font-semibold text-emerald-700 bg-emerald-50 px-1.5 py-0.5 rounded border border-emerald-200">
            {info.getValue() as string}
          </span>
        ),
      },
      {
        accessorKey: 'status',
        header: 'Triage Status',
        cell: (info) => {
          const st = info.getValue() as string;
          const isNew = st === 'NEW';
          const isInvestigating = st === 'INVESTIGATING';
          return (
            <span
              className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded border font-bold ${
                isNew
                  ? 'bg-red-50 text-red-700 border-red-200'
                  : isInvestigating
                  ? 'bg-amber-50 text-amber-800 border-amber-200'
                  : 'bg-slate-100 text-slate-700 border-slate-200'
              }`}
            >
              {st}
            </span>
          );
        },
      },
    ],
    []
  );

  const table = useReactTable({
    data: filteredData,
    columns,
    state: { sorting, pagination },
    onSortingChange: setSorting,
    onPaginationChange: setPagination,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
  });

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="pb-3 border-b border-border-medium flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-sm font-bold text-navy-900 uppercase tracking-wide">Alerts & Detection</h1>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-300">
              Correlated Engine: Active
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Detections generated from normalized telemetry and security analytics. Grounded explainability and deterministic rule matches.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            size="sm"
            variant="outline"
            onClick={() => navigate('/investigation')}
            className="text-xs flex items-center gap-1.5"
          >
            <Crosshair className="w-3.5 h-3.5 text-slate-600" />
            Investigation Desk
          </Button>
          <Button
            size="sm"
            variant="outline"
            onClick={() => navigate('/threat-detection')}
            className="text-xs flex items-center gap-1.5"
          >
            <ShieldAlert className="w-3.5 h-3.5 text-slate-600" />
            Threat Rules
          </Button>
        </div>
      </div>

      {/* Action Notification Banner */}
      {actionNotice && (
        <div className="p-2.5 rounded bg-blue-50 border border-blue-200 text-xs text-blue-900 flex items-center justify-between font-mono animate-fade-in">
          <span>{actionNotice}</span>
          <span className="text-[10px] bg-blue-200 px-1.5 py-0.5 rounded text-blue-800 font-bold">
            DRY RUN / NO EXTERNAL IMPACT
          </span>
        </div>
      )}

      {/* Filtering Toolbar */}
      <div className="bg-white border border-border-medium rounded p-3 flex flex-col sm:flex-row items-stretch sm:items-center gap-2.5 shadow-2xs">
        <div className="relative flex-1 min-w-[260px]">
          <div className="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none text-slate-400 flex items-center">
            <Search className="w-3.5 h-3.5" />
          </div>
          <input
            type="text"
            value={globalFilter}
            onChange={(e) => setGlobalFilter(e.target.value)}
            placeholder="Search detection title, alert ID, affected entity, or MITRE ID..."
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

        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="w-auto min-w-[140px] text-xs rounded border border-border-medium bg-white px-2.5 py-1.5 focus:outline-none focus:ring-1 focus:ring-gov-blue shrink-0"
        >
          <option value="ALL">All Severities</option>
          <option value="CRITICAL">CRITICAL</option>
          <option value="HIGH">HIGH</option>
          <option value="MEDIUM">MEDIUM</option>
          <option value="LOW">LOW</option>
        </select>

        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="w-auto min-w-[150px] text-xs rounded border border-border-medium bg-white px-2.5 py-1.5 focus:outline-none focus:ring-1 focus:ring-gov-blue shrink-0"
        >
          <option value="ALL">All Statuses</option>
          <option value="NEW">NEW</option>
          <option value="ACKNOWLEDGED">ACKNOWLEDGED</option>
          <option value="INVESTIGATING">INVESTIGATING</option>
          <option value="SUPPRESSED">SUPPRESSED</option>
          <option value="RESOLVED">RESOLVED</option>
        </select>

        {(globalFilter || severityFilter !== 'ALL' || statusFilter !== 'ALL') && (
          <Button
            size="sm"
            variant="ghost"
            onClick={() => {
              setGlobalFilter('');
              setSeverityFilter('ALL');
              setStatusFilter('ALL');
            }}
            className="text-xs text-red-600 hover:text-red-700"
          >
            Clear
          </Button>
        )}
      </div>

      {/* TanStack Table */}
      <div className="bg-white border border-border-medium rounded overflow-hidden shadow-2xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              {table.getHeaderGroups().map((headerGroup) => (
                <tr key={headerGroup.id} className="bg-slate-50 border-b border-border-medium text-[11px] font-mono text-slate-600">
                  {headerGroup.headers.map((header) => (
                    <th key={header.id} className="py-2 px-3 font-semibold whitespace-nowrap">
                      {header.isPlaceholder ? null : flexRender(header.column.columnDef.header, header.getContext())}
                    </th>
                  ))}
                  <th className="py-2 px-3 text-right font-semibold">Triage</th>
                </tr>
              ))}
            </thead>
            <tbody className="divide-y divide-border-light text-xs">
              {table.getRowModel().rows.length === 0 ? (
                <tr>
                  <td colSpan={columns.length + 1} className="py-12 text-center text-slate-500">
                    <ShieldCheck className="w-8 h-8 text-slate-300 mx-auto mb-2" />
                    <div className="font-semibold text-slate-700">No active detections match the current filters.</div>
                    <div className="text-[11px] text-slate-400 mt-1">All telemetry is within baseline operational thresholds.</div>
                  </td>
                </tr>
              ) : (
                table.getRowModel().rows.map((row) => (
                  <tr
                    key={row.id}
                    onClick={() => setSelectedAlert(row.original)}
                    className="hover:bg-slate-50 cursor-pointer transition-colors"
                  >
                    {row.getVisibleCells().map((cell) => (
                      <td key={cell.id} className="py-2.5 px-3">
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </td>
                    ))}
                    <td className="py-2.5 px-3 text-right">
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedAlert(row.original);
                        }}
                        className="text-xs h-7 px-2 text-gov-blue hover:text-navy-900"
                      >
                        <Eye className="w-3.5 h-3.5 mr-1" />
                        Inspect
                      </Button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination bar */}
        <div className="py-2.5 px-4 bg-slate-50 border-t border-border-medium flex flex-col sm:flex-row items-center justify-between gap-3 text-xs font-mono text-slate-600">
          <div className="flex items-center gap-3">
            <span>
              Showing {filteredData.length === 0 ? 0 : pagination.pageIndex * pagination.pageSize + 1}–
              {Math.min((pagination.pageIndex + 1) * pagination.pageSize, filteredData.length)} of {filteredData.length} detections
            </span>
            <div className="flex items-center gap-1.5 font-sans text-slate-500">
              <span className="text-[11px] font-mono">Show:</span>
              <select
                value={pagination.pageSize}
                onChange={(e) => table.setPageSize(Number(e.target.value))}
                className="bg-white border border-slate-300 rounded px-2 py-0.5 text-xs font-mono text-navy-900 focus:outline-none focus:ring-1 focus:ring-gov-blue cursor-pointer"
                title="Select detections per page"
              >
                {[5, 10, 20].map((sz) => (
                  <option key={sz} value={sz}>
                    {sz} rows
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="flex items-center gap-1.5">
            <span className="text-slate-500 mr-2 text-[11px] font-mono">
              Page {table.getPageCount() === 0 ? 0 : pagination.pageIndex + 1} of {table.getPageCount()}
            </span>

            <Button
              size="sm"
              variant="outline"
              onClick={() => table.previousPage()}
              disabled={!table.getCanPreviousPage()}
              className="h-7 w-7 p-0 flex items-center justify-center hover:bg-slate-100 disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
              title="Previous page"
              aria-label="Previous page"
            >
              <ChevronLeft className="w-4 h-4 text-slate-700" />
            </Button>

            {Array.from({ length: table.getPageCount() }, (_, i) => i).map((p) => (
              <button
                key={p}
                type="button"
                onClick={() => table.setPageIndex(p)}
                className={`h-7 w-7 rounded text-xs font-mono font-bold transition-all border cursor-pointer ${
                  pagination.pageIndex === p
                    ? '!bg-gov-blue !text-white !border-gov-blue shadow-xs'
                    : 'bg-white text-slate-700 border-slate-300 hover:bg-slate-100'
                }`}
                title={`Go to page ${p + 1}`}
                aria-label={`Go to page ${p + 1}`}
                aria-current={pagination.pageIndex === p ? 'page' : undefined}
              >
                {p + 1}
              </button>
            ))}

            <Button
              size="sm"
              variant="outline"
              onClick={() => table.nextPage()}
              disabled={!table.getCanNextPage()}
              className="h-7 w-7 p-0 flex items-center justify-center hover:bg-slate-100 disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
              title="Next page"
              aria-label="Next page"
            >
              <ChevronRight className="w-4 h-4 text-slate-700" />
            </Button>
          </div>
        </div>
      </div>

      {/* ===================================================================== */}
      {/* Alert Detail Modal with Grounded Explainability                       */}
      {/* ===================================================================== */}
      {selectedAlert && (
        <Dialog.Root open={!!selectedAlert} onOpenChange={(open) => !open && setSelectedAlert(null)}>
          <Dialog.Portal>
            <Dialog.Overlay className="fixed inset-0 bg-slate-900/50 backdrop-blur-2xs z-50 animate-fade-in" />
            <Dialog.Content className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[95vw] max-w-4xl max-h-[90vh] bg-white border border-border-medium rounded-lg shadow-2xl z-50 flex flex-col overflow-hidden animate-scale-in">
              {/* Header */}
              <div className="px-5 py-3 bg-navy-900 text-white flex items-center justify-between border-b border-slate-800">
                <div className="flex items-center gap-3">
                  <span className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
                    Detection Dossier
                  </span>
                  <span className="font-mono text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-200 border border-slate-700">
                    {selectedAlert.alert_id}
                  </span>
                  <Badge variant={selectedAlert.severity === 'CRITICAL' || selectedAlert.severity === 'HIGH' ? 'danger' : selectedAlert.severity === 'MEDIUM' ? 'warn' : 'info'}>
                    {selectedAlert.severity}
                  </Badge>
                </div>
                <Dialog.Close asChild>
                  <button className="text-slate-400 hover:text-white p-1 rounded transition-colors">
                    <X className="w-4 h-4" />
                  </button>
                </Dialog.Close>
              </div>

              {/* Triage Status Bar */}
              <div className="px-5 py-2.5 bg-slate-50 border-b border-border-medium flex flex-wrap items-center justify-between gap-2 text-xs">
                <div className="flex items-center gap-2">
                  <span className="text-slate-500">Current Status:</span>
                  <span className="font-bold text-navy-900 font-mono uppercase">{selectedAlert.status}</span>
                  <span className="text-slate-300">•</span>
                  <span className="text-slate-500">Confidence:</span>
                  <span className="font-bold text-emerald-700 font-mono">{selectedAlert.confidence}</span>
                </div>

                {/* Safe Triage Operations Buttons */}
                <div className="flex items-center gap-1.5">
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => handleUpdateStatus(selectedAlert.alert_id, 'ACKNOWLEDGED')}
                    disabled={selectedAlert.status === 'ACKNOWLEDGED'}
                    className="text-xs h-7"
                  >
                    Acknowledge
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => handleUpdateStatus(selectedAlert.alert_id, 'INVESTIGATING')}
                    disabled={selectedAlert.status === 'INVESTIGATING'}
                    className="text-xs h-7"
                  >
                    Investigate
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => handleUpdateStatus(selectedAlert.alert_id, 'SUPPRESSED')}
                    disabled={selectedAlert.status === 'SUPPRESSED'}
                    className="text-xs h-7 text-slate-500 hover:text-red-700"
                  >
                    Suppress
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => handleUpdateStatus(selectedAlert.alert_id, 'RESOLVED')}
                    disabled={selectedAlert.status === 'RESOLVED'}
                    className="text-xs h-7 text-emerald-700 hover:bg-emerald-50"
                  >
                    Resolve
                  </Button>
                </div>
              </div>

              {/* Modal Body */}
              <div className="p-5 overflow-y-auto space-y-4 text-xs">
                {/* Title & Core Metadata */}
                <div className="p-3 bg-slate-50 rounded border border-border-medium space-y-1">
                  <h3 className="text-sm font-bold text-navy-900">{selectedAlert.title}</h3>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2 font-mono text-[11px] text-slate-600">
                    <div>
                      <span className="text-[10px] text-slate-400 uppercase block">Source Engine</span>
                      <span className="font-semibold text-slate-800">{selectedAlert.source}</span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-400 uppercase block">Timestamp</span>
                      <span>{selectedAlert.timestamp}</span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-400 uppercase block">Entity Scope</span>
                      <span className="font-semibold text-slate-800">{selectedAlert.entity}</span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-400 uppercase block">Rule Identifier</span>
                      <span>{selectedAlert.rule_id}</span>
                    </div>
                  </div>
                </div>

                {/* Grounded Explainability Panel (WHAT, WHO, WHEN, WHERE, WHY) */}
                <div className="border border-border-medium rounded overflow-hidden">
                  <div className="bg-slate-100 px-3 py-1.5 border-b border-border-medium font-bold text-navy-900 text-xs flex items-center justify-between">
                    <span className="flex items-center gap-1.5">
                      <HelpCircle className="w-3.5 h-3.5 text-gov-blue" />
                      Grounded Explainability Dossier
                    </span>
                    <span className="text-[10px] font-mono text-slate-500 uppercase">
                      Deterministic Reason Inference
                    </span>
                  </div>
                  <div className="p-3 bg-white space-y-2.5">
                    <div className="grid grid-cols-1 md:grid-cols-5 gap-1.5">
                      <div className="font-bold text-slate-700 font-mono uppercase text-[11px]">WHAT:</div>
                      <div className="md:col-span-4 text-slate-800">{selectedAlert.explainability.what}</div>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-5 gap-1.5">
                      <div className="font-bold text-slate-700 font-mono uppercase text-[11px]">WHO:</div>
                      <div className="md:col-span-4 font-mono text-navy-900 font-semibold">
                        {selectedAlert.explainability.who}
                      </div>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-5 gap-1.5">
                      <div className="font-bold text-slate-700 font-mono uppercase text-[11px]">WHEN:</div>
                      <div className="md:col-span-4 font-mono text-slate-700">{selectedAlert.explainability.when}</div>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-5 gap-1.5">
                      <div className="font-bold text-slate-700 font-mono uppercase text-[11px]">WHERE:</div>
                      <div className="md:col-span-4 font-mono text-slate-700">{selectedAlert.explainability.where}</div>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-5 gap-1.5">
                      <div className="font-bold text-slate-700 font-mono uppercase text-[11px]">WHY:</div>
                      <div className="md:col-span-4 text-slate-800 leading-relaxed">
                        {selectedAlert.explainability.why}
                      </div>
                    </div>
                  </div>
                </div>

                {/* MITRE ATT&CK Matrix Alignment */}
                <div className="p-3 bg-slate-50 border border-border-medium rounded space-y-1.5 font-mono text-xs">
                  <span className="text-[10px] font-bold text-slate-400 uppercase block">
                    MITRE ATT&CK Matrix Alignment
                  </span>
                  <div className="flex flex-wrap items-center gap-3">
                    <div className="px-2 py-1 bg-white border border-slate-200 rounded">
                      <span className="text-slate-400 text-[10px] block">TACTIC</span>
                      <span className="font-bold text-navy-900">{selectedAlert.mitre_tactic}</span>
                    </div>
                    <div className="px-2 py-1 bg-white border border-slate-200 rounded">
                      <span className="text-slate-400 text-[10px] block">TECHNIQUE</span>
                      <span className="font-bold text-navy-900">
                        {selectedAlert.mitre_technique} ({selectedAlert.mitre_id})
                      </span>
                    </div>
                    <div className="px-2 py-1 bg-white border border-slate-200 rounded">
                      <span className="text-slate-400 text-[10px] block">AUTOMATION</span>
                      <span className="font-bold text-emerald-700">CORRELATED DETECTION</span>
                    </div>
                  </div>
                </div>

                {/* Cross-Module Links & Deep Navigations */}
                <div className="border-t border-slate-200 pt-3 flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    {selectedAlert.event_id && (
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => navigate(`/live-logs?eventId=${selectedAlert.event_id}`)}
                        className="text-xs h-7 flex items-center gap-1"
                      >
                        <Eye className="w-3.5 h-3.5 text-slate-600" />
                        Inspect Source Event ({selectedAlert.event_id})
                      </Button>
                    )}

                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => navigate(`/investigation?case=${selectedAlert.case_id || selectedAlert.alert_id}`)}
                      className="text-xs h-7 flex items-center gap-1"
                    >
                      <Crosshair className="w-3.5 h-3.5 text-slate-600" />
                      Open Investigation ({selectedAlert.case_id || 'New Case'})
                    </Button>

                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => navigate(`/forensics?case=${selectedAlert.case_id || selectedAlert.alert_id}`)}
                      className="text-xs h-7 flex items-center gap-1"
                    >
                      <FileCheck className="w-3.5 h-3.5 text-slate-600" />
                      View Evidence Chain
                    </Button>
                  </div>

                  <span className="text-[10px] font-mono text-slate-400">
                    Safe Execution • Dry-Run Policy Active
                  </span>
                </div>
              </div>

              {/* Footer */}
              <div className="px-5 py-2.5 bg-slate-50 border-t border-border-medium flex items-center justify-between text-xs">
                <span className="font-mono text-[11px] text-slate-500">
                  Tenant Boundary: <strong>{selectedAlert.tenant_id}</strong>
                </span>
                <Dialog.Close asChild>
                  <Button size="sm" variant="outline">
                    Close Dossier
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
