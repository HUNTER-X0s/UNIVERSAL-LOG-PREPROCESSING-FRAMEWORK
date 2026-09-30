import React, { useState, useEffect, useRef } from 'react';
import { MetricCard } from '../components/ui/MetricCard';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { CodePanel } from '../components/ui/CodePanel';
import {
  GitFork,
  RotateCcw,
  Server,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  Radio,
  Trash2,
  Play,
  Pause,
  RefreshCw,
  FastForward,
  SkipForward,
  Plus,
  Sliders,
  Check,
  Copy,
  Download,
  FileCode,
  Zap,
  Activity,
  Layers,
  Edit3,
  FileCheck,
  Filter,
} from 'lucide-react';

interface SinkDestination {
  id: string;
  name: string;
  type: 'SIEM' | 'Lakehouse' | 'Streaming' | 'Compliance';
  protocol: string;
  endpoint: string;
  projection: 'OCSF v1.1.0' | 'OTel Logs' | 'Splunk HEC JSON' | 'Snappy Parquet' | 'Native TCP' | 'Raw Wire';
  routingRule: string;
  epsRate: number;
  p99Latency: string;
  circuitBreaker: 'CLOSED' | 'HALF-OPEN' | 'OPEN';
  status: 'CONNECTED' | 'BACKPRESSURE' | 'DRAINING';
  enabled: boolean;
}

interface DlqEvent {
  id: string;
  timestamp: string;
  vendor: string;
  sourceIp: string;
  stage: 'RAW_INGEST' | 'PARSER_DISPATCH' | 'SCHEMA_VALIDATION' | 'DELIVERY_SINK';
  failureReason: string;
  payload: string;
  casHash: string;
  canAutoHeal?: boolean;
}

const INITIAL_SINKS: SinkDestination[] = [
  {
    id: 'sink-splunk',
    name: 'Splunk Cloud HEC (Hot Security Tier)',
    type: 'SIEM',
    protocol: 'HTTPS / Splunk HEC v1',
    endpoint: 'https://http-inputs-corp.splunkcloud.com:8088',
    projection: 'Splunk HEC JSON',
    routingRule: 'severity in [HIGH, CRITICAL] or domain == "security"',
    epsRate: 5420,
    p99Latency: '2.1 ms',
    circuitBreaker: 'CLOSED',
    status: 'CONNECTED',
    enabled: true,
  },
  {
    id: 'sink-sentinel',
    name: 'Microsoft Sentinel (Log Analytics Workspace)',
    type: 'SIEM',
    protocol: 'Azure DCR Data Ingestion API',
    endpoint: 'https://sec-ops-dcr.eastus.ingest.monitor.azure.com',
    projection: 'OCSF v1.1.0',
    routingRule: 'vendor in [PaloAlto, Fortinet, AWS] and action == "DENY"',
    epsRate: 4890,
    p99Latency: '3.4 ms',
    circuitBreaker: 'CLOSED',
    status: 'CONNECTED',
    enabled: true,
  },
  {
    id: 'sink-s3-lake',
    name: 'S3 / MinIO Cold Sovereign Archive',
    type: 'Lakehouse',
    protocol: 'S3 API / Parquet Snappy Compression',
    endpoint: 's3://ulpf-immutable-evidence-archive-2026',
    projection: 'Snappy Parquet',
    routingRule: '* (100% loss-free forensic mirror of all raw residue)',
    epsRate: 12850,
    p99Latency: '1.4 ms',
    circuitBreaker: 'CLOSED',
    status: 'CONNECTED',
    enabled: true,
  },
  {
    id: 'sink-clickhouse',
    name: 'ClickHouse Security Telemetry Columnar',
    type: 'Lakehouse',
    protocol: 'Native TCP Port 9000 (Batch 5,000)',
    endpoint: 'tcp://ch-analytics-node-01.internal:9000',
    projection: 'Native TCP',
    routingRule: 'category == "network.flow" or protocol in [tcp, udp]',
    epsRate: 12850,
    p99Latency: '0.8 ms',
    circuitBreaker: 'CLOSED',
    status: 'CONNECTED',
    enabled: true,
  },
  {
    id: 'sink-kafka',
    name: 'Enterprise Kafka Event Hub (Stream Bus)',
    type: 'Streaming',
    protocol: 'SASL_SSL / TLS 1.3 Port 9092',
    endpoint: 'kafka-broker-01.internal:9092/topic-uce-v1',
    projection: 'OTel Logs',
    routingRule: 'All normalized canonical events with CAS deduplication key',
    epsRate: 12850,
    p99Latency: '0.9 ms',
    circuitBreaker: 'CLOSED',
    status: 'CONNECTED',
    enabled: true,
  },
];

const INITIAL_DLQ_EVENTS: DlqEvent[] = [
  {
    id: 'dlq-evt-0891',
    timestamp: '2026-09-28T22:15:10.142Z',
    vendor: 'Fortinet FortiGate',
    sourceIp: '10.0.1.45',
    stage: 'DELIVERY_SINK',
    failureReason: 'Downstream HTTP socket timeout (> 50ms bounded budget)',
    payload: 'date=2026-09-28 time=22:15:10 devname=FGT-01 logid=0000000013 type=traffic level=notice proto=6 srcip=10.0.1.45 dstip=198.51.100.99 action=deny',
    casHash: '8e7c10b42f65a12d9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822c',
    canAutoHeal: true,
  },
  {
    id: 'dlq-evt-0892',
    timestamp: '2026-09-28T22:18:34.901Z',
    vendor: 'Cisco ASA',
    sourceIp: '192.168.10.1',
    stage: 'PARSER_DISPATCH',
    failureReason: 'Malformed hex flags parameter in syslog trailer [0x0, 0x0]',
    payload: '%ASA-4-106023: Deny tcp src outside:198.51.100.22/443 dst inside:10.0.1.15/51200 by access-group "OUTSIDE_IN" [0x0, 0x0]',
    casHash: '4a9b31d04f65c19e7a82b081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822d',
    canAutoHeal: true,
  },
  {
    id: 'dlq-evt-0893',
    timestamp: '2026-09-28T22:24:52.410Z',
    vendor: 'Suricata EVE',
    sourceIp: '172.16.0.8',
    stage: 'SCHEMA_VALIDATION',
    failureReason: 'Corrupted trailing JSON bracket in raw network frame (Unexpected EOF)',
    payload: '{"timestamp":"2026-09-28T22:24:52.410123+0000","flow_id":91238471,"event_type":"alert","src_ip":"172.16.0.8","proto":"TCP"}',
    casHash: '7f9c20a14b65a12e8c81d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822e',
    canAutoHeal: false,
  },
  {
    id: 'dlq-evt-0894',
    timestamp: '2026-09-28T22:31:08.822Z',
    vendor: 'AWS CloudTrail',
    sourceIp: '203.0.113.88',
    stage: 'DELIVERY_SINK',
    failureReason: 'Transient SIEM rate-limit 429 Too Many Requests backpressure',
    payload: '{"eventVersion":"1.08","userIdentity":{"type":"IAMUser","userName":"ServiceDeployer"},"eventTime":"2026-09-28T22:31:08Z","eventName":"AssumeRole"}',
    casHash: '3c8e10b42f65a12d1b82a081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822f',
    canAutoHeal: true,
  },
];

export const PipelineRoutingReplay: React.FC = () => {
  const [sinks, setSinks] = useState<SinkDestination[]>(INITIAL_SINKS);
  const [dlqEvents, setDlqEvents] = useState<DlqEvent[]>(INITIAL_DLQ_EVENTS);
  const [selectedDlq, setSelectedDlq] = useState<DlqEvent | null>(INITIAL_DLQ_EVENTS[0]);
  const [isEditingPayload, setIsEditingPayload] = useState<boolean>(false);
  const [editedPayloadText, setEditedPayloadText] = useState<string>('');

  // Stream Player State
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const [playbackSpeed, setPlaybackSpeed] = useState<'1x' | '2x' | '5x' | 'burst'>('1x');
  const [replayedAuditList, setReplayedAuditList] = useState<{ id: string; timestamp: string; cas: string; targetSink: string }[]>([]);
  const [lastReplayedBanner, setLastReplayedBanner] = useState<string | null>(null);

  // Probe testing state per sink
  const [probingSinkId, setProbingSinkId] = useState<string | null>(null);

  // Stream play interval ref
  const timerRef = useRef<any>(null);

  useEffect(() => {
    if (selectedDlq) {
      setEditedPayloadText(selectedDlq.payload);
      setIsEditingPayload(false);
    }
  }, [selectedDlq]);

  // Stream Player Runner
  useEffect(() => {
    if (!isPlaying) {
      if (timerRef.current) clearInterval(timerRef.current);
      return;
    }

    const intervalMs = playbackSpeed === 'burst' ? 250 : playbackSpeed === '5x' ? 400 : playbackSpeed === '2x' ? 800 : 1500;

    timerRef.current = setInterval(() => {
      setDlqEvents((prev) => {
        if (prev.length === 0) {
          setIsPlaying(false);
          setLastReplayedBanner('Replay stream complete. All quarantined events successfully reprocessed and routed.');
          return [];
        }
        const eventToReplay = prev[0];
        const remaining = prev.slice(1);

        setReplayedAuditList((audits) => [
          {
            id: eventToReplay.id,
            timestamp: new Date().toLocaleTimeString(),
            cas: eventToReplay.casHash.substring(0, 16) + '...',
            targetSink: sinks.find((s) => s.enabled)?.name.split(' (')[0] || 'Splunk Cloud HEC',
          },
          ...audits.slice(0, 9),
        ]);

        if (selectedDlq?.id === eventToReplay.id) {
          setSelectedDlq(remaining.length > 0 ? remaining[0] : null);
        }

        return remaining;
      });
    }, intervalMs);

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [isPlaying, playbackSpeed, sinks, selectedDlq]);

  const toggleSink = (id: string) => {
    setSinks((prev) =>
      prev.map((s) => (s.id === id ? { ...s, enabled: !s.enabled } : s))
    );
  };

  const handleTestProbe = (id: string) => {
    setProbingSinkId(id);
    setTimeout(() => {
      setSinks((prev) =>
        prev.map((s) =>
          s.id === id ? { ...s, p99Latency: `${(Math.random() * 1.5 + 0.8).toFixed(1)} ms`, status: 'CONNECTED' } : s
        )
      );
      setProbingSinkId(null);
    }, 700);
  };

  const handleStepReplay = () => {
    if (dlqEvents.length === 0) return;
    const eventToReplay = dlqEvents[0];
    const remaining = dlqEvents.slice(1);

    setReplayedAuditList((audits) => [
      {
        id: eventToReplay.id,
        timestamp: new Date().toLocaleTimeString(),
        cas: eventToReplay.casHash.substring(0, 16) + '...',
        targetSink: sinks.find((s) => s.enabled)?.name.split(' (')[0] || 'Splunk Cloud HEC',
      },
      ...audits.slice(0, 9),
    ]);

    setDlqEvents(remaining);
    setSelectedDlq(remaining.length > 0 ? remaining[0] : null);
    setLastReplayedBanner(`Stepped event ${eventToReplay.id} through UCE normalization -> dispatched to active sinks.`);
  };

  const handleFastReplayAll = () => {
    const count = dlqEvents.length;
    if (count === 0) return;

    const newAudits = dlqEvents.map((e) => ({
      id: e.id,
      timestamp: new Date().toLocaleTimeString(),
      cas: e.casHash.substring(0, 16) + '...',
      targetSink: sinks.find((s) => s.enabled)?.name.split(' (')[0] || 'Splunk Cloud HEC',
    }));

    setReplayedAuditList((audits) => [...newAudits, ...audits].slice(0, 10));
    setDlqEvents([]);
    setSelectedDlq(null);
    setIsPlaying(false);
    setLastReplayedBanner(`Reprocessed all ${count} DLQ events in batch. CAS attestation confirmed.`);
  };

  const handlePurgeDlq = () => {
    setDlqEvents([]);
    setSelectedDlq(null);
    setIsPlaying(false);
  };

  const handleReset = () => {
    setDlqEvents(INITIAL_DLQ_EVENTS);
    setSelectedDlq(INITIAL_DLQ_EVENTS[0]);
    setIsPlaying(false);
    setLastReplayedBanner(null);
  };

  const handleSaveAndReplayCurrent = () => {
    if (!selectedDlq) return;
    const currentId = selectedDlq.id;
    const remaining = dlqEvents.filter((e) => e.id !== currentId);

    setReplayedAuditList((audits) => [
      {
        id: currentId,
        timestamp: new Date().toLocaleTimeString(),
        cas: selectedDlq.casHash.substring(0, 16) + '...',
        targetSink: sinks.find((s) => s.enabled)?.name.split(' (')[0] || 'Splunk Cloud HEC',
      },
      ...audits.slice(0, 9),
    ]);

    setDlqEvents(remaining);
    setSelectedDlq(remaining.length > 0 ? remaining[0] : null);
    setIsEditingPayload(false);
    setLastReplayedBanner(`Validated & repaired payload for ${currentId}. Event successfully re-routed.`);
  };

  const handleExportDiagnostics = () => {
    const report = {
      $schema: 'https://ulpf.sovereign.gov.in/schemas/v1/dlq-diagnostics.json',
      timestamp: new Date().toISOString(),
      active_sinks: sinks.filter((s) => s.enabled).map((s) => ({ name: s.name, protocol: s.protocol, eps: s.epsRate })),
      quarantined_events_count: dlqEvents.length,
      quarantined_events: dlqEvents,
      recent_replays: replayedAuditList,
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `ulpf-dlq-diagnostics-${Date.now()}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const activeEpsTotal = sinks
    .filter((s) => s.enabled)
    .reduce((acc, s) => acc + s.epsRate, 0);

  return (
    <div className="space-y-5">
      {/* Top Banner Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-border-light">
        <div className="min-w-0">
          <div className="flex items-center gap-2.5 flex-wrap">
            <h1 className="text-xl font-bold text-navy-900 tracking-tight uppercase flex items-center gap-2">
              <GitFork className="w-5 h-5 text-gov-blue" />
              Pipeline Multi-Destination Routing & DLQ Stream Play/Replay
            </h1>
            <Badge variant="ok" dot>
              STREAM ACTIVE · ZERO TELEMETRY LOSS
            </Badge>
          </div>
          <p className="text-xs text-slate-500 mt-1 max-w-2xl leading-relaxed">
            Fork normalized UCE streams simultaneously to hot SIEMs, columnar analytics, and sovereign S3 lakehouses. Inspect, repair, and play back dead-letter quarantine events with step-by-step stream control.
          </p>
        </div>

        {/* Action Buttons Right Next to Each Other */}
        <div className="flex flex-row items-center gap-2.5 shrink-0 flex-nowrap">
          <Button
            variant="outline"
            size="md"
            onClick={handleExportDiagnostics}
            className="font-semibold text-xs px-3.5 py-2 whitespace-nowrap h-9 shadow-xs"
            icon={<Download className="w-4 h-4 text-slate-600" />}
          >
            Export DLQ JSON
          </Button>

          <Button
            variant="secondary"
            size="md"
            onClick={handleFastReplayAll}
            disabled={dlqEvents.length === 0}
            className="font-semibold text-xs px-3.5 py-2 whitespace-nowrap h-9 shadow-xs"
            icon={<FastForward className="w-4 h-4 text-gov-blue" />}
          >
            Replay All ({dlqEvents.length})
          </Button>

          <Button
            variant="primary"
            size="md"
            onClick={handleReset}
            className="font-semibold text-xs px-4 py-2 whitespace-nowrap h-9 shadow-xs"
            icon={<RefreshCw className="w-4 h-4" />}
          >
            Reset Demo
          </Button>
        </div>
      </div>

      {/* Notification Banner */}
      {lastReplayedBanner && (
        <div className="p-3 bg-emerald-50 border border-emerald-300 rounded-xl text-xs font-mono text-emerald-950 flex items-center justify-between shadow-xs animate-fade-in">
          <span className="flex items-center gap-2 font-bold">
            <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
            <span>{lastReplayedBanner}</span>
          </span>
          <span className="text-[10px] bg-emerald-200/80 px-2 py-0.5 rounded font-bold text-emerald-900 border border-emerald-300">
            0 DROPPED · CAS ATTESTED
          </span>
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          label="Active Egress Sinks"
          value={`${sinks.filter((s) => s.enabled).length} / ${sinks.length} Destinations`}
          subtext="Simultaneous multi-target fanout"
          category="Protocols: HTTPS, TCP, S3, OTLP"
          icon={<Server className="w-4 h-4 text-gov-blue" />}
        />
        <MetricCard
          label="Aggregated Egress EPS"
          value={`${activeEpsTotal.toLocaleString()} EPS`}
          subtext="Wire-speed stream replication"
          category="Zero Re-parsing Overhead"
          icon={<Radio className="w-4 h-4 text-emerald-600" />}
        />
        <MetricCard
          label="Quarantine DLQ Buffer"
          value={`${dlqEvents.length} Events`}
          subtext={dlqEvents.length === 0 ? 'Clean isolated state' : 'Awaiting stream play / repair'}
          category="Durable SQLite Queue"
          badge={<Badge variant={dlqEvents.length > 0 ? 'warn' : 'ok'}>{dlqEvents.length > 0 ? 'NEEDS REPLAY' : 'CLEAN'}</Badge>}
          icon={<AlertTriangle className="w-4 h-4 text-amber-500" />}
        />
        <MetricCard
          label="Circuit Breakers"
          value="ALL CLOSED (HEALTHY)"
          subtext="Auto-backpressure throttle"
          category="Disk Buffer: 50 GB Spillover"
          badge={<Badge variant="ok" dot>STABLE</Badge>}
          icon={<ShieldCheck className="w-4 h-4 text-emerald-600" />}
        />
      </div>

      {/* Destination Sinks Grid */}
      <div className="bg-white border border-border-medium rounded-xl p-5 shadow-xs space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-border-light gap-2">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-gov-blue" />
            <span className="text-xs font-bold text-navy-900 uppercase">
              Multi-Destination Egress Forking Matrix ({sinks.filter((s) => s.enabled).length} Enabled)
            </span>
          </div>
          <span className="text-[11px] font-mono text-slate-500">
            Per-destination schema projection & custom routing filters
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-slate-50 border-b border-slate-200 text-[11px] font-bold text-slate-500 uppercase tracking-wider">
                <th className="py-2.5 px-3">Destination Platform</th>
                <th className="py-2.5 px-3">Tier</th>
                <th className="py-2.5 px-3">Projection Format</th>
                <th className="py-2.5 px-3">Routing Filter Policy</th>
                <th className="py-2.5 px-3">Throughput</th>
                <th className="py-2.5 px-3">Latency</th>
                <th className="py-2.5 px-3 text-center">Health Probe</th>
                <th className="py-2.5 px-3 text-right">Route Toggle</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 font-mono">
              {sinks.map((s) => (
                <tr key={s.id} className="hover:bg-slate-50/80 transition-colors">
                  <td className="py-3 px-3 font-sans font-semibold text-navy-900">
                    <div className="flex items-center gap-2">
                      <span className={`w-2 h-2 rounded-full shrink-0 ${s.enabled ? 'bg-emerald-500' : 'bg-slate-300'}`} />
                      <span className="truncate max-w-[180px]" title={s.name}>{s.name}</span>
                    </div>
                  </td>
                  <td className="py-3 px-3 font-sans">
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 font-semibold border border-slate-200">
                      {s.type}
                    </span>
                  </td>
                  <td className="py-3 px-3 font-sans">
                    <span className="text-[10px] px-2 py-0.5 rounded-full bg-blue-50 text-gov-blue font-bold border border-blue-200">
                      {s.projection}
                    </span>
                  </td>
                  <td className="py-3 px-3 text-[11px] text-slate-600 font-mono truncate max-w-[200px]" title={s.routingRule}>
                    {s.routingRule}
                  </td>
                  <td className="py-3 px-3 font-bold text-navy-900">
                    {s.enabled ? `${s.epsRate.toLocaleString()} EPS` : <span className="text-slate-400">0 EPS (PAUSED)</span>}
                  </td>
                  <td className="py-3 px-3 text-emerald-700 font-bold">{s.p99Latency}</td>
                  <td className="py-3 px-3 text-center font-sans">
                    <button
                      type="button"
                      onClick={() => handleTestProbe(s.id)}
                      disabled={probingSinkId === s.id}
                      className="px-2 py-1 text-[10px] font-semibold rounded border border-slate-200 hover:bg-slate-100 text-slate-600 transition-colors inline-flex items-center gap-1"
                    >
                      <Activity className={`w-3 h-3 text-gov-blue ${probingSinkId === s.id ? 'animate-spin' : ''}`} />
                      {probingSinkId === s.id ? 'Probing…' : 'Ping'}
                    </button>
                  </td>
                  <td className="py-3 px-3 text-right">
                    <button
                      type="button"
                      onClick={() => toggleSink(s.id)}
                      aria-label={`Toggle sink ${s.name}`}
                      className={`w-9 h-5 inline-flex items-center rounded-full p-0.5 transition-colors cursor-pointer ${
                        s.enabled ? 'bg-gov-blue justify-end' : 'bg-slate-300 justify-start'
                      }`}
                    >
                      <div className="bg-white w-4 h-4 rounded-full shadow-xs" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Dead-Letter Queue (DLQ) Stream Play / Replay Console */}
      <div className="bg-white border border-border-medium rounded-xl p-5 shadow-xs space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-border-light gap-2">
          <div className="flex items-center gap-2">
            <RotateCcw className="w-4 h-4 text-amber-600" />
            <span className="text-xs font-bold text-navy-900 uppercase">
              DLQ Stream Playback & Quarantine Inspector ({dlqEvents.length} Buffered)
            </span>
          </div>

          {/* Stream Player Controls */}
          <div className="flex items-center gap-1.5 flex-wrap">
            <div className="flex items-center bg-slate-100 rounded-lg p-0.5 border border-slate-200 mr-2">
              <button
                type="button"
                onClick={() => setIsPlaying(!isPlaying)}
                disabled={dlqEvents.length === 0}
                className={`px-3 py-1 text-xs font-bold rounded-md flex items-center gap-1.5 transition-all ${
                  isPlaying
                    ? 'bg-amber-600 text-white shadow-xs'
                    : 'bg-white text-navy-900 shadow-2xs hover:bg-slate-50'
                }`}
              >
                {isPlaying ? <Pause className="w-3 h-3" /> : <Play className="w-3 h-3 text-gov-blue" />}
                {isPlaying ? 'Pause Stream' : 'Play Replay'}
              </button>

              <button
                type="button"
                onClick={handleStepReplay}
                disabled={isPlaying || dlqEvents.length === 0}
                className="px-2.5 py-1 text-xs font-semibold text-slate-700 hover:text-navy-900 flex items-center gap-1 transition-colors"
                title="Reprocess exactly 1 event"
              >
                <SkipForward className="w-3 h-3" />
                Step 1
              </button>
            </div>

            {/* Speed Selector */}
            <div className="flex items-center gap-1 bg-slate-50 px-2 py-0.5 rounded-lg border border-slate-200">
              <span className="text-[10px] font-bold text-slate-400 uppercase">Speed:</span>
              {(['1x', '2x', '5x', 'burst'] as const).map((spd) => (
                <button
                  key={spd}
                  type="button"
                  onClick={() => setPlaybackSpeed(spd)}
                  className={`px-1.5 py-0.5 text-[10px] font-mono font-bold rounded transition-colors ${
                    playbackSpeed === spd
                      ? 'bg-gov-blue text-white'
                      : 'text-slate-600 hover:bg-slate-200'
                  }`}
                >
                  {spd}
                </button>
              ))}
            </div>

            <Button
              size="sm"
              variant="danger"
              onClick={handlePurgeDlq}
              disabled={dlqEvents.length === 0}
              className="text-xs ml-1"
              icon={<Trash2 className="w-3 h-3" />}
            >
              Purge
            </Button>
          </div>
        </div>

        {dlqEvents.length === 0 ? (
          <div className="p-8 text-center bg-slate-50 rounded-xl border border-dashed border-slate-300 space-y-3">
            <CheckCircle2 className="w-9 h-9 text-emerald-600 mx-auto" />
            <div className="text-xs font-bold text-navy-900 uppercase">Dead-Letter Queue is Empty & Clean</div>
            <p className="text-[11.5px] text-slate-500 max-w-md mx-auto">
              Zero unparseable or rejected events. 100% of telemetry has been successfully re-routed and indexed with verified cryptographic CAS attestation.
            </p>
            <div className="flex justify-center">
              <Button variant="outline" size="sm" onClick={handleReset} className="text-xs">
                <RefreshCw className="w-3.5 h-3.5" />
                Restore Quarantined Test Events
              </Button>
            </div>
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
            {/* Event List (5 cols) */}
            <div className="lg:col-span-5 border border-border-light rounded-xl divide-y divide-slate-100 max-h-[380px] overflow-y-auto shadow-2xs">
              {dlqEvents.map((e) => (
                <div
                  key={e.id}
                  onClick={() => setSelectedDlq(e)}
                  className={`p-3 cursor-pointer transition-all text-xs ${
                    selectedDlq?.id === e.id
                      ? 'bg-blue-50/80 border-l-4 border-gov-blue font-semibold'
                      : 'hover:bg-slate-50'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1 font-mono">
                    <span className="font-bold text-navy-900 flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
                      {e.id}
                    </span>
                    <span className="text-[10px] text-slate-400">{e.timestamp.substring(11, 23)}</span>
                  </div>
                  <div className="text-slate-600 mb-1 flex items-center justify-between">
                    <span>{e.vendor} · IP {e.sourceIp}</span>
                    <span className="text-[9px] font-mono px-1 rounded bg-slate-200/80 text-slate-700">
                      {e.stage}
                    </span>
                  </div>
                  <div className="text-[10.5px] font-mono text-amber-900 bg-amber-50/80 px-2 py-1 rounded border border-amber-200/70 truncate">
                    {e.failureReason}
                  </div>
                </div>
              ))}
            </div>

            {/* Event Inspector & Payload Repair Console (7 cols) */}
            <div className="lg:col-span-7 bg-slate-50/70 border border-border-light rounded-xl p-4 space-y-3.5 shadow-2xs">
              {selectedDlq ? (
                <>
                  <div className="flex items-center justify-between pb-2 border-b border-slate-200">
                    <div>
                      <span className="text-xs font-bold text-navy-900 font-mono">{selectedDlq.id}</span>
                      <span className="text-[11px] text-slate-500 ml-2">({selectedDlq.vendor})</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <span className="text-[10px] font-mono text-amber-800 font-bold bg-amber-100/80 border border-amber-300 px-2 py-0.5 rounded">
                        STAGE: {selectedDlq.stage}
                      </span>
                      <button
                        type="button"
                        onClick={() => setIsEditingPayload(!isEditingPayload)}
                        className="px-2 py-0.5 text-[11px] font-semibold text-gov-blue hover:text-navy-900 flex items-center gap-1"
                      >
                        <Edit3 className="w-3 h-3" />
                        {isEditingPayload ? 'Cancel Edit' : 'Edit Frame'}
                      </button>
                    </div>
                  </div>

                  <div className="text-[11.5px] space-y-1">
                    <div className="text-slate-700 font-semibold flex items-center justify-between">
                      <span>Quarantine Failure Reason:</span>
                      <span className="font-mono text-[10px] text-slate-500">
                        CAS: {selectedDlq.casHash.substring(0, 16)}...
                      </span>
                    </div>
                    <div className="font-mono text-xs text-amber-950 bg-amber-50 p-2.5 rounded-lg border border-amber-200 leading-relaxed">
                      {selectedDlq.failureReason}
                    </div>
                  </div>

                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between text-xs font-semibold text-slate-700">
                      <span>Raw Quarantined Frame:</span>
                      {isEditingPayload && (
                        <span className="text-[10px] font-mono text-gov-blue">Editing in-flight frame</span>
                      )}
                    </div>

                    {isEditingPayload ? (
                      <div className="space-y-2">
                        <textarea
                          value={editedPayloadText}
                          onChange={(e) => setEditedPayloadText(e.target.value)}
                          rows={6}
                          className="w-full font-mono text-xs p-3 bg-white border border-border-medium rounded-lg text-navy-900 focus:outline-none focus:ring-1 focus:ring-gov-blue leading-relaxed shadow-inner"
                        />
                        <Button
                          size="sm"
                          variant="primary"
                          onClick={handleSaveAndReplayCurrent}
                          className="w-full text-xs font-semibold"
                          icon={<Check className="w-3.5 h-3.5" />}
                        >
                          Validate, Repair & Replay Event
                        </Button>
                      </div>
                    ) : (
                      <div className="rounded-lg overflow-hidden border border-slate-200">
                        <CodePanel code={selectedDlq.payload} language="text" maxHeight="180px" className="border-0 text-xs" />
                      </div>
                    )}
                  </div>
                </>
              ) : (
                <div className="text-center py-16 text-slate-400 text-xs">
                  Select an event from the DLQ quarantine list to inspect diagnostics
                </div>
              )}
            </div>
          </div>
        )}

        {/* Live Replay Attestation Stream */}
        {replayedAuditList.length > 0 && (
          <div className="pt-3 border-t border-slate-100 space-y-2">
            <span className="text-xs font-bold text-navy-900 uppercase flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5 text-emerald-600" />
              Recent Replay Dispatch Log (Attested & Re-routed)
            </span>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
              {replayedAuditList.slice(0, 6).map((audit, i) => (
                <div key={i} className="p-2 bg-slate-50 rounded-lg border border-slate-200 text-[11px] font-mono flex items-center justify-between">
                  <div className="truncate pr-2">
                    <span className="font-bold text-navy-900">{audit.id}</span>
                    <span className="text-slate-400 ml-1">→ {audit.targetSink}</span>
                  </div>
                  <span className="text-emerald-700 font-bold shrink-0">REPLAYED</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
