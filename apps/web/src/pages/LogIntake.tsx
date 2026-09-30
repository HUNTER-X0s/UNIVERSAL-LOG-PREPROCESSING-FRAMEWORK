import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { IngestConsole } from '../components/telemetry/IngestConsole';
import { Card } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { MetricCard } from '../components/ui/MetricCard';
import {
  Server,
  Shield,
  Radio,
  FileText,
  CheckCircle2,
  Lock,
  Activity,
  HardDrive,
  Cpu,
  Layers,
  ExternalLink,
  ShieldCheck,
  Zap,
  Clock,
  ArrowRight,
} from 'lucide-react';

export const LogIntake: React.FC = () => {
  const navigate = useNavigate();
  const [selectedProtocolTab, setSelectedProtocolTab] = useState<'all' | 'syslog' | 'rest' | 'spool' | 'streaming'>('all');

  const LISTENERS = [
    {
      id: 'syslog',
      protocol: 'SYSLOG DUAL (TCP/UDP)',
      port: 'Port 514 (UDP) / Port 6514 (TCP TLS 1.3)',
      format: 'RFC 5424 / RFC 3164 / Octet Framing',
      security: 'TLS 1.3 / mTLS / Plaintext',
      maxFrame: '65,536 Bytes / Frame',
      backpressure: 'BLOCK_THEN_REJECT',
      status: 'LISTENING',
      activeConns: 48,
      throughput: '14,850 EPS',
      icon: <Radio className="w-4 h-4 text-gov-blue" />,
    },
    {
      id: 'rest',
      protocol: 'ENTERPRISE REST INGEST API',
      port: 'Port 8080 (/api/v1/intake/raw & /events/ingest)',
      format: 'JSON / Raw String / OTel OTLP / Splunk HEC',
      security: 'Bearer JWT / API Key / HMAC Header',
      maxFrame: '10 MB Multipart Bounded',
      backpressure: 'HTTP 429 / 503 Retry-After Signal',
      status: 'LISTENING',
      activeConns: 124,
      throughput: '28,400 EPS',
      icon: <Server className="w-4 h-4 text-gov-blue" />,
    },
    {
      id: 'spool',
      protocol: 'DURABLE FILE SPOOL WATCHER',
      port: 'Direct POSIX Mount (/var/spool/ulpf/incoming)',
      format: 'GZIP / ZSTD / TAR.GZ / NDJSON / CSV',
      security: 'Chroot Jailed / Read-Only Inode',
      maxFrame: '500 MB Chunk Partition',
      backpressure: 'Inode Throttle Flow Control',
      status: 'WATCHING',
      activeConns: 12,
      throughput: '6,200 EPS',
      icon: <FileText className="w-4 h-4 text-gov-blue" />,
    },
    {
      id: 'streaming',
      protocol: 'HIGH-VELOCITY STREAMING FABRIC',
      port: 'Zero-Copy Ring Buffer (Vector / Kafka / OTel Agent)',
      format: 'Bounded Ring Buffer / Arrow IPC',
      security: 'Mutual TLS / SASL SCRAM-SHA-512',
      maxFrame: 'Bounded FIFO (5,000 Capacity)',
      backpressure: 'Adaptive Watermarking Token Gate',
      status: 'BUFFERED',
      activeConns: 32,
      throughput: '52,000 EPS',
      icon: <Shield className="w-4 h-4 text-gov-blue" />,
    },
  ];

  const filteredListeners = selectedProtocolTab === 'all'
    ? LISTENERS
    : LISTENERS.filter(l => l.id === selectedProtocolTab);

  return (
    <div className="space-y-5">
      {/* Top Header & Operational State */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-border-light">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-bold text-navy-900 tracking-tight">Log Telemetry Intake Plane</h2>
            <Badge variant="ok" dot>INGEST BOUNDARY: ACTIVE</Badge>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Multi-protocol verbatim capture plane storing immutable SHA-256 evidence into Content-Addressed Storage (CAS) prior to any parsing.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            size="sm"
            variant="outline"
            onClick={() => navigate('/health')}
            icon={<Activity className="w-3.5 h-3.5 text-gov-blue" />}
          >
            System Health & SLAs
          </Button>
          <Button
            size="sm"
            variant="primary"
            onClick={() => navigate('/live-logs')}
            icon={<ArrowRight className="w-3.5 h-3.5" />}
          >
            View Live Stream
          </Button>
        </div>
      </div>

      {/* Top 4 Performance & Ingest Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        <MetricCard
          label="Ingress Telemetry Plane"
          value="101,450 EPS"
          subtext="Aggregate multi-socket throughput"
          category="4 Listeners Active"
          icon={<Zap className="w-4 h-4" />}
        />
        <MetricCard
          label="Raw Lossless Retention"
          value="100.0%"
          subtext="Byte-exact judicial admissibility"
          category="Pre-CAS Zero-Loss"
          icon={<ShieldCheck className="w-4 h-4" />}
        />
        <MetricCard
          label="CAS Vault Deduplication"
          value="42.8% Saved"
          subtext="SHA-256 O(1) content deduplication"
          category="Zero Storage Bloat"
          icon={<HardDrive className="w-4 h-4" />}
        />
        <MetricCard
          label="Bounded Backpressure Queue"
          value="0 Dropped"
          subtext="Capacity 5,000 | Token Bucket Throttling"
          category="Zero Drop Guarantee"
          icon={<Cpu className="w-4 h-4" />}
        />
      </div>

      {/* Protocol Listeners Matrix */}
      <div className="bg-white rounded border border-border-light shadow-2xs overflow-hidden">
        <div className="px-4 py-3 bg-surface-alt border-b border-border-light flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-navy-900 flex items-center gap-2">
              <Server className="w-3.5 h-3.5 text-gov-blue" />
              <span>Multi-Protocol Ingestion Listeners</span>
            </h3>
            <p className="text-[11px] text-slate-500 mt-0.5">
              Production listening sockets with TLS 1.3 termination, rate bounding, and transparent payload decompression (GZIP/ZSTD).
            </p>
          </div>

          {/* Protocol Filter Tabs */}
          <div className="flex items-center gap-1">
            <button
              onClick={() => setSelectedProtocolTab('all')}
              className={`px-2 py-0.5 text-xs rounded font-medium transition-colors ${
                selectedProtocolTab === 'all'
                  ? 'bg-gov-blue text-white shadow-2xs'
                  : 'bg-white text-slate-600 hover:bg-slate-100 border border-border-light'
              }`}
            >
              All (4)
            </button>
            <button
              onClick={() => setSelectedProtocolTab('syslog')}
              className={`px-2 py-0.5 text-xs rounded font-medium transition-colors ${
                selectedProtocolTab === 'syslog'
                  ? 'bg-gov-blue text-white shadow-2xs'
                  : 'bg-white text-slate-600 hover:bg-slate-100 border border-border-light'
              }`}
            >
              Syslog
            </button>
            <button
              onClick={() => setSelectedProtocolTab('rest')}
              className={`px-2 py-0.5 text-xs rounded font-medium transition-colors ${
                selectedProtocolTab === 'rest'
                  ? 'bg-gov-blue text-white shadow-2xs'
                  : 'bg-white text-slate-600 hover:bg-slate-100 border border-border-light'
              }`}
            >
              REST API
            </button>
            <button
              onClick={() => setSelectedProtocolTab('streaming')}
              className={`px-2 py-0.5 text-xs rounded font-medium transition-colors ${
                selectedProtocolTab === 'streaming'
                  ? 'bg-gov-blue text-white shadow-2xs'
                  : 'bg-white text-slate-600 hover:bg-slate-100 border border-border-light'
              }`}
            >
              Streaming
            </button>
          </div>
        </div>

        {/* Listeners Grid */}
        <div className="p-4 grid grid-cols-1 md:grid-cols-2 gap-3.5">
          {filteredListeners.map((item) => (
            <div key={item.id} className="bg-surface-alt p-3.5 rounded border border-border-light shadow-2xs flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-bold text-navy-900 flex items-center gap-1.5">
                    {item.icon}
                    {item.protocol}
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-50 text-emerald-800 border border-emerald-200 font-bold">
                    {item.status}
                  </span>
                </div>

                <div className="space-y-1 text-xs font-mono">
                  <div className="flex items-center justify-between bg-white px-2 py-1 rounded border border-slate-100">
                    <span className="text-slate-500">Bound Interface:</span>
                    <span className="text-navy-900 font-semibold">{item.port}</span>
                  </div>
                  <div className="flex items-center justify-between bg-white px-2 py-1 rounded border border-slate-100">
                    <span className="text-slate-500">Security & Cipher:</span>
                    <span className="text-gov-blue font-semibold">{item.security}</span>
                  </div>
                  <div className="flex items-center justify-between bg-white px-2 py-1 rounded border border-slate-100">
                    <span className="text-slate-500">Framing Standard:</span>
                    <span className="text-slate-700">{item.format}</span>
                  </div>
                  <div className="flex items-center justify-between bg-white px-2 py-1 rounded border border-slate-100">
                    <span className="text-slate-500">Throughput & Sockets:</span>
                    <span className="text-emerald-700 font-bold">{item.throughput} ({item.activeConns} conns)</span>
                  </div>
                </div>
              </div>

              <div className="pt-2 mt-2.5 border-t border-slate-200 flex items-center justify-between text-[11px] text-slate-500 font-mono">
                <span>Overload Throttling:</span>
                <span className="text-gov-blue font-semibold">{item.backpressure}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Interactive Ingest Console & Raw Socket Simulator */}
      <IngestConsole />

      {/* Enterprise SOC & MNC Institutional Guarantees */}
      <Card title="Enterprise Ingestion Guarantees & Judicial Compliance Matrix">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div className="space-y-1.5 p-3 rounded bg-surface-alt border border-border-light">
            <strong className="text-navy-900 block flex items-center gap-1.5 text-xs">
              <CheckCircle2 className="w-4 h-4 text-emerald-600" />
              Verbatim Byte Retention (Section 65B)
            </strong>
            <p className="text-slate-600 text-[11px] leading-relaxed">
              Zero transformation, tokenization, or parsing occurs prior to Content-Addressed Storage. The raw network payload is preserved with exact byte-level fidelity for judicial admissibility under the Indian Evidence Act.
            </p>
          </div>

          <div className="space-y-1.5 p-3 rounded bg-surface-alt border border-border-light">
            <strong className="text-navy-900 block flex items-center gap-1.5 text-xs">
              <Lock className="w-4 h-4 text-gov-blue" />
              Content-Addressed CAS Deduplication
            </strong>
            <p className="text-slate-600 text-[11px] leading-relaxed">
              Every log event is cryptographically indexed by its SHA-256 hash (<code className="font-mono bg-white px-1 py-0.5 rounded border border-slate-200">cas/ab/abcdef...</code>). Duplicate packets are deduplicated in O(1) time without consuming additional storage.
            </p>
          </div>

          <div className="space-y-1.5 p-3 rounded bg-surface-alt border border-border-light">
            <strong className="text-navy-900 block flex items-center gap-1.5 text-xs">
              <ShieldCheck className="w-4 h-4 text-purple-600" />
              Bounded Queue Backpressure & Circuit Breakers
            </strong>
            <p className="text-slate-600 text-[11px] leading-relaxed">
              Intake pipelines use bounded FIFO token-bucket channels (5,000 capacity). Under high-volume burst conditions, the platform enforces rate-limiting backpressure rather than dropping events silently, preventing memory exhaustion.
            </p>
          </div>
        </div>
      </Card>
    </div>
  );
};
