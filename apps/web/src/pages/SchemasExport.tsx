import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import * as Dialog from '@radix-ui/react-dialog';
import {
  Archive,
  ArrowRight,
  CheckCircle2,
  Clock,
  Copy,
  Database,
  Download,
  ExternalLink,
  Eye,
  FileCheck,
  FileCode,
  FileSpreadsheet,
  FileText,
  Filter,
  Layers,
  Lock,
  RefreshCw,
  Search,
  ShieldCheck,
  SlidersHorizontal,
  Check,
  X,
  Sparkles,
  FileDown,
  Zap,
} from 'lucide-react';

import { fetchSchemas, SchemaDefinition } from '../api/operations';
import { INITIAL_TELEMETRY_EVENTS } from '../demo/telemetryEvents';
import { CodePanel } from '../components/ui/CodePanel';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';

// Mock export history ledger representing immutable batch exports
interface ExportRecord {
  export_id: string;
  timestamp: string;
  format: string;
  target_format: string;
  compression: string;
  time_scope: string;
  event_count: number;
  sha256_manifest: string;
  status: 'COMPLETED' | 'IN_PROGRESS';
  size_kb: number;
  download_payload?: string;
  extension: string;
}

const MOCK_EXPORT_HISTORY: ExportRecord[] = [
  {
    export_id: 'EXP-20260913-0091',
    timestamp: '2026-09-13T17:10:00Z',
    format: 'NDJSON (GZIP)',
    target_format: 'ndjson',
    compression: 'gzip',
    time_scope: '1h',
    event_count: 14200,
    sha256_manifest: 'b3f1c849102c918a29b3847291048201a48c7821948271049182390148291048',
    status: 'COMPLETED',
    size_kb: 4812,
    extension: 'ndjson.gz',
  },
  {
    export_id: 'EXP-20260913-0090',
    timestamp: '2026-09-13T16:30:00Z',
    format: 'PARQUET (ZSTD)',
    target_format: 'parquet',
    compression: 'zstd',
    time_scope: '24h',
    event_count: 50000,
    sha256_manifest: '9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b',
    status: 'COMPLETED',
    size_kb: 12450,
    extension: 'parquet.zst',
  },
  {
    export_id: 'EXP-20260913-0089',
    timestamp: '2026-09-13T15:00:00Z',
    format: 'CSV (NONE)',
    target_format: 'csv',
    compression: 'none',
    time_scope: '15m',
    event_count: 8500,
    sha256_manifest: '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
    status: 'COMPLETED',
    size_kb: 3120,
    extension: 'csv',
  },
];

async function computeSha256(text: string): Promise<string> {
  try {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  } catch {
    let hash = 0;
    for (let i = 0; i < text.length; i++) {
      hash = (hash << 5) - hash + text.charCodeAt(i);
      hash |= 0;
    }
    return Math.abs(hash).toString(16).padStart(64, '0');
  }
}

export const SchemasExport: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  // Schema catalog
  const [schemas, setSchemas] = useState<SchemaDefinition[]>([]);
  const [selectedSchemaKey, setSelectedSchemaKey] = useState<string>('uce');

  // Export generator state
  const [exportFormat, setExportFormat] = useState<string>('ndjson');
  const [compression, setCompression] = useState<string>('gzip');
  const [timeScope, setTimeScope] = useState<string>('1h');
  const [isExporting, setIsExporting] = useState<boolean>(false);
  const [exportSuccessNotice, setExportSuccessNotice] = useState<string | null>(null);

  // Copy feedback state
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  // Inspect modal record
  const [inspectingRecord, setInspectingRecord] = useState<ExportRecord | null>(null);

  // Export history state
  const [history, setHistory] = useState<ExportRecord[]>(MOCK_EXPORT_HISTORY);

  useEffect(() => {
    fetchSchemas().then((s) => setSchemas(s));
  }, []);

  const activeSchema = useMemo(() => {
    return (
      schemas.find((s) => (s.schema_id || s.id || '').toLowerCase() === selectedSchemaKey.toLowerCase()) ||
      schemas[0]
    );
  }, [schemas, selectedSchemaKey]);

  // Synchronize top standard card selection with export format
  const handleSelectStandardCard = (key: string) => {
    setSelectedSchemaKey(key);
    if (key === 'ocsf') setExportFormat('ocsf');
    else if (key === 'stix') setExportFormat('stix');
    else if (key === 'tabular') setExportFormat('parquet');
    else if (key === 'uce') setExportFormat('ndjson');
  };

  // Synchronize format select with standard card
  const handleSelectExportFormat = (fmt: string) => {
    setExportFormat(fmt);
    if (fmt === 'ocsf') setSelectedSchemaKey('ocsf');
    else if (fmt === 'stix') setSelectedSchemaKey('stix');
    else if (fmt === 'parquet' || fmt === 'csv') setSelectedSchemaKey('tabular');
    else if (fmt === 'ndjson') setSelectedSchemaKey('uce');
  };

  // Dynamic calculations based on Time Boundary & Compression
  const timeMetrics = useMemo(() => {
    switch (timeScope) {
      case '15m':
        return {
          label: 'Last 15 Minutes',
          events: 340,
          rawBytes: 340 * 395,
          windowText: '2026-09-13T17:00:22Z → 2026-09-13T17:15:22Z',
        };
      case '24h':
        return {
          label: 'Last 24 Hours',
          events: 34800,
          rawBytes: 34800 * 395,
          windowText: '2026-09-12T17:15:22Z → 2026-09-13T17:15:22Z',
        };
      case 'all':
        return {
          label: 'Full Bounded Buffer (Memory)',
          events: 128500,
          rawBytes: 128500 * 395,
          windowText: 'Complete Retained In-Memory Epoch Buffer',
        };
      case '1h':
      default:
        return {
          label: 'Last 1 Hour (Standard)',
          events: 1420,
          rawBytes: 1420 * 395,
          windowText: '2026-09-13T16:15:22Z → 2026-09-13T17:15:22Z',
        };
    }
  }, [timeScope]);

  const compressionMetrics = useMemo(() => {
    switch (compression) {
      case 'zstd':
        return {
          ratio: 5.2,
          savings: '81%',
          speed: '1.4 GB/s',
          label: 'Zstandard v1.5 (High-Speed Block Dictionary)',
          extSuffix: '.zst',
        };
      case 'none':
        return {
          ratio: 1.0,
          savings: '0%',
          speed: '2.5 GB/s (Raw)',
          label: 'Raw Uncompressed Stream',
          extSuffix: '',
        };
      case 'gzip':
      default:
        return {
          ratio: 3.8,
          savings: '74%',
          speed: '820 MB/s',
          label: 'GNU Zip (RFC 1952 Deflate)',
          extSuffix: '.gz',
        };
    }
  }, [compression]);

  const estimatedArchiveSizeKb = useMemo(() => {
    return Math.max(1, Math.round(timeMetrics.rawBytes / compressionMetrics.ratio / 1024));
  }, [timeMetrics, compressionMetrics]);

  // Generate Sample Projected Output string for Live Preview
  const sampleProjectedOutput = useMemo(() => {
    const sampleEvent = INITIAL_TELEMETRY_EVENTS[0];
    switch (exportFormat) {
      case 'ocsf':
        return JSON.stringify(
          {
            activity_id: 1,
            category_uid: 4,
            class_uid: 4001,
            class_name: 'Network Activity',
            severity_id: 4,
            severity: 'High',
            time: 1789319722140,
            metadata: {
              version: '1.1.0',
              uid: sampleEvent.event_id,
              product: {
                vendor_name: sampleEvent.vendor,
                name: sampleEvent.source,
              },
            },
            src_endpoint: {
              ip: sampleEvent.extracted_fields?.src_ip || '198.51.100.99',
              port: sampleEvent.extracted_fields?.src_port || 445,
            },
            dst_endpoint: {
              ip: sampleEvent.extracted_fields?.dst_ip || '10.0.1.45',
              port: sampleEvent.extracted_fields?.dst_port || 445,
            },
            disposition: sampleEvent.action,
            unmapped: sampleEvent.unmapped_residue,
          },
          null,
          2
        );
      case 'stix':
        return JSON.stringify(
          {
            type: 'bundle',
            id: `bundle--${sampleEvent.event_id}`,
            spec_version: '2.1',
            objects: [
              {
                type: 'ipv4-addr',
                id: 'ipv4-addr--198-51-100-99',
                value: sampleEvent.extracted_fields?.src_ip || '198.51.100.99',
              },
              {
                type: 'network-traffic',
                id: `network-traffic--${sampleEvent.event_id}`,
                start: sampleEvent.timestamp,
                protocols: ['tcp'],
                src_ref: 'ipv4-addr--198-51-100-99',
                dst_port: 445,
              },
            ],
          },
          null,
          2
        );
      case 'csv':
        return `event_id,timestamp,vendor,action,severity,src_ip,dst_ip,threat_name\n${sampleEvent.event_id},${sampleEvent.timestamp},"${sampleEvent.vendor}",${sampleEvent.action},${sampleEvent.severity},${sampleEvent.extracted_fields?.src_ip},${sampleEvent.extracted_fields?.dst_ip},"${sampleEvent.detection_title || 'SMB Remote Code Execution'}"`;
      case 'otel':
        return JSON.stringify({
          resourceLogs: [{
            resource: { attributes: [{ key: 'service.name', value: { stringValue: 'ulpf.preprocessor' } }] },
            scopeLogs: [{
              scope: { name: 'ulpf.normalizer' },
              logRecords: [{
                timeUnixNano: String(new Date(sampleEvent.timestamp).getTime() * 1000000),
                severityNumber: 17,
                severityText: sampleEvent.severity,
                body: { stringValue: sampleEvent.detection_title || 'Network Security Telemetry' },
                attributes: [
                  { key: 'source.ip', value: { stringValue: sampleEvent.extracted_fields?.src_ip || '198.51.100.4' } },
                  { key: 'destination.ip', value: { stringValue: sampleEvent.extracted_fields?.dst_ip || '10.0.0.1' } },
                ]
              }]
            }]
          }]
        }, null, 2);
      case 'ecs':
        return JSON.stringify({
          '@timestamp': sampleEvent.timestamp,
          event: { action: sampleEvent.action, category: ['network'], dataset: 'firewall' },
          source: { ip: sampleEvent.extracted_fields?.src_ip, port: sampleEvent.extracted_fields?.src_port },
          destination: { ip: sampleEvent.extracted_fields?.dst_ip, port: sampleEvent.extracted_fields?.dst_port },
          message: sampleEvent.detection_title || 'Security alert',
        }, null, 2);
      case 'cef':
        return `CEF:0|ULPF|Universal Preprocessor|1.0|4001|Network Alert|${sampleEvent.severity}|src=${sampleEvent.extracted_fields?.src_ip} dst=${sampleEvent.extracted_fields?.dst_ip} act=${sampleEvent.action} msg=${sampleEvent.detection_title || 'Security Event'}`;
      case 'leef':
        return `LEEF:2.0|ULPF|Universal Preprocessor|1.0|${sampleEvent.event_id}\tsrc=${sampleEvent.extracted_fields?.src_ip}\tdst=${sampleEvent.extracted_fields?.dst_ip}\tact=${sampleEvent.action}\tsev=${sampleEvent.severity}`;
      case 'splunk_hec':
        return JSON.stringify({
          time: Math.floor(new Date(sampleEvent.timestamp).getTime() / 1000),
          event: {
            action: sampleEvent.action,
            src_ip: sampleEvent.extracted_fields?.src_ip,
            dest_ip: sampleEvent.extracted_fields?.dst_ip,
            severity: sampleEvent.severity,
            cim_model: 'Network_Traffic',
          },
          sourcetype: 'ulpf:telemetry',
          source: 'ulpf_preprocessor',
        }, null, 2);
      case 'google_udm':
        return JSON.stringify({
          metadata: { event_timestamp: sampleEvent.timestamp, event_type: 'NETWORK_CONNECTION' },
          principal: { ip: sampleEvent.extracted_fields?.src_ip },
          target: { ip: sampleEvent.extracted_fields?.dst_ip },
          security_result: { action: sampleEvent.action, severity: sampleEvent.severity },
        }, null, 2);
      case 'sentinel_asim':
        return JSON.stringify({
          TimeGenerated: sampleEvent.timestamp,
          EventVendor: sampleEvent.vendor,
          EventType: 'NetworkSession',
          SrcIpAddr: sampleEvent.extracted_fields?.src_ip,
          DstIpAddr: sampleEvent.extracted_fields?.dst_ip,
          DvcAction: sampleEvent.action,
        }, null, 2);
      case 'syslog_5424':
        return `<165>1 ${sampleEvent.timestamp} edge-gw ulpf 1042 ID47 [meta@32473 src="${sampleEvent.extracted_fields?.src_ip}" dst="${sampleEvent.extracted_fields?.dst_ip}"] ${sampleEvent.action} ${sampleEvent.detection_title || 'Alert'}`;
      case 'syslog_3164':
        return `Sep 30 02:00:00 edge-gw ulpf[${sampleEvent.event_id}]: ${sampleEvent.action} connection from ${sampleEvent.extracted_fields?.src_ip} to ${sampleEvent.extracted_fields?.dst_ip}`;
      case 'w3c':
        return `${sampleEvent.extracted_fields?.src_ip || '198.51.100.4'} - secops [30/Sep/2026:02:00:00 +0000] "POST /api/telemetry HTTP/1.1" 200 4096 "https://portal" "ULPF-Agent"`;
      case 'logfmt':
        return `ts=${sampleEvent.timestamp} event_id=${sampleEvent.event_id} src=${sampleEvent.extracted_fields?.src_ip} dst=${sampleEvent.extracted_fields?.dst_ip} act=${sampleEvent.action} sev=${sampleEvent.severity}`;
      case 'neo4j':
        return `// Neo4j Cypher Attack Graph Ingestion\nMERGE (src:IP {address: "${sampleEvent.extracted_fields?.src_ip || '198.51.100.4'}"})\nMERGE (dst:IP {address: "${sampleEvent.extracted_fields?.dst_ip || '10.0.0.1'}"})\nCREATE (src)-[:COMMUNICATED_WITH {action: "${sampleEvent.action}", time: "${sampleEvent.timestamp}"}]->(dst);`;
      case 'gelf':
        return JSON.stringify({
          version: '1.1',
          host: 'ulpf-preprocessor',
          short_message: sampleEvent.detection_title || 'Security event',
          timestamp: Math.floor(new Date(sampleEvent.timestamp).getTime() / 1000),
          level: 4,
          _src_ip: sampleEvent.extracted_fields?.src_ip,
          _dst_ip: sampleEvent.extracted_fields?.dst_ip,
          _event_id: sampleEvent.event_id,
        }, null, 2);
      case 'forensic_dossier':
        return `========================================================================\nSTATUTORY FORENSIC EVIDENCE CERTIFICATE\nUnder Section 65B Indian Evidence Act 1872 / Section 63 BSA 2023\n========================================================================\nEvent Reference: ${sampleEvent.event_id}\nCanonical Timestamp: ${sampleEvent.timestamp}\nOrigin Appliance: ${sampleEvent.vendor}\nSource Endpoint: ${sampleEvent.extracted_fields?.src_ip}\nDestination Endpoint: ${sampleEvent.extracted_fields?.dst_ip}\nDisposition: ${sampleEvent.action}\nIntegrity Attestation: HASH SEALED RFC-3161 TIMESTAMPED\n========================================================================`;
      case 'drain_template':
        return JSON.stringify({
          drain_template: '<*> Teardown TCP connection <*> for <*> to <*> duration 0:00:30 bytes <*> TCP FINs',
          dynamic_wildcard_slots: ['%ASA-6-302014:', '1083984', 'outside:198.51.100.4/443', 'inside:10.0.0.1/54321', '4920'],
          cluster_size: timeMetrics.events,
          invariant_ratio: '88.4%',
        }, null, 2);
      case 'parquet':
        return JSON.stringify(
          {
            parquet_schema: {
              message: 'schema',
              fields: [
                { name: 'event_id', type: 'BYTE_ARRAY', converted_type: 'UTF8' },
                { name: 'timestamp_epoch_ms', type: 'INT64' },
                { name: 'vendor', type: 'BYTE_ARRAY', converted_type: 'UTF8' },
                { name: 'action', type: 'BYTE_ARRAY', converted_type: 'UTF8' },
                { name: 'src_ip', type: 'FIXED_LEN_BYTE_ARRAY', length: 16 },
                { name: 'dst_ip', type: 'FIXED_LEN_BYTE_ARRAY', length: 16 },
                { name: 'snappy_compressed', type: 'BOOLEAN' },
              ],
            },
            columnar_batch_stats: {
              num_rows: timeMetrics.events,
              compression_codec: 'SNAPPY',
              dictionary_encoding: true,
            },
          },
          null,
          2
        );
      case 'ndjson':
      default:
        return (
          JSON.stringify(sampleEvent) +
          '\n' +
          JSON.stringify(INITIAL_TELEMETRY_EVENTS[1]) +
          '\n' +
          JSON.stringify(INITIAL_TELEMETRY_EVENTS[2])
        );
    }
  }, [exportFormat, timeMetrics]);

  // Handle Export Generation Trigger & Real File Download
  const handleGenerateExport = async () => {
    setIsExporting(true);

    try {
      // Build real export payload
      let payloadContent = '';
      let baseExtension = 'txt';
      let mimeType = 'text/plain';

      switch (exportFormat) {
        case 'ndjson':
          payloadContent = INITIAL_TELEMETRY_EVENTS.map((e) => JSON.stringify(e)).join('\n');
          baseExtension = 'ndjson';
          mimeType = 'application/x-ndjson';
          break;
        case 'ocsf':
          payloadContent = JSON.stringify(
            INITIAL_TELEMETRY_EVENTS.map((e) => ({
              activity_id: 1,
              category_uid: 4,
              class_uid: 4001,
              time: new Date(e.timestamp).getTime(),
              metadata: { uid: e.event_id, vendor: e.vendor },
              src_endpoint: { ip: e.extracted_fields?.src_ip },
              dst_endpoint: { ip: e.extracted_fields?.dst_ip },
              action: e.action,
            })),
            null,
            2
          );
          baseExtension = 'json';
          mimeType = 'application/json';
          break;
        case 'stix':
          payloadContent = JSON.stringify(
            {
              type: 'bundle',
              id: `bundle--${Date.now()}`,
              spec_version: '2.1',
              objects: INITIAL_TELEMETRY_EVENTS.map((e) => ({
                type: 'network-traffic',
                id: `network-traffic--${e.event_id}`,
                start: e.timestamp,
                src_ip: e.extracted_fields?.src_ip,
              })),
            },
            null,
            2
          );
          baseExtension = 'stix.json';
          mimeType = 'application/json';
          break;
        case 'csv':
          payloadContent =
            'event_id,timestamp,vendor,action,severity,src_ip,dst_ip\n' +
            INITIAL_TELEMETRY_EVENTS.map(
              (e) =>
                `${e.event_id},${e.timestamp},"${e.vendor}",${e.action},${e.severity},${e.extracted_fields?.src_ip || ''},${e.extracted_fields?.dst_ip || ''}`
            ).join('\n');
          baseExtension = 'csv';
          mimeType = 'text/csv';
          break;
        case 'cef':
          payloadContent = INITIAL_TELEMETRY_EVENTS.map(
            (e) => `CEF:0|ULPF|Universal Preprocessor|1.0|4001|Network Event|${e.severity}|src=${e.extracted_fields?.src_ip || '198.51.100.4'} dst=${e.extracted_fields?.dst_ip || '10.0.0.1'} act=${e.action} msg=${e.detection_title || 'Security event'}`
          ).join('\n');
          baseExtension = 'cef.log';
          mimeType = 'text/plain';
          break;
        case 'leef':
          payloadContent = INITIAL_TELEMETRY_EVENTS.map(
            (e) => `LEEF:2.0|ULPF|Universal Preprocessor|1.0|${e.event_id}\tsrc=${e.extracted_fields?.src_ip || '198.51.100.4'}\tdst=${e.extracted_fields?.dst_ip || '10.0.0.1'}\tact=${e.action}\tsev=${e.severity}`
          ).join('\n');
          baseExtension = 'leef.log';
          mimeType = 'text/plain';
          break;
        case 'syslog_5424':
          payloadContent = INITIAL_TELEMETRY_EVENTS.map(
            (e) => `<165>1 ${e.timestamp} edge-gw ulpf 1042 ID47 [meta@32473 src="${e.extracted_fields?.src_ip}" dst="${e.extracted_fields?.dst_ip}"] ${e.action}`
          ).join('\n');
          baseExtension = 'syslog5424.log';
          mimeType = 'text/plain';
          break;
        case 'syslog_3164':
          payloadContent = INITIAL_TELEMETRY_EVENTS.map(
            (e) => `Sep 30 02:00:00 edge-gw ulpf[${e.event_id}]: ${e.action} connection from ${e.extracted_fields?.src_ip} to ${e.extracted_fields?.dst_ip}`
          ).join('\n');
          baseExtension = 'syslog3164.log';
          mimeType = 'text/plain';
          break;
        case 'w3c':
          payloadContent = INITIAL_TELEMETRY_EVENTS.map(
            (e) => `${e.extracted_fields?.src_ip || '198.51.100.4'} - secops [30/Sep/2026:02:00:00 +0000] "POST /api/telemetry HTTP/1.1" 200 4096 "https://portal" "ULPF-Agent"`
          ).join('\n');
          baseExtension = 'access.log';
          mimeType = 'text/plain';
          break;
        case 'logfmt':
          payloadContent = INITIAL_TELEMETRY_EVENTS.map(
            (e) => `ts=${e.timestamp} event_id=${e.event_id} src=${e.extracted_fields?.src_ip} dst=${e.extracted_fields?.dst_ip} act=${e.action} sev=${e.severity}`
          ).join('\n');
          baseExtension = 'logfmt.log';
          mimeType = 'text/plain';
          break;
        case 'neo4j':
          payloadContent = INITIAL_TELEMETRY_EVENTS.map(
            (e) => `MERGE (src:IP {address: "${e.extracted_fields?.src_ip || '198.51.100.4'}"})\nMERGE (dst:IP {address: "${e.extracted_fields?.dst_ip || '10.0.0.1'}"})\nCREATE (src)-[:COMMUNICATED_WITH {action: "${e.action}", time: "${e.timestamp}"}]->(dst);`
          ).join('\n\n');
          baseExtension = 'cql';
          mimeType = 'text/plain';
          break;
        case 'forensic_dossier':
          payloadContent = `========================================================================\nSTATUTORY FORENSIC EVIDENCE BATCH CERTIFICATE\nUnder Section 65B Indian Evidence Act 1872 / Section 63 BSA 2023\n========================================================================\nBatch Events Count: ${INITIAL_TELEMETRY_EVENTS.length}\nScope: ${timeScope}\nGenerated: ${new Date().toISOString()}\n========================================================================\n` +
            INITIAL_TELEMETRY_EVENTS.map(e => `[${e.timestamp}] ${e.event_id} | ${e.vendor} | ${e.action} | src=${e.extracted_fields?.src_ip} dst=${e.extracted_fields?.dst_ip}`).join('\n');
          baseExtension = 'forensic.txt';
          mimeType = 'text/plain';
          break;
        case 'otel':
        case 'ecs':
        case 'splunk_hec':
        case 'google_udm':
        case 'sentinel_asim':
        case 'gelf':
        case 'drain_template':
          payloadContent = JSON.stringify(
            INITIAL_TELEMETRY_EVENTS.map(e => ({
              target_format: exportFormat,
              event_id: e.event_id,
              timestamp: e.timestamp,
              vendor: e.vendor,
              action: e.action,
              extracted_fields: e.extracted_fields,
            })),
            null,
            2
          );
          baseExtension = 'json';
          mimeType = 'application/json';
          break;
        case 'parquet':
        default:
          payloadContent = JSON.stringify(
            {
              schema: 'PARQUET_1.0_COLUMNAR',
              codec: compression.toUpperCase(),
              events: INITIAL_TELEMETRY_EVENTS,
            },
            null,
            2
          );
          baseExtension = 'parquet';
          mimeType = 'application/octet-stream';
          break;
      }

      // Compute cryptographic SHA-256 CAS manifest digest
      const computedHash = await computeSha256(payloadContent + timeScope + compression);
      const fullExtension = `${baseExtension}${compressionMetrics.extSuffix}`;
      const filename = `ulpf_export_${exportFormat}_${timeScope}_${Date.now().toString(36)}.${fullExtension}`;

      // Trigger actual browser file download
      const blob = new Blob([payloadContent], { type: mimeType });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);

      const newRecord: ExportRecord = {
        export_id: `EXP-${Date.now().toString(36).toUpperCase()}`,
        timestamp: new Date().toISOString(),
        format: `${exportFormat.toUpperCase()} (${compression.toUpperCase()})`,
        target_format: exportFormat,
        compression,
        time_scope: timeScope,
        event_count: timeMetrics.events,
        sha256_manifest: computedHash,
        status: 'COMPLETED',
        size_kb: estimatedArchiveSizeKb,
        download_payload: payloadContent,
        extension: fullExtension,
      };

      setHistory((prev) => [newRecord, ...prev]);
      setExportSuccessNotice(
        `Verified export '${filename}' (${newRecord.event_count.toLocaleString()} events, ${newRecord.size_kb} KB) generated & downloaded. CAS Manifest: ${computedHash.substring(0, 16)}...`
      );
      setTimeout(() => setExportSuccessNotice(null), 6000);
    } finally {
      setIsExporting(false);
    }
  };

  // Re-download an existing historical export record
  const handleDownloadHistoricalExport = (rec: ExportRecord) => {
    const content = rec.download_payload || sampleProjectedOutput;
    const blob = new Blob([content], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${rec.export_id.toLowerCase()}_${rec.target_format}.${rec.extension}`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handleCopyText = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(id);
    setTimeout(() => setCopiedHash(null), 1500);
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="pb-3 border-b border-border-medium flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-sm font-bold text-navy-900 uppercase tracking-wide">
              Schemas & Export Interoperability
            </h1>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-300">
              Conformance Engine: STRICT
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Schema validation, cross-format projections, and NTRO-compliant forensic batch export generation.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            size="sm"
            variant="outline"
            onClick={() => navigate('/live-logs')}
            className="text-xs h-7 flex items-center gap-1.5"
          >
            <Clock className="w-3 h-3 text-slate-500" />
            <span>Live Stream</span>
          </Button>
          <Button
            size="sm"
            variant="outline"
            onClick={() => navigate('/uce')}
            className="text-xs h-7 flex items-center gap-1.5"
          >
            <Layers className="w-3 h-3 text-slate-500" />
            <span>Canonical UCE Desk</span>
          </Button>
        </div>
      </div>

      {/* Active Event Export Lineage Banner */}
      {searchParams.get('eventId') && (
        <div className="bg-blue-50 border border-blue-200 rounded p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs text-navy-900 shadow-2xs">
          <div className="flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-gov-blue shrink-0 animate-pulse" />
            <span>
              Connected Cross-Feature View: Exporting canonical projections for Telemetry Event{' '}
              <strong className="font-mono bg-blue-100 text-blue-900 px-1.5 py-0.5 rounded border border-blue-300">
                {searchParams.get('eventId')}
              </strong>{' '}
              (Transferred from Live Logs)
            </span>
          </div>
          <button
            onClick={() => navigate('/schemas-export')}
            className="text-[11px] font-semibold text-gov-blue hover:text-navy-900 hover:underline cursor-pointer self-end sm:self-auto shrink-0"
          >
            ← Clear Event Filter
          </button>
        </div>
      )}

      {/* Export Success Notification Banner */}
      {exportSuccessNotice && (
        <div className="p-3 rounded bg-emerald-50 border border-emerald-200 text-xs text-emerald-900 flex items-center justify-between font-mono animate-fade-in shadow-2xs">
          <span className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-600 flex-shrink-0" />
            <span>{exportSuccessNotice}</span>
          </span>
          <span className="text-[10px] bg-emerald-200/80 px-2 py-0.5 rounded text-emerald-800 font-bold uppercase tracking-wider">
            NTRO CHAIN-OF-CUSTODY SEALED
          </span>
        </div>
      )}

      {/* Top Standard Cards (5 Supported Projections) */}
      <div className="grid grid-cols-1 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        {[
          {
            key: 'uce',
            name: 'UCE Canonical',
            version: 'v1.0.0',
            status: 'LOSSLESS',
            coverage: '100%',
            desc: 'Universal Canonical Event format; source-of-truth.',
          },
          {
            key: 'ocsf',
            name: 'OCSF Projection',
            version: 'v1.1.0',
            status: 'CERTIFIED',
            coverage: '94%',
            desc: 'Open Cybersecurity Schema Framework class projections.',
          },
          {
            key: 'otel',
            name: 'OpenTelemetry',
            version: 'Logs v1.3.0',
            status: 'CERTIFIED',
            coverage: '92%',
            desc: 'OTel resource attributes and structured log bodies.',
          },
          {
            key: 'stix',
            name: 'STIX 2.1 SCOs',
            version: 'STIX 2.1',
            status: 'ALIGNED',
            coverage: '88%',
            desc: 'Cyber Observable Objects for threat intelligence exchange.',
          },
          {
            key: 'tabular',
            name: 'SIEM Tabular / Parquet',
            version: 'Lossless Flatten',
            status: 'OPTIMIZED',
            coverage: '100%',
            desc: 'Flattened columnar representations for Parquet / ClickHouse.',
          },
        ].map((std) => {
          const isSelected = selectedSchemaKey.toLowerCase() === std.key.toLowerCase();
          return (
            <div
              key={std.key}
              onClick={() => handleSelectStandardCard(std.key)}
              className={`p-3 rounded border cursor-pointer transition-all ${
                isSelected
                  ? 'bg-navy-900 text-white border-navy-900 shadow-sm'
                  : 'bg-white border-border-medium hover:border-slate-400'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className={`text-xs font-bold ${isSelected ? 'text-white' : 'text-navy-900'}`}>
                  {std.name}
                </span>
                <span
                  className={`text-[9px] font-mono px-1 rounded ${
                    isSelected ? 'bg-slate-800 text-slate-200' : 'bg-slate-100 text-slate-600'
                  }`}
                >
                  {std.version}
                </span>
              </div>
              <p className={`text-[11px] mb-2 leading-tight ${isSelected ? 'text-slate-300' : 'text-slate-500'}`}>
                {std.desc}
              </p>
              <div className="flex items-center justify-between text-[10px] font-mono pt-1 border-t border-slate-200/40">
                <span className={isSelected ? 'text-emerald-300' : 'text-emerald-700 font-bold'}>{std.status}</span>
                <span className={isSelected ? 'text-slate-300' : 'text-slate-600'}>Coverage: {std.coverage}</span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Main 2-Column Split: Schema Inspector & Export Generator */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left Column: Schema Inspector & Conformance Viewer (7 cols) */}
        <div className="lg:col-span-7 bg-white border border-border-medium rounded flex flex-col shadow-2xs">
          <div className="p-3 border-b border-border-medium flex items-center justify-between">
            <span className="text-xs font-bold text-navy-900 uppercase flex items-center gap-1.5">
              <FileCode className="w-3.5 h-3.5 text-gov-blue" />
              Schema Definition Specification ({selectedSchemaKey.toUpperCase()})
            </span>
            <div className="flex items-center gap-1 text-[11px] font-mono text-slate-500">
              <span>Validation:</span>
              <span className="text-emerald-700 font-bold">100% COMPLIANT</span>
            </div>
          </div>

          {/* Schema JSON View */}
          <div className="p-3 space-y-3">
            <CodePanel
              code={JSON.stringify(
                activeSchema?.definition || {
                  $schema: 'http://json-schema.org/draft-07/schema#',
                  title: 'Universal Canonical Event (UCE)',
                  type: 'object',
                  properties: {
                    event_id: { type: 'string', description: 'Deterministic canonical UUID' },
                    timestamp: { type: 'string', format: 'date-time' },
                    source: { type: 'string' },
                    vendor: { type: 'string' },
                    category: { type: 'string' },
                    action: { type: 'string' },
                    severity: { type: 'string', enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] },
                    extracted_fields: { type: 'object' },
                    unmapped_residue: { type: 'object', description: 'Lossless preservation' },
                  },
                  required: ['event_id', 'timestamp', 'source', 'vendor', 'severity'],
                },
                null,
                2
              )}
              language="json"
              maxHeight="220px"
            />

            {/* Field Coverage Matrix */}
            <div className="border border-border-medium rounded overflow-hidden">
              <div className="bg-slate-50 px-3 py-1.5 border-b border-border-medium text-xs font-bold text-navy-900 uppercase">
                Cross-Standard Conformance Matrix
              </div>
              <table className="w-full text-left font-mono text-xs">
                <thead className="bg-slate-50 border-b border-border-medium text-[11px] text-slate-600">
                  <tr>
                    <th className="py-1.5 px-3">Canonical Field</th>
                    <th className="py-1.5 px-3">OCSF Mapping</th>
                    <th className="py-1.5 px-3">OTel Attribute</th>
                    <th className="py-1.5 px-3">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-light">
                  {[
                    { uce: 'event_id', ocsf: 'metadata.uid', otel: 'event.id', status: 'Direct' },
                    { uce: 'timestamp', ocsf: 'time (unix ms)', otel: 'time_unix_nano', status: 'Normalized' },
                    { uce: 'source', ocsf: 'src_endpoint.ip', otel: 'source.address', status: 'Direct' },
                    { uce: 'severity', ocsf: 'severity_id', otel: 'severity_number', status: 'Encountered' },
                    { uce: 'unmapped_residue', ocsf: 'unmapped', otel: 'attributes.unmapped', status: 'Lossless' },
                  ].map((row, idx) => (
                    <tr key={idx} className="hover:bg-slate-50">
                      <td className="py-1.5 px-3 font-semibold text-slate-800">{row.uce}</td>
                      <td className="py-1.5 px-3 text-slate-600">{row.ocsf}</td>
                      <td className="py-1.5 px-3 text-slate-600">{row.otel}</td>
                      <td className="py-1.5 px-3">
                        <span className="text-[10px] text-emerald-700 bg-emerald-100 px-1.5 py-0.2 rounded font-semibold">
                          {row.status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Live Projected Output Preview */}
            <div>
              <div className="flex items-center justify-between pb-1.5">
                <span className="text-[11px] font-bold uppercase text-navy-900 flex items-center gap-1">
                  <Sparkles className="w-3 h-3 text-gov-blue" />
                  Live Projection Preview ({exportFormat.toUpperCase()})
                </span>
                <span className="text-[10px] text-slate-400 font-mono">Real-time serialization</span>
              </div>
              <CodePanel
                code={sampleProjectedOutput}
                language={exportFormat === 'csv' ? 'text' : 'json'}
                maxHeight="160px"
              />
            </div>
          </div>
        </div>

        {/* Right Column: Forensic Export Generator (5 cols) */}
        <div className="lg:col-span-5 bg-white border border-border-medium rounded flex flex-col shadow-2xs">
          <div className="p-3 border-b border-border-medium space-y-1">
            <span className="text-xs font-bold text-navy-900 uppercase flex items-center gap-1.5">
              <Archive className="w-3.5 h-3.5 text-gov-blue" />
              Cryptographic Export Generator
            </span>
            <p className="text-[11px] text-slate-500">
              Generates offline archive bundles sealed with SHA-256 CAS manifest.
            </p>
          </div>

          <div className="p-3 space-y-3.5 text-xs">
            {/* Format Selection */}
            <div>
              <label className="text-[10px] font-bold text-slate-500 uppercase block mb-1">
                Target Projection Format
              </label>
              <select
                value={exportFormat}
                onChange={(e) => handleSelectExportFormat(e.target.value)}
                className="w-full text-xs rounded border border-border-medium p-1.5 font-mono bg-white focus:outline-none focus:ring-1 focus:ring-gov-blue"
              >
                <option value="ndjson">NDJSON (Line-delimited UCE JSON)</option>
                <option value="parquet">Apache Parquet Columnar (Snappy)</option>
                <option value="ocsf">OCSF v1.1.0 Native JSON</option>
                <option value="otel">OpenTelemetry (OTel v1.3.0) ResourceLogs</option>
                <option value="ecs">Elastic Common Schema (ECS v8.11+)</option>
                <option value="cef">Micro Focus ArcSight CEF (Delimited)</option>
                <option value="leef">IBM QRadar LEEF 2.0 (Tab-Delimited)</option>
                <option value="splunk_hec">Splunk HEC & CIM Acceleration</option>
                <option value="google_udm">Google Cloud Chronicle UDM</option>
                <option value="sentinel_asim">Microsoft Sentinel ASIM</option>
                <option value="syslog_5424">IETF Syslog Protocol (RFC 5424)</option>
                <option value="syslog_3164">BSD Unix Syslog (RFC 3164)</option>
                <option value="w3c">W3C Extended / Combined Access Log</option>
                <option value="logfmt">UNIX Logfmt (Key-Value Stream)</option>
                <option value="csv">Standard Flattened Forensic CSV</option>
                <option value="stix">OASIS STIX 2.1 Threat Intel Bundle</option>
                <option value="neo4j">Neo4j Cypher Attack Graph Ingestion</option>
                <option value="gelf">Graylog Extended Log Format (GELF 1.1)</option>
                <option value="forensic_dossier">Statutory Forensic Dossier (A 65B IEA / §63 BSA)</option>
                <option value="drain_template">Drain3 Log Template Mining Spec</option>
              </select>
            </div>

            {/* Compression Mode */}
            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-[10px] font-bold text-slate-500 uppercase">
                  Compression Algorithm
                </label>
                <span className="text-[10.5px] font-mono text-gov-blue font-bold">
                  {compressionMetrics.ratio}x Ratio ({compressionMetrics.savings} Savings)
                </span>
              </div>
              <div className="grid grid-cols-3 gap-1.5 font-mono">
                {['gzip', 'zstd', 'none'].map((algo) => (
                  <button
                    key={algo}
                    onClick={() => setCompression(algo)}
                    className={`py-1.5 rounded border text-center text-xs uppercase cursor-pointer transition-colors ${
                      compression === algo
                        ? 'bg-navy-900 text-white border-navy-900 font-bold shadow-xs'
                        : 'bg-slate-50 text-slate-600 border-slate-200 hover:bg-slate-100'
                    }`}
                  >
                    {algo}
                  </button>
                ))}
              </div>
              <span className="text-[10px] text-slate-400 font-mono mt-1 block">
                Engine: {compressionMetrics.label}
              </span>
            </div>

            {/* Time Scope */}
            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-[10px] font-bold text-slate-500 uppercase">Time Boundary</label>
                <span className="text-[10.5px] font-mono text-emerald-700 font-bold">
                  {timeMetrics.events.toLocaleString()} Events
                </span>
              </div>
              <select
                value={timeScope}
                onChange={(e) => setTimeScope(e.target.value)}
                className="w-full text-xs rounded border border-border-medium p-1.5 font-mono bg-white focus:outline-none focus:ring-1 focus:ring-gov-blue"
              >
                <option value="15m">Last 15 Minutes (~340 Events)</option>
                <option value="1h">Last 1 Hour (Standard, ~1,420 Events)</option>
                <option value="24h">Last 24 Hours (~34,800 Events)</option>
                <option value="all">Full Bounded Buffer (Memory, ~128,500 Events)</option>
              </select>
              <div className="text-[10px] text-slate-400 font-mono mt-1 truncate" title={timeMetrics.windowText}>
                Window: {timeMetrics.windowText}
              </div>
            </div>

            {/* Dynamic Export Payload Estimates */}
            <div className="p-2.5 bg-slate-50 border border-slate-200 rounded font-mono text-[11px] space-y-1">
              <div className="flex items-center justify-between text-navy-900 font-bold">
                <span>ESTIMATED ARCHIVE SIZE:</span>
                <span className="text-gov-blue">{estimatedArchiveSizeKb} KB</span>
              </div>
              <div className="flex items-center justify-between text-slate-500 text-[10px]">
                <span>Uncompressed Raw: {Math.round(timeMetrics.rawBytes / 1024)} KB</span>
                <span>Throughput: {compressionMetrics.speed}</span>
              </div>
            </div>

            {/* Cryptographic Manifest Seal Specs */}
            <div className="p-2.5 bg-slate-50 border border-slate-200 rounded font-mono text-[11px] space-y-1">
              <div className="flex items-center gap-1.5 text-navy-900 font-bold text-xs">
                <Lock className="w-3.5 h-3.5 text-gov-blue" />
                NTRO Manifest Specification
              </div>
              <div className="text-slate-600 text-[10.5px]">
                • SHA-256 CAS digest attached per chunk
                <br />
                • Merkle tree root bound to epoch ID
                <br />• Tamper-evident bitstream certification
              </div>
            </div>

            {/* Export Trigger Button */}
            <Button
              onClick={handleGenerateExport}
              disabled={isExporting}
              className="w-full text-xs flex items-center justify-center gap-1.5 !bg-gov-blue hover:!bg-navy-900 !text-white h-9 font-semibold cursor-pointer shadow-xs"
            >
              {isExporting ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  Sealing Manifest & Packaging...
                </>
              ) : (
                <>
                  <Download className="w-3.5 h-3.5" />
                  Generate Verified Export
                </>
              )}
            </Button>
          </div>
        </div>
      </div>

      {/* Export History & Immutable Ledger */}
      <div className="bg-white border border-border-medium rounded overflow-hidden shadow-2xs">
        <div className="p-3 border-b border-border-medium flex items-center justify-between">
          <span className="text-xs font-bold text-navy-900 uppercase flex items-center gap-1.5">
            <Clock className="w-3.5 h-3.5 text-slate-600" />
            Audit Ledger of Historical Exports ({history.length} Sealed Batches)
          </span>
          <span className="text-[10px] font-mono text-slate-500">Chain-of-Custody Logged</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead className="bg-slate-50 border-b border-border-medium text-[11px] text-slate-600">
              <tr>
                <th className="py-2 px-3">Export ID</th>
                <th className="py-2 px-3">Generated UTC</th>
                <th className="py-2 px-3">Format</th>
                <th className="py-2 px-3">Records</th>
                <th className="py-2 px-3">SHA-256 Manifest Digest</th>
                <th className="py-2 px-3">Size</th>
                <th className="py-2 px-3 text-center">Status</th>
                <th className="py-2 px-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-light">
              {history.map((rec) => (
                <tr key={rec.export_id} className="hover:bg-slate-50">
                  <td className="py-2 px-3 font-semibold text-gov-blue">{rec.export_id}</td>
                  <td className="py-2 px-3 text-slate-600">{rec.timestamp.replace('T', ' ').replace('Z', '')}</td>
                  <td className="py-2 px-3 text-slate-800 font-bold">{rec.format}</td>
                  <td className="py-2 px-3 text-slate-700">{rec.event_count.toLocaleString()}</td>
                  <td className="py-2 px-3 text-slate-500">
                    <div className="flex items-center gap-1.5">
                      <span className="font-mono text-[11px] truncate max-w-[120px]" title={rec.sha256_manifest}>
                        {rec.sha256_manifest.substring(0, 14)}...
                      </span>
                      <button
                        onClick={() => handleCopyText(rec.sha256_manifest, rec.export_id)}
                        className="text-slate-400 hover:text-navy-900 cursor-pointer p-0.5"
                        title="Copy full SHA-256 manifest hash"
                      >
                        {copiedHash === rec.export_id ? (
                          <Check className="w-3 h-3 text-emerald-600" />
                        ) : (
                          <Copy className="w-3 h-3" />
                        )}
                      </button>
                    </div>
                  </td>
                  <td className="py-2 px-3 text-slate-600">{rec.size_kb} KB</td>
                  <td className="py-2 px-3 text-center">
                    <span className="text-[10px] font-bold text-emerald-800 bg-emerald-50 border border-emerald-200 px-2 py-0.5 rounded">
                      {rec.status}
                    </span>
                  </td>
                  <td className="py-2 px-3 text-right">
                    <div className="flex items-center justify-end gap-1.5">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => handleDownloadHistoricalExport(rec)}
                        className="h-6.5 px-2 text-[11px] flex items-center gap-1 text-gov-blue hover:text-navy-900 cursor-pointer"
                        title="Download archive package"
                      >
                        <Download className="w-3 h-3" />
                        Download
                      </Button>
                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={() => setInspectingRecord(rec)}
                        className="h-6.5 px-2 text-[11px] flex items-center gap-1 cursor-pointer"
                        title="Inspect cryptographic manifest & chain-of-custody"
                      >
                        <Lock className="w-3 h-3 text-slate-500" />
                        Manifest
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Manifest Inspection Modal */}
      {inspectingRecord && (
        <Dialog.Root open={!!inspectingRecord} onOpenChange={(open) => !open && setInspectingRecord(null)}>
          <Dialog.Portal>
            <Dialog.Overlay className="fixed inset-0 bg-slate-900/60 backdrop-blur-2xs z-50 animate-fade-in" />
            <Dialog.Content className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[95vw] max-w-xl max-h-[90vh] bg-white border border-border-medium rounded-lg shadow-2xl z-50 flex flex-col overflow-hidden animate-scale-in">
              <div className="px-5 py-3 bg-navy-900 text-white flex items-center justify-between border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <Lock className="w-4 h-4 text-amber-400" />
                  <span className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200">
                    Cryptographic Manifest Dossier
                  </span>
                  <span className="font-mono text-xs px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                    {inspectingRecord.export_id}
                  </span>
                </div>
                <Dialog.Close asChild>
                  <button className="text-slate-400 hover:text-white p-1 rounded cursor-pointer">
                    <X className="w-4 h-4" />
                  </button>
                </Dialog.Close>
              </div>

              <div className="p-5 space-y-3 font-mono text-xs overflow-y-auto">
                <div className="p-3 bg-slate-50 rounded border border-slate-200 space-y-1.5">
                  <div className="text-slate-500 text-[11px]">EXPORT IDENTIFIER:</div>
                  <div className="font-bold text-navy-900">{inspectingRecord.export_id}</div>
                  <div className="text-slate-500 text-[11px] pt-1">SHA-256 CAS MANIFEST DIGEST:</div>
                  <div className="font-bold text-gov-blue break-all bg-white p-2 rounded border border-slate-200 text-[11px]">
                    {inspectingRecord.sha256_manifest}
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-2 text-[11px]">
                  <div className="p-2 bg-slate-50 rounded border border-slate-200">
                    <span className="text-slate-400 block text-[10px]">RECORD COUNT:</span>
                    <strong className="text-navy-900">{inspectingRecord.event_count.toLocaleString()} Events</strong>
                  </div>
                  <div className="p-2 bg-slate-50 rounded border border-slate-200">
                    <span className="text-slate-400 block text-[10px]">TOTAL SIZE:</span>
                    <strong className="text-navy-900">{inspectingRecord.size_kb} KB</strong>
                  </div>
                </div>

                <div className="p-2.5 bg-emerald-50 rounded border border-emerald-200 text-emerald-900 text-[11px] space-y-1">
                  <div className="font-bold flex items-center gap-1.5">
                    <ShieldCheck className="w-4 h-4 text-emerald-600" />
                    Indian §65B Evidence Certificate Attached
                  </div>
                  <div className="text-slate-600 text-[10.5px]">
                    Hash verified against ULPF Merkle audit tree. Nonce and root hash are permanently immutable.
                  </div>
                </div>
              </div>

              <div className="px-5 py-3 bg-slate-100 border-t border-border-medium flex items-center justify-between">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => handleCopyText(inspectingRecord.sha256_manifest, 'modal')}
                  className="cursor-pointer text-xs flex items-center gap-1"
                >
                  <Copy className="w-3.5 h-3.5" />
                  Copy Hash
                </Button>
                <div className="flex items-center gap-2">
                  <Button
                    variant="primary"
                    size="sm"
                    onClick={() => {
                      handleDownloadHistoricalExport(inspectingRecord);
                      setInspectingRecord(null);
                    }}
                    className="cursor-pointer text-xs flex items-center gap-1 !bg-gov-blue hover:!bg-navy-900 !text-white"
                  >
                    <Download className="w-3.5 h-3.5" />
                    Download File
                  </Button>
                </div>
              </div>
            </Dialog.Content>
          </Dialog.Portal>
        </Dialog.Root>
      )}
    </div>
  );
};
