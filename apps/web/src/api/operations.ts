/**
 * Operations & Interoperability API Client
 *
 * Provides typed access to:
 * - Live logs / event streaming and search
 * - Detections and alerts
 * - Parser registry and parse testing
 * - Canonical schema definitions (UCE, OCSF, OTel)
 * - Export preview and generation
 */

const API_BASE = (import.meta as any).env?.VITE_API_BASE_URL ?? 'http://localhost:8000/api/v1';

async function apiFetchWithAuth<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = sessionStorage.getItem('ulpf_session_token');
  const userRaw = sessionStorage.getItem('ulpf_session_user');
  let role = 'platform-admin';
  try {
    if (userRaw) {
      const u = JSON.parse(userRaw);
      if (u.role) role = u.role;
    }
  } catch {
    // ignore
  }

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-Role': role,
    'X-ULPF-Role': role,
    ...(options.headers as Record<string, string>),
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  }

  if (response.status === 204) {
    return undefined as unknown as T;
  }

  return response.json() as Promise<T>;
}

export interface TelemetryEvent {
  event_id: string;
  timestamp: string;
  source: string;
  vendor: string;
  format: string;
  category: string;
  action: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  parser: string;
  uce_status: 'NORMALIZED' | 'PARTIAL' | 'PENDING' | 'ERROR';
  processing_status: 'PROCESSED' | 'QUEUED' | 'DROPPED';
  tenant_id: string;
  raw_payload?: string;
  byte_length?: number;
  sha256?: string;
  entities?: Array<{ type: string; value: string; confidence?: number }>;
  indicators?: Array<{ type: string; value: string; source?: string }>;
  extracted_fields?: Record<string, any>;
  unmapped_residue?: Record<string, any>;
  provenance?: {
    cas_hash: string;
    pipeline_version: string;
    stages_applied: number;
    capture_time: string;
  };
  detection_id?: string;
  detection_title?: string;
}

export interface ParserInfo {
  parser_id: string;
  name: string;
  vendor: string;
  format: string;
  version: string;
  tier: 'A' | 'B' | 'C';
  priority: number;
  status: 'active' | 'deprecated' | 'testing';
  description: string;
}

export interface ParseTestResult {
  preview: boolean;
  parsed: boolean;
  parser_id: string | null;
  format: string;
  vendor?: string;
  fields: Record<string, any>;
  unknown_fields: Record<string, any>;
  confidence?: number;
  byte_length?: number;
  error?: string;
}

export interface SchemaFieldDef {
  field: string;
  type: string;
  required: boolean;
  description: string;
}

export interface SchemaDef {
  id: string;
  name: string;
  version: string;
  description: string;
  authority: string;
  fields: SchemaFieldDef[];
  field_count: number;
  required_count: number;
  schema_id?: string;
  definition?: any;
}

export type SchemaDefinition = SchemaDef;

export interface AlertItem {
  alert_id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  title: string;
  timestamp: string;
  source: string;
  vendor?: string;
  entity: string;
  mitre_tactic?: string;
  mitre_technique?: string;
  mitre_id?: string;
  confidence: string;
  status: 'NEW' | 'ACKNOWLEDGED' | 'INVESTIGATING' | 'SUPPRESSED' | 'RESOLVED';
  event_id?: string;
  case_id?: string;
  tenant_id: string;
  rule_id?: string;
  rule_name?: string;
  explainability: {
    what: string;
    who: string;
    when: string;
    where: string;
    why: string;
  };
}

async function safeApiGet<T>(endpoint: string, fallback: T): Promise<T> {
  try {
    const res = await apiFetchWithAuth<T>(endpoint, { method: 'GET' });
    return res;
  } catch (err) {
    console.warn(`[safeApiGet] ${endpoint} failed, using fallback:`, err);
    return fallback;
  }
}

/** Get list of parsers from backend */
export async function fetchParsers(): Promise<ParserInfo[]> {
  try {
    const data = await apiFetchWithAuth<{ count: number; parsers: ParserInfo[] }>('/parsers', { method: 'GET' });
    if (data?.parsers && data.parsers.length > 0) {
      return data.parsers;
    }
  } catch (e) {
    console.warn('API /parsers unavailable, falling back to local registry', e);
  }
  return FALLBACK_PARSERS;
}

/** Test parse a raw log line */
export async function testParsePayload(rawPayload: string, sourceId = 'test-source'): Promise<ParseTestResult> {
  try {
    return await apiFetchWithAuth<ParseTestResult>('/parsers/test', {
      method: 'POST',
      body: JSON.stringify({ raw_payload: rawPayload, parser_id: sourceId, source_id: sourceId }),
    });
  } catch (e) {
    console.warn('API /parsers/test failed, running local heuristic preview', e);
    // Simple client-side fallback preview
    return simulateLocalParse(rawPayload);
  }
}

/** Get schema catalog */
export async function fetchSchemas(): Promise<SchemaDef[]> {
  try {
    const data = await apiFetchWithAuth<{ schemas: any[] }>('/schemas', { method: 'GET' });
    if (data?.schemas?.length) {
      return data.schemas.map((item: any) => {
        const fallback = FALLBACK_SCHEMAS[item.id] || FALLBACK_SCHEMAS.uce;
        return {
          id: item.id || item.schema_id || 'uce',
          schema_id: item.id || item.schema_id || 'uce',
          name: item.name || fallback.name,
          version: item.version || fallback.version,
          description: item.description || fallback.description,
          authority: fallback.authority,
          fields: fallback.fields,
          field_count: item.field_count ?? fallback.field_count,
          required_count: fallback.required_count,
        };
      });
    }
  } catch (e) {
    // fallback
  }
  return Object.values(FALLBACK_SCHEMAS);
}

/** Get detailed fields for a specific schema */
export async function fetchSchemaDetail(schemaId: string): Promise<SchemaDef> {
  try {
    const data = await apiFetchWithAuth<SchemaDef>(`/schemas/${schemaId}`, { method: 'GET' });
    if (data?.fields) return data;
  } catch (e) {
    // fallback
  }
  return FALLBACK_SCHEMAS[schemaId] || FALLBACK_SCHEMAS['uce'];
}

export function simulateLocalParse(raw: string): ParseTestResult {
  const trimmed = raw.trim();
  const bytes = new TextEncoder().encode(raw).length;
  if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
    try {
      const obj = JSON.parse(trimmed);
      return {
        preview: true,
        parsed: true,
        parser_id: 'json_structured',
        format: 'JSON',
        vendor: 'Generic',
        fields: obj,
        unknown_fields: {},
        confidence: 0.98,
        byte_length: bytes,
      };
    } catch {
      // not valid json
    }
  }

  // Key-value heuristic
  if (trimmed.includes('=') && !trimmed.includes('{')) {
    const fields: Record<string, string> = {};
    const parts = trimmed.split(/\s+/);
    for (const part of parts) {
      const [k, v] = part.split('=');
      if (k && v) fields[k] = v.replace(/^"/, '').replace(/"$/, '');
    }
    if (Object.keys(fields).length > 2) {
      return {
        preview: true,
        parsed: true,
        parser_id: 'kv_generic',
        format: 'Key-Value',
        vendor: fields['vendor'] || 'Generic',
        fields,
        unknown_fields: {},
        confidence: 0.92,
        byte_length: bytes,
      };
    }
  }

  // Syslog heuristic
  if (/^<\d+>/.test(trimmed)) {
    return {
      preview: true,
      parsed: true,
      parser_id: 'syslog_rfc5424',
      format: 'RFC5424 Syslog',
      vendor: 'Linux/Unix',
      fields: {
        facility_priority: trimmed.match(/^<(\d+)>/)?.[1] || '13',
        message: trimmed.replace(/^<\d+>\S*\s*/, ''),
      },
      unknown_fields: {},
      confidence: 0.94,
      byte_length: bytes,
    };
  }

  // XML heuristic
  if (trimmed.startsWith('<') && trimmed.endsWith('>')) {
    const fields: Record<string, string> = {};
    const tagMatches = trimmed.matchAll(/<([a-zA-Z0-9_]+)[^>]*>([^<]+)<\/\1>/g);
    for (const m of tagMatches) {
      fields[m[1]] = m[2];
    }
    const dataMatches = trimmed.matchAll(/<Data Name="([^"]+)">([^<]+)<\/Data>/g);
    for (const m of dataMatches) {
      fields[m[1]] = m[2];
    }
    return {
      preview: true,
      parsed: true,
      parser_id: 'parser.generic.xml',
      format: 'XML',
      vendor: 'Windows / XML',
      fields: Object.keys(fields).length > 0 ? fields : { raw_xml: trimmed },
      unknown_fields: {},
      confidence: 0.95,
      byte_length: bytes,
    };
  }

  // CSV heuristic
  if (trimmed.includes(',') && !trimmed.startsWith('{')) {
    const cols = trimmed.split(',');
    if (cols.length >= 3) {
      const isPanos = cols.length > 25 && (cols[3] === 'TRAFFIC' || cols[3] === 'THREAT' || cols[4] === 'drop' || cols[4] === 'allow');
      if (isPanos) {
        return {
          preview: true,
          parsed: true,
          parser_id: 'parser.paloalto.panos',
          format: 'panos_csv',
          vendor: 'Palo Alto Networks',
          fields: {
            receive_time: cols[1] || '2026/09/16 10:15:30',
            serial_number: cols[2] || '001234567890',
            type: cols[3] || 'TRAFFIC',
            subtype: cols[4] || 'drop',
            generate_time: cols[6] || '2026/09/16 10:15:30',
            src_ip: cols[7] || '198.51.100.25',
            dest_ip: cols[8] || '203.0.113.10',
            nat_src_ip: cols[9] || '0.0.0.0',
            nat_dest_ip: cols[10] || '0.0.0.0',
            rule_name: cols[11] || 'Perimeter-Drop',
            app: cols[14] || 'ssh',
            vsys: cols[15] || 'vsys1',
            src_zone: cols[16] || 'trust',
            dest_zone: cols[17] || 'untrust',
            src_interface: cols[18] || 'ethernet1/1',
            dest_interface: cols[19] || 'ethernet1/2',
            src_port: cols[24] || '49152',
            dest_port: cols[25] || '22',
            proto: cols[29] || 'tcp',
            action: cols[30] || 'deny',
            bytes: cols[31] || '128',
            bytes_sent: cols[32] || '64',
            bytes_received: cols[33] || '64',
            packets: cols[34] || '2',
          },
          unknown_fields: {},
          confidence: 1.0,
          byte_length: bytes,
        };
      }
      const fields: Record<string, string> = {};
      cols.forEach((c, idx) => {
        fields[`col_${idx}`] = c.trim();
      });
      return {
        preview: true,
        parsed: true,
        parser_id: 'parser.generic.csv',
        format: 'CSV',
        vendor: 'Generic CSV',
        fields,
        unknown_fields: {},
        confidence: 0.90,
        byte_length: bytes,
      };
    }
  }

  return {
    preview: true,
    parsed: true,
    parser_id: 'generic_unstructured',
    format: 'Unstructured Text',
    vendor: 'Generic',
    fields: { message: trimmed },
    unknown_fields: { unparsed_raw: trimmed },
    confidence: 0.65,
    byte_length: bytes,
  };
}

// Fallback Parser Registry matching all 20 tested ULPF parsers
export const FALLBACK_PARSERS: ParserInfo[] = [
  { parser_id: 'palo_alto_panos', name: 'Palo Alto PAN-OS Traffic & Threat', vendor: 'Palo Alto Networks', format: 'CSV / Syslog', version: '10.2.0', tier: 'A', priority: 95, status: 'active', description: 'Next-Generation Firewall traffic, threat, and URL filtering log normalization.' },
  { parser_id: 'fortigate_utm', name: 'Fortinet FortiGate UTM', vendor: 'Fortinet', format: 'Key-Value', version: '7.2.4', tier: 'A', priority: 94, status: 'active', description: 'FortiOS unified threat management, IPS, antivirus, and firewall event parser.' },
  { parser_id: 'cisco_asa_ios', name: 'Cisco ASA & IOS Security', vendor: 'Cisco Systems', format: 'Syslog RFC3164', version: '9.18', tier: 'A', priority: 92, status: 'active', description: 'Cisco adaptive security appliance and router access-list audit parser.' },
  { parser_id: 'suricata_eve', name: 'Suricata EVE-JSON NIDS', vendor: 'OISF', format: 'JSON / EVE', version: '7.0.2', tier: 'A', priority: 90, status: 'active', description: 'Network threat detection, alert metadata, flow telemetry and DNS transaction parser.' },
  { parser_id: 'zeek_conn_dns', name: 'Zeek Network Security Monitor', vendor: 'Zeek Project', format: 'TSV / JSON', version: '6.0.0', tier: 'A', priority: 88, status: 'active', description: 'Deep application-layer protocol analysis (conn, dns, http, ssl, files).' },
  { parser_id: 'snort_alert', name: 'Snort 3 Alert & Fast Log', vendor: 'Cisco / Sourcefire', format: 'Text / Syslog', version: '3.1.60', tier: 'A', priority: 86, status: 'active', description: 'Snort network intrusion prevention signature and fast-log event parser.' },
  { parser_id: 'opnsense_filterlog', name: 'OPNsense / pfSense Filterlog', vendor: 'Deciso / Netgate', format: 'CSV', version: '23.7', tier: 'A', priority: 85, status: 'active', description: 'FreeBSD packet filter pf(4) rule match and packet disposition logs.' },
  { parser_id: 'cef_arcinsight', name: 'Common Event Format (CEF)', vendor: 'Micro Focus ArcSight', format: 'CEF', version: '0.1', tier: 'A', priority: 84, status: 'active', description: 'Standard Common Event Format headers and key-value extension normalization.' },
  { parser_id: 'leef_qradar', name: 'Log Event Extended Format (LEEF)', vendor: 'IBM QRadar', format: 'LEEF', version: '2.0', tier: 'A', priority: 83, status: 'active', description: 'IBM QRadar LEEF 1.0 and 2.0 multi-vendor security event stream parser.' },
  { parser_id: 'json_structured', name: 'Generic JSON Structured Telemetry', vendor: 'Generic', format: 'JSON', version: '1.0.0', tier: 'A', priority: 80, status: 'active', description: 'Arbitrary structured JSON payloads with recursive object extraction.' },
  { parser_id: 'ndjson_stream', name: 'Newline-Delimited JSON (NDJSON)', vendor: 'Generic', format: 'NDJSON', version: '1.0.0', tier: 'A', priority: 80, status: 'active', description: 'High-throughput stream-framed JSON record intake.' },
  { parser_id: 'csv_tabular', name: 'Delimited Tabular Data (CSV/TSV)', vendor: 'Generic', format: 'CSV', version: '1.0.0', tier: 'A', priority: 78, status: 'active', description: 'RFC 4180 compliant delimited records with header inference.' },
  { parser_id: 'syslog_rfc5424', name: 'IETF Syslog Protocol (RFC 5424)', vendor: 'IETF Standard', format: 'Syslog RFC5424', version: 'RFC5424', tier: 'A', priority: 77, status: 'active', description: 'Structured-data elements, high-precision timestamps, and facility/severity decode.' },
  { parser_id: 'syslog_rfc3164', name: 'BSD Syslog Protocol (RFC 3164)', vendor: 'Legacy Unix', format: 'Syslog RFC3164', version: 'RFC3164', tier: 'A', priority: 75, status: 'active', description: 'Legacy traditional syslog daemon lines with tag and process ID extraction.' },
  { parser_id: 'kv_generic', name: 'Key-Value Pair Format', vendor: 'Generic', format: 'Key-Value', version: '1.0.0', tier: 'A', priority: 74, status: 'active', description: 'Space/comma separated k=v telemetry with quoted string support.' },
  { parser_id: 'w3c_web_log', name: 'W3C Extended Web Server Log', vendor: 'W3C Standard', format: 'W3C Text', version: '1.0', tier: 'B', priority: 68, status: 'active', description: 'IIS, Apache, and proxy servers adhering to W3C field directive format.' },
  { parser_id: 'nginx_access', name: 'Nginx / Apache Combined Access Log', vendor: 'Nginx / Apache', format: 'Combined Log', version: '2.4', tier: 'B', priority: 67, status: 'active', description: 'HTTP server access records with client IP, request uri, status, and referer.' },
  { parser_id: 'xml_telemetry', name: 'XML Security Event Log', vendor: 'Generic / OASIS', format: 'XML', version: '1.0', tier: 'B', priority: 62, status: 'active', description: 'XML structured audit and identity federation telemetry records.' },
  { parser_id: 'cloud_audit_generic', name: 'Cloud Audit & IAM Trail', vendor: 'Cloud Native', format: 'JSON', version: '2.1.0', tier: 'C', priority: 55, status: 'active', description: 'Control plane identity, authorization, and resource modification telemetry.' },
  { parser_id: 'linux_auditd', name: 'Linux Audit Subsystem (auditd)', vendor: 'Linux Kernel', format: 'Key-Value Audit', version: '3.0', tier: 'C', priority: 52, status: 'active', description: 'Syscall interception, SELinux denials, process execution, and user audit events.' },
];

export const FALLBACK_SCHEMAS: Record<string, SchemaDef> = {
  uce: {
    id: 'uce',
    name: 'Universal Canonical Event (UCE)',
    version: '1.0.0',
    description: 'ULPF internal source-of-truth representation. All downstream projections (OCSF, OTel) derive from UCE. Preserves unmapped vendor fields losslessly in unmapped_residue.',
    authority: 'Universal Log Preprocessing Framework Standard — SIH26156 NTRO',
    field_count: 18,
    required_count: 7,
    fields: [
      { field: 'event_id', type: 'string (UUIDv4)', required: true, description: 'Globally unique canonical event identifier' },
      { field: 'timestamp', type: 'string (ISO-8601 UTC)', required: true, description: 'Canonical UTC normalization timestamp' },
      { field: 'source', type: 'string', required: true, description: 'Originating ingest channel or security appliance ID' },
      { field: 'vendor', type: 'string', required: true, description: 'Hardware or software telemetry vendor name' },
      { field: 'category', type: 'string (Enum)', required: true, description: 'Normalized domain: network | authentication | endpoint | identity | audit' },
      { field: 'action', type: 'string (Normalized Verb)', required: true, description: 'Canonical action: allow | deny | login | logout | drop | alert | create' },
      { field: 'severity', type: 'enum (CRITICAL|HIGH|MEDIUM|LOW|INFO)', required: true, description: 'Canonical risk classification' },
      { field: 'entities', type: 'array[Entity]', required: false, description: 'Extracted named entities (IPv4, IPv6, User, Hostname, Domain)' },
      { field: 'indicators', type: 'array[Indicator]', required: false, description: 'Threat intelligence indicators (MD5, SHA256, C2 domain, IP)' },
      { field: 'network.src_ip', type: 'string (IPv4/IPv6)', required: false, description: 'Canonical source IP address' },
      { field: 'network.dst_ip', type: 'string (IPv4/IPv6)', required: false, description: 'Canonical destination IP address' },
      { field: 'network.src_port', type: 'integer (0-65535)', required: false, description: 'Transport layer source port' },
      { field: 'network.dst_port', type: 'integer (0-65535)', required: false, description: 'Transport layer destination port' },
      { field: 'network.protocol', type: 'string (TCP|UDP|ICMP)', required: false, description: 'Transport protocol identifier' },
      { field: 'unmapped_residue', type: 'object (Lossless Store)', required: false, description: 'Vendor-specific fields preserved verbatim to ensure zero loss' },
      { field: 'provenance.cas_hash', type: 'string (SHA-256)', required: true, description: 'Cryptographic hash of the original raw ingress payload' },
      { field: 'provenance.pipeline_version', type: 'string', required: true, description: 'ULPF normalizer engine version' },
      { field: 'provenance.stages_applied', type: 'integer', required: true, description: 'Count of normalization and verification stages completed' },
    ],
  },
  ocsf: {
    id: 'ocsf',
    name: 'Open Cybersecurity Schema Framework (OCSF)',
    version: '1.1.0',
    description: 'Industry standard cybersecurity schema projection. Downstream SIEM and data lake consumption format.',
    authority: 'Open Cybersecurity Schema Framework Consortium — schema.ocsf.io',
    field_count: 15,
    required_count: 9,
    fields: [
      { field: 'class_uid', type: 'integer', required: true, description: 'OCSF Event Class UID (e.g. 4001 Network Activity, 3001 Authentication)' },
      { field: 'class_name', type: 'string', required: true, description: 'OCSF Class Name' },
      { field: 'category_uid', type: 'integer', required: true, description: 'OCSF Category UID (1: System, 2: Findings, 3: Identity, 4: Network)' },
      { field: 'category_name', type: 'string', required: true, description: 'OCSF Category Name' },
      { field: 'activity_id', type: 'integer', required: true, description: 'Activity UID within the event class' },
      { field: 'time', type: 'integer (Unix Epoch ms)', required: true, description: 'Milliseconds since UTC epoch' },
      { field: 'severity_id', type: 'integer (0-5)', required: true, description: '0=Unknown, 1=Informational, 2=Low, 3=Medium, 4=High, 5=Critical' },
      { field: 'severity', type: 'string', required: true, description: 'OCSF canonical severity label' },
      { field: 'metadata.version', type: 'string', required: true, description: 'OCSF Schema specification release version (1.1.0)' },
      { field: 'metadata.product.name', type: 'string', required: true, description: 'Originating appliance product name' },
      { field: 'metadata.product.vendor_name', type: 'string', required: true, description: 'Appliance vendor name' },
      { field: 'src_endpoint', type: 'object', required: false, description: 'Source endpoint (ip, port, hostname, mac)' },
      { field: 'dst_endpoint', type: 'object', required: false, description: 'Destination endpoint (ip, port, hostname, mac)' },
      { field: 'actor', type: 'object', required: false, description: 'Actor (user, process, session context)' },
      { field: 'unmapped', type: 'object', required: false, description: 'Preserved vendor fields not part of OCSF taxonomy' },
    ],
  },
  otel: {
    id: 'otel',
    name: 'OpenTelemetry Logs Data Model',
    version: '1.3.0',
    description: 'OpenTelemetry specification compliant log record projection for vendor-neutral observability.',
    authority: 'Cloud Native Computing Foundation (CNCF) — opentelemetry.io',
    field_count: 9,
    required_count: 5,
    fields: [
      { field: 'resource.attributes', type: 'object', required: true, description: 'Service and host metadata (service.name, host.id, tenant.id)' },
      { field: 'scope_logs[].scope.name', type: 'string', required: true, description: 'Instrumentation library / ingestion scope name' },
      { field: 'scope_logs[].log_records[].time_unix_nano', type: 'integer (Unix Nano)', required: true, description: 'Nanosecond Unix timestamp' },
      { field: 'scope_logs[].log_records[].severity_number', type: 'integer (1-24)', required: true, description: 'OTel standard severity number (1=TRACE to 24=FATAL4)' },
      { field: 'scope_logs[].log_records[].severity_text', type: 'string', required: false, description: 'Text representation of severity' },
      { field: 'scope_logs[].log_records[].body', type: 'string | object', required: true, description: 'Log message body or structured payload' },
      { field: 'scope_logs[].log_records[].attributes', type: 'object', required: false, description: 'Event-level attributes mapped from canonical UCE fields' },
      { field: 'scope_logs[].log_records[].trace_id', type: 'string (Hex)', required: false, description: 'W3C distributed trace correlation identifier' },
      { field: 'scope_logs[].log_records[].span_id', type: 'string (Hex)', required: false, description: 'W3C distributed span correlation identifier' },
    ],
  },
};

// ---------------------------------------------------------------------------
// Universal Any-to-Any Log Transpiler Client & Types
// ---------------------------------------------------------------------------

export interface UniversalFormatDef {
  id: string;
  name: string;
  category: string;
  vendor: string;
  output_type: string;
  description: string;
}

export interface UniversalTranspileRequest {
  raw_payload: string;
  target_format: string;
  source_format?: string;
  residue_policy?: string;
  options?: Record<string, any>;
}

export interface UniversalTranspileResponse {
  success: boolean;
  source_format_detected: string;
  confidence: number;
  target_format: string;
  output: any;
  extracted_fields: Record<string, any>;
  unmapped_residue: Record<string, any>;
  canonical_summary: {
    timestamp?: string;
    src_ip?: string;
    src_port?: number;
    dst_ip?: string;
    dst_port?: number;
    protocol?: string;
    action?: string;
    severity_label?: string;
    severity_num?: number;
    user?: string;
    host?: string;
    process?: string;
    command_line?: string;
    rule_name?: string;
  };
  drain_template: string;
  drain_parameters: string[];
  entities: Array<{ type: string; value: string; role: string }>;
  cas_sha256: string;
  duration_ms: number;
  byte_count_in: number;
  byte_count_out: number;
  compression_ratio: number;
  error?: string;
}

export const FALLBACK_UNIVERSAL_FORMATS: UniversalFormatDef[] = [
  { id: 'ocsf', name: 'Open Cybersecurity Schema Framework (OCSF v1.1.0)', category: 'Global Standard', vendor: 'OCSF Consortium / AWS', output_type: 'json', description: 'Industry open cybersecurity taxonomy for unified SIEM/XDR analysis.' },
  { id: 'otel', name: 'OpenTelemetry Log Data Model (OTel v1.3.0)', category: 'Cloud Native', vendor: 'CNCF', output_type: 'json', description: 'Vendor-neutral telemetry logging format with ResourceLogs and ScopeLogs.' },
  { id: 'ecs', name: 'Elastic Common Schema (ECS v8.11+)', category: 'Search & SIEM', vendor: 'Elasticsearch', output_type: 'json', description: 'Standard schema for Elasticsearch, Logstash, Kibana, and Elastic Security SIEM.' },
  { id: 'cef', name: 'Micro Focus ArcSight CEF', category: 'Enterprise SIEM', vendor: 'Micro Focus / ArcSight', output_type: 'text', description: 'Pipe-delimited standard: CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension.' },
  { id: 'leef', name: 'IBM QRadar LEEF 2.0', category: 'Enterprise SIEM', vendor: 'IBM Security', output_type: 'text', description: 'Tab-delimited standard: LEEF:2.0|Vendor|Product|Version|EventID|Attributes.' },
  { id: 'splunk_hec', name: 'Splunk HEC & CIM Data Model', category: 'Enterprise SIEM', vendor: 'Splunk Inc.', output_type: 'json', description: 'Splunk HTTP Event Collector payload structured for Common Information Model (CIM) acceleration.' },
  { id: 'google_udm', name: 'Google Cloud Chronicle UDM', category: 'Cloud SecOps', vendor: 'Google Cloud', output_type: 'json', description: 'Unified Data Model for Google Chronicle Security Operations.' },
  { id: 'sentinel_asim', name: 'Microsoft Sentinel ASIM', category: 'Cloud SIEM', vendor: 'Microsoft Azure', output_type: 'json', description: 'Advanced Security Information Model schema for Microsoft Sentinel KQL analytics.' },
  { id: 'syslog_5424', name: 'IETF Syslog Protocol (RFC 5424)', category: 'IETF Standard', vendor: 'IETF', output_type: 'text', description: 'Modern syslog with <PRI>1, ISO timestamp, PROCID, MSGID, and structured data blocks.' },
  { id: 'syslog_3164', name: 'BSD Unix Syslog (RFC 3164)', category: 'Legacy Unix', vendor: 'BSD / Unix Standard', output_type: 'text', description: 'Classic BSD syslog with PRI code, timestamp, hostname, tag, and message body.' },
  { id: 'w3c', name: 'W3C Extended / Combined Access Log', category: 'Web & Proxy', vendor: 'W3C / Apache / Nginx', output_type: 'text', description: 'Standard web server access log format with remote host, user, request, status, and agent.' },
  { id: 'logfmt', name: 'UNIX Logfmt (Key-Value)', category: 'Modern DevOps', vendor: 'Heroku / Go Standard', output_type: 'text', description: 'Space-delimited key=value format optimized for grep, awk, and high-speed streaming parsers.' },
  { id: 'ndjson', name: 'Newline-Delimited JSON (NDJSON)', category: 'Data Engineering', vendor: 'JSON Lines Standard', output_type: 'text', description: 'Single-line compacted JSON record for high-throughput stream pipelines and Kafka ingestion.' },
  { id: 'csv', name: 'RFC 4180 CSV with Dynamic Header', category: 'Data Science', vendor: 'IETF / Tabular', output_type: 'text', description: 'Tabular CSV representation with auto-extracted headers and normalized column alignments.' },
  { id: 'stix', name: 'OASIS STIX 2.1 Threat Intel', category: 'Cyber Threat Intel', vendor: 'OASIS Open', output_type: 'json', description: 'Structured Threat Information Expression bundle with network-traffic, ipv4-addr, and indicators.' },
  { id: 'neo4j', name: 'Neo4j Cypher Graph Ingestion', category: 'Graph Analytics', vendor: 'Neo4j Inc.', output_type: 'text', description: 'Declarative Cypher MERGE and CREATE statements to construct attack graph nodes and edges.' },
  { id: 'gelf', name: 'Graylog Extended Log Format (GELF 1.1)', category: 'Open Observability', vendor: 'Graylog', output_type: 'json', description: 'Graylog standard JSON payload with version, host, short_message, level, and custom attributes.' },
  { id: 'parquet_schema', name: 'Apache Arrow / Parquet Typed Schema', category: 'Data Lake', vendor: 'Apache Software Foundation', output_type: 'json', description: 'Strongly-typed columnar Arrow/Parquet schema definition with field data types and nullability.' },
  { id: 'forensic_dossier', name: 'Statutory Forensic Evidence Dossier (A 65B IEA)', category: 'Legal & Forensics', vendor: 'Judicial Authority', output_type: 'text', description: 'Statutory forensic attestation document complying with Section 65B Indian Evidence Act.' },
  { id: 'drain_template', name: 'Drain3 Log Template Mining Spec', category: 'Academic AI Discovery', vendor: 'IEEE ICWS He et al.', output_type: 'json', description: 'Extracted invariant template string with <*> slots and dynamic parameter value tokens.' },
];

export async function getUniversalFormats(): Promise<{ formats: UniversalFormatDef[] }> {
  try {
    return await apiFetchWithAuth<{ formats: UniversalFormatDef[] }>('/universal/formats');
  } catch (err) {
    console.warn('API /universal/formats call failed, fallback to local registry:', err);
    return { formats: FALLBACK_UNIVERSAL_FORMATS };
  }
}

export async function transpileUniversalLog(req: UniversalTranspileRequest): Promise<UniversalTranspileResponse> {
  return await apiFetchWithAuth<UniversalTranspileResponse>('/universal/transpile', {
    method: 'POST',
    body: JSON.stringify(req),
  });
}

