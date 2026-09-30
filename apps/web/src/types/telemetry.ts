export type TelemetrySeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface RawEventRecord {
  event_id: string;
  source_type: string;
  payload: string;
  timestamp: string;
  sha256: string;
  cas_path: string;
  bytes: number;
}

export interface CasReceipt {
  accepted: boolean;
  status: string;
  event_id: string;
  receipt_id: string;
  sha256: string;
  cas_path: string;
  received_at: string;
  format_detected: string;
  bytes: number;
  airgap_isolation: string;
  transport?: string;
  compression?: string;
  semantic_event_id?: string;
  duration_ms?: number;
  deduplicated?: boolean;
}

export interface UniversalCanonicalEvent {
  event_id: string;
  timestamp: string;
  source_type: string;
  vendor: string;
  parser_id: string;
  severity: TelemetrySeverity;
  category: string;
  action: string;
  network?: {
    src_ip?: string;
    dst_ip?: string;
    src_port?: number;
    dst_port?: number;
    protocol?: string;
  };
  entities: Array<{
    type: string;
    value: string;
  }>;
  indicators: Array<{
    type: string;
    value: string;
    confidence: number;
  }>;
  unmapped_residue: Record<string, unknown>;
  provenance: {
    cas_hash: string;
    pipeline_version: string;
    stages_applied: number;
  };
}

export interface PipelineStageInfo {
  id: string;
  number: string;
  name: string;
  shortDesc: string;
  status: 'active' | 'complete' | 'ready';
  latencyMs: number;
  guarantee: string;
}
