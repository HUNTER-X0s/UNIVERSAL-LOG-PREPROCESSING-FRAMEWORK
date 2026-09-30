import { PipelineStageInfo } from '../types/telemetry';

export const PIPELINE_STAGES: PipelineStageInfo[] = [
  {
    id: 'stage-raw-capture',
    number: '01',
    name: 'RAW CAPTURE',
    shortDesc: 'Verbatim socket/file intake with zero mutation',
    status: 'complete',
    latencyMs: 1.2,
    guarantee: '100% Raw Byte Retention'
  },
  {
    id: 'stage-sha-cas',
    number: '02',
    name: 'SHA-256 CAS',
    shortDesc: 'Content-Addressed Storage digest calculation',
    status: 'complete',
    latencyMs: 2.1,
    guarantee: 'Immutable Write-Once Anchor'
  },
  {
    id: 'stage-parser-dispatch',
    number: '03',
    name: 'PARSER DISPATCH',
    shortDesc: 'Dynamic vendor identification & parser selection',
    status: 'complete',
    latencyMs: 0.8,
    guarantee: 'Deterministic Rule Match'
  },
  {
    id: 'stage-uce-norm',
    number: '04',
    name: 'UCE NORMALIZATION',
    shortDesc: 'Standard schema mapping with residue preservation',
    status: 'complete',
    latencyMs: 3.4,
    guarantee: 'Lossless Schema Taxonomy'
  },
  {
    id: 'stage-semantic-map',
    number: '05',
    name: 'SEMANTIC MAPPING',
    shortDesc: 'Entity, network, and indicator extraction',
    status: 'complete',
    latencyMs: 2.7,
    guarantee: 'Structured Semantic Graph'
  },
  {
    id: 'stage-ocsf-otel',
    number: '06',
    name: 'OCSF / OTEL PROJECTION',
    shortDesc: 'Simultaneous dual open standards generation',
    status: 'complete',
    latencyMs: 1.9,
    guarantee: 'Zero Re-Parse Overhead'
  },
  {
    id: 'stage-threat-detect',
    number: '07',
    name: 'THREAT DETECTION',
    shortDesc: 'Sliding-window correlation & MITRE ATT&CK tagging',
    status: 'complete',
    latencyMs: 4.1,
    guarantee: 'Multi-Stage Attack Sequence'
  },
  {
    id: 'stage-evidence-pkg',
    number: '08',
    name: 'EVIDENCE PACKAGE',
    shortDesc: '13-stage Merkle DAG lineage envelope assembly',
    status: 'complete',
    latencyMs: 1.5,
    guarantee: 'Cryptographic Tamper-Evidence'
  },
  {
    id: 'stage-siem-delivery',
    number: '09',
    name: 'OUTBOX DELIVERY',
    shortDesc: 'Transactional SIEM / Lake delivery with DLQ safety',
    status: 'active',
    latencyMs: 2.3,
    guarantee: 'At-Least-Once Delivery SLA'
  }
];

export const FORENSIC_LINEAGE_13: Array<{
  stage: number;
  name: string;
  component: string;
  hash: string;
  timestamp: string;
  details: string;
}> = [
  { stage: 1, name: 'Raw Telemetry Capture', component: 'raw_intake_service', hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', timestamp: '2026-09-11T14:30:00.102Z', details: 'Verbatim TCP socket bytes received' },
  { stage: 2, name: 'CAS Storage Receipt', component: 'raw_fs.py', hash: '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b', timestamp: '2026-09-11T14:30:00.105Z', details: 'Content-Addressed Storage write-once confirmation' },
  { stage: 3, name: 'Format Profile Discovery', component: 'profiler.py', hash: '8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4', timestamp: '2026-09-11T14:30:00.108Z', details: 'Heuristic pattern matched: Cisco ASA' },
  { stage: 4, name: 'Pre-Parse Schema Validation', component: 'intake_validator.py', hash: '6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090', timestamp: '2026-09-11T14:30:00.110Z', details: 'Syntax bounds and token delimiters verified' },
  { stage: 5, name: 'Deterministic Parser Invocation', component: 'cisco_asa_parser.py', hash: 'eccbc87e4b5ce2fe28308fd9f2a7baf3a87989938f36c507c6f376918d390234', timestamp: '2026-09-11T14:30:00.114Z', details: 'Extracted 14 core fields and unmapped residue' },
  { stage: 6, name: 'Field Extraction & Normalization', component: 'normalizer.py', hash: 'c81e728d9d4c2f636f067f89cc14862c1ecd6920f6990d794b150917618ff7e4', timestamp: '2026-09-11T14:30:00.118Z', details: 'IP addresses and ports normalized to standard types' },
  { stage: 7, name: 'Semantic Taxonomy Mapping', component: 'semantic_service.py', hash: 'a87ff679a2f3e71d9181a67b7542122c34ff24a66a7b8e5c2cf5df246c075f10', timestamp: '2026-09-11T14:30:00.123Z', details: 'Universal Canonical Event (UCE) constructed' },
  { stage: 8, name: 'Dynamic Risk Evaluation', component: 'risk_engine.py', hash: 'e4da3b7fbbce2345d7772b0674a318d5b91b8d6f5f3e098a8a47814b7e808e01', timestamp: '2026-09-11T14:30:00.127Z', details: 'Multi-factor risk score assigned: 84/100 (HIGH)' },
  { stage: 9, name: 'MITRE ATT&CK Technique Mapping', component: 'mitre_classifier.py', hash: '1679091c5a880faf6fb5e6087eb1b2dc8a245582f6e9196b0521e1e9b72a0f86', timestamp: '2026-09-11T14:30:00.131Z', details: 'Mapped to T1071.001 (Application Layer Protocol: Web)' },
  { stage: 10, name: 'Sliding Correlation Engine', component: 'correlation_engine.py', hash: '8f14e45fceea167a5a36dedd4bea2543e390c5079a37e1933e4597b5e4070a2a', timestamp: '2026-09-11T14:30:00.136Z', details: 'Correlated with host scan detection on 10.0.1.20' },
  { stage: 11, name: 'Dual Open Standards Projection', component: 'projections_registry.py', hash: 'c9f0f895fb98ab9159f51fd0297e236d1da2c79b4a8b75c87e6005c2a472a71f', timestamp: '2026-09-11T14:30:00.141Z', details: 'OCSF Class 4001 & OpenTelemetry Log projected' },
  { stage: 12, name: 'Cryptographic Evidence Packaging', component: 'evidence_packaging.py', hash: '45c48cce2e2d7fbdea1afc51c7c6ad26fe41369f681a8b98ce307a50da83c675', timestamp: '2026-09-11T14:30:00.144Z', details: 'Merkle root envelope assembled with SHA-256 signatures' },
  { stage: 13, name: 'Transactional Outbox Dispatch', component: 'delivery_service.py', hash: 'd3d9446802a44259755d38e6d163e820c7493a7d4bf0e0c03429e3a6c9d0d1b4', timestamp: '2026-09-11T14:30:00.148Z', details: 'Delivered to SIEM sink with transactional receipt confirmation' }
];
