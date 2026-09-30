/**
 * Static demo blockchain data for the Block Explorer UI.
 *
 * Shown when the API is unavailable (offline mode / demo mode).
 * Mirrors the data seeded by the backend anchoring service.
 */

export interface DemoTransaction {
  event_id: string;
  sha256: string;
  source: string;
  anchored_at: string;
  description: string;
}

export interface DemoBlock {
  index: number;
  timestamp: number;
  timestamp_iso: string;
  transactions: DemoTransaction[];
  transaction_count: number;
  merkle_root: string;
  previous_hash: string;
  hash: string;
  authority_signature: string;
  block_version: string;
  framework: string;
  is_genesis: boolean;
}

export const DEMO_BLOCKS: DemoBlock[] = [
  {
    index: 0,
    timestamp: 1751328000.0,
    timestamp_iso: '2026-01-01T00:00:00+00:00',
    transaction_count: 1,
    merkle_root: 'a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9',
    previous_hash: '0000000000000000000000000000000000000000000000000000000000000000',
    hash: 'genesis1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab',
    authority_signature: 'poa_sig_genesis_ntro_sih2026_ulpf_permissioned_chain_of_custody',
    block_version: 'ULPF-BC-v1',
    framework: 'Universal Log Pre-processing Framework',
    is_genesis: true,
    transactions: [
      {
        event_id: '00000000-0000-0000-0000-000000000001',
        sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        source: 'ULPF_GENESIS',
        anchored_at: '2026-01-01T00:00:00+00:00',
        description: 'ULPF Permissioned Blockchain Genesis — NTRO SIH 2026',
      },
    ],
  },
  {
    index: 1,
    timestamp: 1758096600.0,
    timestamp_iso: '2026-09-17T01:30:00+00:00',
    transaction_count: 8,
    merkle_root: 'f1e2d3c4b5a6978869504132231445566778899aabbccddeeff00112233445566',
    previous_hash: 'genesis1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab',
    hash: 'block1_hash_abcdef1234567890abcdef1234567890abcdef1234567890abcdef12',
    authority_signature: 'poa_sig_block1_ulpf_authority_node_ntro_001_hmac_sha256',
    block_version: 'ULPF-BC-v1',
    framework: 'Universal Log Pre-processing Framework',
    is_genesis: false,
    transactions: [
      {
        event_id: 'a1b2c3d4-0001-4000-8000-000000000001',
        sha256: '3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c',
        source: 'CISCO_ASA',
        anchored_at: '2026-09-17T01:30:01+00:00',
        description: 'Cisco ASA Firewall — Deny TCP 443 inbound',
      },
      {
        event_id: 'a1b2c3d4-0002-4000-8000-000000000002',
        sha256: '4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d',
        source: 'SNORT',
        anchored_at: '2026-09-17T01:30:02+00:00',
        description: 'Snort IDS — ET MALWARE CnC Callback detected',
      },
      {
        event_id: 'a1b2c3d4-0003-4000-8000-000000000003',
        sha256: '5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e',
        source: 'WINEVENT',
        anchored_at: '2026-09-17T01:30:03+00:00',
        description: 'Windows Event 4625 — Failed Logon attempt',
      },
      {
        event_id: 'a1b2c3d4-0004-4000-8000-000000000004',
        sha256: '6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f',
        source: 'OKTA',
        anchored_at: '2026-09-17T01:30:04+00:00',
        description: 'Okta — MFA bypass attempt detected',
      },
      {
        event_id: 'a1b2c3d4-0005-4000-8000-000000000005',
        sha256: '7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a',
        source: 'PALO_ALTO',
        anchored_at: '2026-09-17T01:30:05+00:00',
        description: 'Palo Alto — SSH brute-force threat blocked',
      },
      {
        event_id: 'a1b2c3d4-0006-4000-8000-000000000006',
        sha256: '8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b',
        source: 'AWS_CLOUDTRAIL',
        anchored_at: '2026-09-17T01:30:06+00:00',
        description: 'AWS CloudTrail — IAM policy modification',
      },
      {
        event_id: 'a1b2c3d4-0007-4000-8000-000000000007',
        sha256: '9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c',
        source: 'FORTINET',
        anchored_at: '2026-09-17T01:30:07+00:00',
        description: 'Fortinet IPS — SQL injection attempt blocked',
      },
      {
        event_id: 'a1b2c3d4-0008-4000-8000-000000000008',
        sha256: '0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d',
        source: 'CROWDSTRIKE',
        anchored_at: '2026-09-17T01:30:08+00:00',
        description: 'CrowdStrike EDR — Process hollowing / ransomware',
      },
    ],
  },
  {
    index: 2,
    timestamp: 1758096660.0,
    timestamp_iso: '2026-09-17T01:31:00+00:00',
    transaction_count: 4,
    merkle_root: 'a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3',
    previous_hash: 'block1_hash_abcdef1234567890abcdef1234567890abcdef1234567890abcdef12',
    hash: 'block2_hash_9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedc',
    authority_signature: 'poa_sig_block2_ulpf_authority_node_ntro_001_hmac_sha256',
    block_version: 'ULPF-BC-v1',
    framework: 'Universal Log Pre-processing Framework',
    is_genesis: false,
    transactions: [
      {
        event_id: 'b2c3d4e5-0009-4000-8000-000000000009',
        sha256: '1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e',
        source: 'KUBERNETES',
        anchored_at: '2026-09-17T01:31:01+00:00',
        description: 'K8s — Pod privilege escalation attempt',
      },
      {
        event_id: 'b2c3d4e5-0010-4000-8000-000000000010',
        sha256: '2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f',
        source: 'SURICATA',
        anchored_at: '2026-09-17T01:31:02+00:00',
        description: 'Suricata — Lateral movement via SMB detected',
      },
      {
        event_id: 'b2c3d4e5-0011-4000-8000-000000000011',
        sha256: '3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a',
        source: 'ACTIVE_DIRECTORY',
        anchored_at: '2026-09-17T01:31:03+00:00',
        description: 'AD — Domain Admin group modification',
      },
      {
        event_id: 'b2c3d4e5-0012-4000-8000-000000000012',
        sha256: '4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b',
        source: 'GITHUB_AUDIT',
        anchored_at: '2026-09-17T01:31:04+00:00',
        description: 'GitHub Audit — Secrets pushed to public repo',
      },
    ],
  },
];

export const DEMO_CHAIN_STATS = {
  chain_height: 3,
  total_events_anchored: 13,
  chain_integrity: 'VALID',
  genesis_hash: 'genesis1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab',
  latest_block_hash: 'block2_hash_9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedc',
  latest_block_time: '2026-09-17T01:31:04+00:00',
  authority_node_id: 'ULPF-AUTHORITY-NODE-NTRO-001',
  pending_transactions: 0,
  consensus_algorithm: 'Proof of Authority (PoA)',
  hash_algorithm: 'SHA-256',
  merkle_algorithm: 'Binary Merkle Tree (SHA-256)',
};

export const DEMO_CONTRACT_RULES = [
  { rule_id: 'SC-001', name: 'SOURCE_ALLOWLIST', description: 'Only trusted, recognized device source types may be anchored.', severity: 'CRITICAL', enabled: 'true' },
  { rule_id: 'SC-002', name: 'HASH_INTEGRITY', description: 'The declared SHA-256 hash must be a valid 64-character hex string.', severity: 'CRITICAL', enabled: 'true' },
  { rule_id: 'SC-003', name: 'EVENT_ID_FORMAT', description: 'Event IDs must be valid UUID v4 strings.', severity: 'HIGH', enabled: 'true' },
  { rule_id: 'SC-004', name: 'RETENTION_POLICY', description: 'Events older than 7 days cannot be anchored (forensic hygiene).', severity: 'HIGH', enabled: 'true' },
  { rule_id: 'SC-005', name: 'REQUIRED_FIELDS', description: 'Every anchored event must carry event_id, sha256, source, anchored_at.', severity: 'CRITICAL', enabled: 'true' },
  { rule_id: 'SC-006', name: 'HASH_LENGTH', description: 'SHA-256 hash must be exactly 64 hex characters.', severity: 'CRITICAL', enabled: 'true' },
];
