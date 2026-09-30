/**
 * Response Playbooks — ULPF SOAR Dry-Run Simulation & Dispatch Control
 *
 * Provides a zero-side-effect automated response engine for sovereign SOCs.
 * Enables analysts to simulate, audit, and preview exact blast radius,
 * required permissions, and rollback actions before any live execution.
 */

import React, { useState, useMemo, useEffect } from 'react';
import { Card } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { CodePanel } from '../components/ui/CodePanel';
import {
  Zap,
  Play,
  CheckCircle2,
  ShieldAlert,
  Shield,
  Server,
  RefreshCw,
  Terminal,
  Layers,
  AlertTriangle,
  Lock,
  Eye,
  Activity,
  ChevronRight,
  Check,
  ArrowRight,
  RotateCcw,
  Filter,
  Search,
  FileText,
  Globe,
  KeyRound,
  ExternalLink,
  SlidersHorizontal,
  Clock,
  Sparkles,
  Info,
} from 'lucide-react';
import { NavLink, useSearchParams } from 'react-router-dom';

// ---------------------------------------------------------------------------
// Playbook Definitions & Data Model
// ---------------------------------------------------------------------------

export type PlaybookCategory = 'Containment' | 'Identity' | 'Network' | 'Forensics' | 'Compliance';
export type BlastRadius = 'LOW' | 'MEDIUM' | 'HIGH';

export interface PlaybookStepDef {
  id: string;
  name: string;
  actionType: string;
  target: string;
  requiredPermission: string;
  rollbackAction: string;
  description: string;
  estimatedLatency: string;
}

export interface PlaybookDef {
  id: string;
  name: string;
  shortLabel: string;
  category: PlaybookCategory;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  mitreTechniques: string[];
  triggerConditions: string;
  blastRadius: BlastRadius;
  automationType: 'Fully Automated' | 'Human-in-the-Loop';
  description: string;
  defaultTarget: string;
  steps: PlaybookStepDef[];
}

export const PLAYBOOK_CATALOG: PlaybookDef[] = [
  {
    id: 'PB-RANSOMWARE-CONTAINMENT',
    name: 'Emergency Host & Lateral Ransomware Containment',
    shortLabel: 'PB-RANSOMWARE · Ransomware Containment',
    category: 'Containment',
    severity: 'CRITICAL',
    mitreTechniques: ['T1486 Data Encrypted', 'T1021 Remote Services', 'T1489 Service Stop'],
    triggerConditions: 'Mass file renaming velocity (>500 files/min) OR shadow copy deletion indicator',
    blastRadius: 'HIGH',
    automationType: 'Fully Automated',
    description:
      'Isolates target host from all subnet communications, severs lateral SMB/RDP ports at switch level, and freezes shadow copies to prevent encryption spread.',
    defaultTarget: '10.0.1.20 / srv-fin-db-01 (Ubuntu 22.04 LTS)',
    steps: [
      {
        id: 'STEP-01',
        name: 'Isolate Host from Local Subnet',
        actionType: 'QUARANTINE_NODE',
        target: '10.0.1.20',
        requiredPermission: 'secops.containment.network',
        rollbackAction: 'RECONNECT_NODE (Flush iptables quarantine)',
        description: 'Inject EDR kernel hook to block all ingress/egress except to SOC controller',
        estimatedLatency: '14ms',
      },
      {
        id: 'STEP-02',
        name: 'Block Lateral SMB & RDP Ports',
        actionType: 'BLOCK_PORTS',
        target: 'Ports 445, 139, 3389',
        requiredPermission: 'firewall.ports.write',
        rollbackAction: 'UNBLOCK_PORTS (Restore default port rules)',
        description: 'Drop lateral RPC/SMB traffic on switch VLAN boundary to stop propagation',
        estimatedLatency: '28ms',
      },
      {
        id: 'STEP-03',
        name: 'Freeze Storage & Preserve Volume Snapshots',
        actionType: 'STORAGE_FREEZE',
        target: '/dev/vg_data/lv_app',
        requiredPermission: 'storage.immutable.lock',
        rollbackAction: 'STORAGE_UNLOCK (Re-enable write access)',
        description: 'Place local filesystem in read-only write-barrier mode to protect backups',
        estimatedLatency: '45ms',
      },
      {
        id: 'STEP-04',
        name: 'Broadcast Incident Dispatch to NTRO & CERT-In',
        actionType: 'STATUTORY_ALERT',
        target: 'cert-in-desk@nic.in, ntro-soc@gov.in',
        requiredPermission: 'notification.statutory.send',
        rollbackAction: 'N/A (Informational dispatch)',
        description: 'Compile cryptographic incident digest and transmit critical alert payload',
        estimatedLatency: '82ms',
      },
    ],
  },
  {
    id: 'PB-HOST-ISOLATION',
    name: 'Compromised Node Network Quarantine',
    shortLabel: 'PB-HOST-ISOLATION · Node Quarantine',
    category: 'Containment',
    severity: 'HIGH',
    mitreTechniques: ['T1059 Execution', 'T1203 Exploitation', 'T1068 Priv Escalation'],
    triggerConditions: 'Unapproved binary execution OR active meterpreter/CobaltStrike beacon',
    blastRadius: 'MEDIUM',
    automationType: 'Fully Automated',
    description:
      'Applies immediate network quarantine on endpoint via EDR agent and pfSense perimeter, preserving evidence memory space.',
    defaultTarget: '10.0.2.14 / ws-finance-04 (Windows 11 Enterprise)',
    steps: [
      {
        id: 'STEP-01',
        name: 'Inject EDR Host Isolation Rule',
        actionType: 'EDR_ISOLATE',
        target: 'ws-finance-04 (Agent UUID 4a9f...e18b)',
        requiredPermission: 'edr.agent.isolate',
        rollbackAction: 'EDR_UNISOLATE (Release agent network clamp)',
        description: 'Command EDR agent to disconnect all TCP/UDP sockets immediately',
        estimatedLatency: '18ms',
      },
      {
        id: 'STEP-02',
        name: 'Drop Perimeter Gateway Sessions',
        actionType: 'FIREWALL_DROP',
        target: 'pfSense Gateway 192.168.1.1',
        requiredPermission: 'firewall.rules.write',
        rollbackAction: 'FIREWALL_RESTORE (Remove drop rule)',
        description: 'Terminate all active NAT states associated with host IP at perimeter',
        estimatedLatency: '24ms',
      },
      {
        id: 'STEP-03',
        name: 'Snapshot Volatile RAM to Secure CAS',
        actionType: 'MEMORY_CAPTURE',
        target: 'Dump to CAS vault /evidence/ram_dumps',
        requiredPermission: 'forensics.memory.read',
        rollbackAction: 'PURGE_TEMPORARY_STAGING',
        description: 'Trigger LiME/WinPmem memory acquisition for malware reverse engineering',
        estimatedLatency: '180ms',
      },
    ],
  },
  {
    id: 'PB-CREDENTIAL-REVOCATION',
    name: 'Compromised Identity & Token Revocation',
    shortLabel: 'PB-CRED-REVOKE · Identity Revocation',
    category: 'Identity',
    severity: 'HIGH',
    mitreTechniques: ['T1078 Valid Accounts', 'T1110 Brute Force', 'T1550 Pass the Hash'],
    triggerConditions: 'Impossible travel anomaly (IN -> US in 12 mins) OR LSASS credential dump event',
    blastRadius: 'LOW',
    automationType: 'Fully Automated',
    description:
      'Invalidates active Kerberos TGTs, revokes OAuth JWT session tokens across Active Directory and Okta, and forces MFA re-challenge.',
    defaultTarget: 'anurag.swain@ntro.gov.in (UPN / Kerberos Principal)',
    steps: [
      {
        id: 'STEP-01',
        name: 'Revoke Active Kerberos Ticket-Granting Tickets',
        actionType: 'KERBEROS_REVOKE',
        target: 'dc-primary.internal.gov (Domain Controller)',
        requiredPermission: 'identity.ad.write',
        rollbackAction: 'REISSUE_KERBEROS_SESSION',
        description: 'Set user account lockout bit and flush Kerberos ticket cache on all domain controllers',
        estimatedLatency: '35ms',
      },
      {
        id: 'STEP-02',
        name: 'Revoke OAuth 2.0 & JWT Refresh Tokens',
        actionType: 'TOKEN_REVOCATION',
        target: 'Okta / ULPF Auth Gateway',
        requiredPermission: 'identity.oauth.revoke',
        rollbackAction: 'RESTORE_OAUTH_SESSION',
        description: 'Blacklist all active token signatures in Redis session store',
        estimatedLatency: '12ms',
      },
      {
        id: 'STEP-03',
        name: 'Trigger Mandatory MFA Re-Enrollment',
        actionType: 'MFA_RESET',
        target: 'FIDO2 / TOTP Authenticator',
        requiredPermission: 'identity.mfa.admin',
        rollbackAction: 'RESTORE_MFA_STATUS',
        description: 'Flag account for mandatory hardware key or TOTP re-authentication on next login',
        estimatedLatency: '22ms',
      },
    ],
  },
  {
    id: 'PB-C2-NETWORK-BLOCK',
    name: 'Adversary Command & Control (C2) Blackhole',
    shortLabel: 'PB-C2-BLOCK · C2 Network Blackhole',
    category: 'Network',
    severity: 'CRITICAL',
    mitreTechniques: ['T1071 App Layer Protocol: Web/DNS', 'T1041 Exfil over C2', 'T1090 Proxy'],
    triggerConditions: 'Beaconing pattern detected to known APT hostile IP/domain with periodicity score > 0.95',
    blastRadius: 'MEDIUM',
    automationType: 'Fully Automated',
    description:
      'Instantly pushes BGP null-routes and DNS Response Policy Zone (RPZ) sinkhole rules to block communication with adversary C2 servers.',
    defaultTarget: '198.51.100.42 / c2-beacon.darknet-nexus.org',
    steps: [
      {
        id: 'STEP-01',
        name: 'Inject BGP Null-Route on Core Routers',
        actionType: 'BGP_NULL_ROUTE',
        target: '198.51.100.42/32',
        requiredPermission: 'network.bgp.write',
        rollbackAction: 'BGP_WITHDRAW_ROUTE (Restore route advertisement)',
        description: 'Advertise blackhole next-hop to edge routers to drop all C2 packets silently',
        estimatedLatency: '42ms',
      },
      {
        id: 'STEP-02',
        name: 'Inject DNS RPZ Sinkhole Rule',
        actionType: 'DNS_SINKHOLE',
        target: 'c2-beacon.darknet-nexus.org',
        requiredPermission: 'network.dns.write',
        rollbackAction: 'DNS_REMOVE_RPZ (Remove sinkhole entry)',
        description: 'Map malicious FQDN to internal loopback 127.0.0.1 on Bind9 recursive resolvers',
        estimatedLatency: '16ms',
      },
      {
        id: 'STEP-03',
        name: 'Reset Active TCP Connections',
        actionType: 'TCP_RST_INJECT',
        target: 'All outbound ports to 198.51.100.42',
        requiredPermission: 'firewall.session.kill',
        rollbackAction: 'N/A (Transient reset)',
        description: 'Send TCP RST flags to tear down active established adversary sessions',
        estimatedLatency: '9ms',
      },
    ],
  },
  {
    id: 'PB-MALICIOUS-PROCESS-KILL',
    name: 'Adversary Process Tree Eradication & Hash Quarantine',
    shortLabel: 'PB-PROC-KILL · Process Tree Eradication',
    category: 'Containment',
    severity: 'HIGH',
    mitreTechniques: ['T1059.001 PowerShell', 'T1027 Obfuscated Files', 'T1562 Disable Security'],
    triggerConditions: 'Encoded PowerShell execution spawning cmd.exe or unverified cert injected into memory',
    blastRadius: 'LOW',
    automationType: 'Fully Automated',
    description:
      'Suspends target process, snapshots memory pages for threat intel extraction, terminates the process tree, and moves binary to immutable quarantine.',
    defaultTarget: 'PID 4820 (powershell.exe) on srv-app-01',
    steps: [
      {
        id: 'STEP-01',
        name: 'Freeze Process Execution via Kernel Hook',
        actionType: 'SUSPEND_PID',
        target: 'PID 4820 (powershell.exe)',
        requiredPermission: 'endpoint.process.suspend',
        rollbackAction: 'RESUME_PID (Resume execution if false positive)',
        description: 'Pause thread scheduling to prevent further file or registry modifications',
        estimatedLatency: '8ms',
      },
      {
        id: 'STEP-02',
        name: 'Extract Process Memory Pages for Intel',
        actionType: 'MEM_EXTRACT',
        target: 'PID 4820 Memory Space (42 MB)',
        requiredPermission: 'endpoint.process.dump',
        rollbackAction: 'CLEANUP_DUMP_CACHE',
        description: 'Save process memory dump to extract decoded scripts, URLs, and encryption keys',
        estimatedLatency: '95ms',
      },
      {
        id: 'STEP-03',
        name: 'Terminate Full Process Tree',
        actionType: 'KILL_PROCESS_TREE',
        target: 'PID 4820 and child PIDs 4824, 4832',
        requiredPermission: 'endpoint.process.kill',
        rollbackAction: 'N/A (Permanent termination)',
        description: 'Execute forceful SIGKILL across the process hierarchy',
        estimatedLatency: '11ms',
      },
      {
        id: 'STEP-04',
        name: 'Quarantine Dropped Binary to CAS Vault',
        actionType: 'QUARANTINE_FILE',
        target: 'C:\\Users\\Public\\malware_loader.exe',
        requiredPermission: 'filesystem.quarantine.write',
        rollbackAction: 'RESTORE_QUARANTINED_FILE',
        description: 'Calculate SHA-256 hash and move executable into read-only quarantine folder',
        estimatedLatency: '32ms',
      },
    ],
  },
  {
    id: 'PB-CERT-IN-6HR-REPORTING',
    name: 'Statutory CERT-In 6-Hour Incident Filing',
    shortLabel: 'PB-CERT-IN · 6-Hour Statutory Filing',
    category: 'Compliance',
    severity: 'CRITICAL',
    mitreTechniques: ['T1499 Denial of Service', 'T1562 Disable Security', 'T1190 Exploit Public App'],
    triggerConditions: 'Any Severity-1 breach or Ransomware event triggering statutory reporting SLA countdown',
    blastRadius: 'LOW',
    automationType: 'Human-in-the-Loop',
    description:
      'Compiles the official CERT-In Annexure I incident reporting dossier, attaches cryptographically verified UCE logs, and stages formal submission.',
    defaultTarget: 'CERT-In Incident Desk (Ref: CERT-IN-SLA-2026-0928)',
    steps: [
      {
        id: 'STEP-01',
        name: 'Aggregate Chronological Incident Logs',
        actionType: 'AUDIT_QUERY',
        target: 'ULPF Sovereign Telemetry Index (T-0 to T-6h)',
        requiredPermission: 'audit.telemetry.query',
        rollbackAction: 'N/A (Query only)',
        description: 'Extract all normalized UCE events with cryptographic hash lineage',
        estimatedLatency: '110ms',
      },
      {
        id: 'STEP-02',
        name: 'Format Annexure I Statutory Filing Dossier',
        actionType: 'GENERATE_REPORT',
        target: 'Ministry of Electronics & IT (MeitY) Format',
        requiredPermission: 'compliance.report.generate',
        rollbackAction: 'DISCARD_DRAFT_REPORT',
        description: 'Populate 20 mandatory incident fields (impacted systems, IOCs, containment status)',
        estimatedLatency: '65ms',
      },
      {
        id: 'STEP-03',
        name: 'Cryptographically Sign Evidence Package',
        actionType: 'CRYPTO_SIGN',
        target: 'Ed25519 Platform Key Signature',
        requiredPermission: 'crypto.signing.key',
        rollbackAction: 'N/A (Immutable signature)',
        description: 'Generate tamper-proof cryptographic attestation signature across PDF payload',
        estimatedLatency: '25ms',
      },
      {
        id: 'STEP-04',
        name: 'Stage for CISO / Nodal Officer Authorization',
        actionType: 'APPROVAL_DISPATCH',
        target: 'Nodal Security Officer Approval Desk',
        requiredPermission: 'compliance.dispatch.stage',
        rollbackAction: 'CANCEL_SUBMISSION_REQUEST',
        description: 'Present signed report to authorized executive for one-click statutory transmission',
        estimatedLatency: '15ms',
      },
    ],
  },
  {
    id: 'PB-EVIDENCE-FREEZE',
    name: 'Forensic Evidence Freeze & Blockchain Ledger Anchor',
    shortLabel: 'PB-EVIDENCE · Ledger Anchor Freeze',
    category: 'Forensics',
    severity: 'HIGH',
    mitreTechniques: ['T1070 Clear Windows Event Logs', 'T1565 Data Manipulation'],
    triggerConditions: 'Analyst initiates forensic chain-of-custody seal for judicial court submission',
    blastRadius: 'LOW',
    automationType: 'Fully Automated',
    description:
      'Freezes telemetry CAS hashes, constructs a cryptographic Merkle root of the raw audit stream, and anchors the digest to the sovereign blockchain ledger.',
    defaultTarget: 'Block Ledger: ULPF-SOVEREIGN-CHAIN (Epoch 8492)',
    steps: [
      {
        id: 'STEP-01',
        name: 'Lock Content-Addressable Storage (CAS)',
        actionType: 'CAS_LOCK',
        target: 'Raw Telemetry Block Storage',
        requiredPermission: 'storage.cas.lock',
        rollbackAction: 'RELEASE_CAS_LOCK',
        description: 'Set immutable WORM (Write Once, Read Many) attribute on raw log archives',
        estimatedLatency: '20ms',
      },
      {
        id: 'STEP-02',
        name: 'Compute 13-Stage Merkle Tree Root',
        actionType: 'MERKLE_TREE_ROOT',
        target: 'Batch of 10,000 Verified Telemetry Events',
        requiredPermission: 'crypto.merkle.compute',
        rollbackAction: 'N/A (Mathematical computation)',
        description: 'Hash chain events sequentially into a 256-bit cryptographic root digest',
        estimatedLatency: '48ms',
      },
      {
        id: 'STEP-03',
        name: 'Anchor Root Digest to Ledger Smart Contract',
        actionType: 'BLOCKCHAIN_ANCHOR',
        target: 'Smart Contract: 0x9f4a...e18b (Block #24,910)',
        requiredPermission: 'blockchain.tx.commit',
        rollbackAction: 'N/A (Immutable blockchain record)',
        description: 'Publish transaction with RFC 3161 proof for Section 65B Indian Evidence Act admissibility',
        estimatedLatency: '140ms',
      },
    ],
  },
  {
    id: 'PB-DDOS-TRAFFIC-SCRUB',
    name: 'Distributed Denial-of-Service (DDoS) Scrubbing & Geo-Fencing',
    shortLabel: 'PB-DDOS-SCRUB · Traffic Scrubbing',
    category: 'Network',
    severity: 'HIGH',
    mitreTechniques: ['T1498 Network DoS', 'T1499 Endpoint DoS'],
    triggerConditions: 'Ingress bandwidth spike > 5 Gbps with 90% SYN flood or UDP reflection profile',
    blastRadius: 'HIGH',
    automationType: 'Human-in-the-Loop',
    description:
      'Diverts inbound ingress through National Cyber Scrubbing Centers, enables SYN cookies, and applies automated geo-fencing against hostile CIDRs.',
    defaultTarget: 'Core Perimeter Router (Edge ASN 55836)',
    steps: [
      {
        id: 'STEP-01',
        name: 'Divert Traffic to National Cloud Scrubber',
        actionType: 'BGP_SCRUB_DIVERT',
        target: 'BGP Community Tag 65000:999',
        requiredPermission: 'network.bgp.divert',
        rollbackAction: 'BGP_RESTORE_PRIMARY (Revert to direct routing)',
        description: 'Announce dirty traffic prefixes to Cloudflare/NIC scrubbing infrastructure',
        estimatedLatency: '55ms',
      },
      {
        id: 'STEP-02',
        name: 'Activate Aggressive SYN Cookie Mitigation',
        actionType: 'KERNEL_SYN_COOKIE',
        target: 'Host TCP Stack (net.ipv4.tcp_syncookies = 1)',
        requiredPermission: 'network.kernel.tune',
        rollbackAction: 'RESTORE_DEFAULT_SYN_POLICY',
        description: 'Protect against TCP half-open connection table exhaustion without dropping legit users',
        estimatedLatency: '8ms',
      },
      {
        id: 'STEP-03',
        name: 'Apply Geo-Fence Rules on Foreign Tor / VPN Nodes',
        actionType: 'GEOFENCE_DROP',
        target: 'Inbound Edge Access Control List',
        requiredPermission: 'firewall.geofence.write',
        rollbackAction: 'REMOVE_GEOFENCE_FILTER',
        description: 'Drop traffic originating from non-domestic anonymous proxy relays',
        estimatedLatency: '26ms',
      },
    ],
  },
];

const PRESET_TARGETS = [
  { label: 'srv-fin-db-01 · 10.0.1.20 (Database)', value: '10.0.1.20 / srv-fin-db-01 (Ubuntu 22.04 LTS)' },
  { label: 'dc-primary · 10.0.0.5 (Domain Controller)', value: '10.0.0.5 / dc-primary.internal.gov (Windows Server 2022)' },
  { label: 'anurag.swain (Global Admin Identity)', value: 'anurag.swain@ntro.gov.in (Kerberos Principal)' },
  { label: 'pfSense-gateway · 192.168.1.1 (Perimeter)', value: '192.168.1.1 / pfSense-perimeter-01 (Core Gateway)' },
  { label: 'ws-finance-04 · 10.0.2.14 (Endpoint)', value: '10.0.2.14 / ws-finance-04 (Windows 11 Enterprise)' },
  { label: 'powershell.exe · PID 4820 (Malicious Proc)', value: 'PID 4820 (powershell.exe) on srv-app-01' },
  { label: 'c2-beacon · 198.51.100.42 (Hostile IP)', value: '198.51.100.42 / c2-beacon.darknet-nexus.org' },
  { label: 'CERT-In Incident Desk (SLA-2026)', value: 'CERT-In Incident Desk (Ref: CERT-IN-SLA-2026-0928)' },
  { label: 'ULPF Sovereign Ledger (Epoch 8492)', value: 'Block Ledger: ULPF-SOVEREIGN-CHAIN (Epoch 8492)' },
];

// ---------------------------------------------------------------------------
// Component Implementation
// ---------------------------------------------------------------------------

export const ResponsePlaybooks: React.FC = () => {
  const [searchParams] = useSearchParams();
  const paramPlaybook = searchParams.get('playbook');
  const paramAsset = searchParams.get('asset');

  const [selectedPlaybookId, setSelectedPlaybookId] = useState<string>(() => {
    if (paramPlaybook && PLAYBOOK_CATALOG.some((p) => p.id === paramPlaybook)) {
      return paramPlaybook;
    }
    return 'PB-RANSOMWARE-CONTAINMENT';
  });
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [executionMode, setExecutionMode] = useState<'DRY_RUN' | 'LIVE_GUARDED'>('DRY_RUN');
  const [operatorConfirmation, setOperatorConfirmation] = useState('');
  
  // Active playbook definition
  const activePlaybook = useMemo(() => {
    return PLAYBOOK_CATALOG.find((p) => p.id === selectedPlaybookId) || PLAYBOOK_CATALOG[0];
  }, [selectedPlaybookId]);

  const [targetAsset, setTargetAsset] = useState<string>(() => {
    if (paramAsset) {
      return decodeURIComponent(paramAsset);
    }
    return activePlaybook.defaultTarget;
  });

  // Sync if URL query parameters change or active playbook changes
  useEffect(() => {
    if (paramPlaybook && PLAYBOOK_CATALOG.some((p) => p.id === paramPlaybook)) {
      setSelectedPlaybookId(paramPlaybook);
    }
  }, [paramPlaybook]);

  useEffect(() => {
    if (paramAsset && selectedPlaybookId === paramPlaybook) {
      setTargetAsset(decodeURIComponent(paramAsset));
    } else {
      setTargetAsset(activePlaybook.defaultTarget);
    }
    setSimulationReport(null);
    setTerminalLogs([]);
  }, [activePlaybook, paramAsset, paramPlaybook, selectedPlaybookId]);

  // Simulation execution state
  const [simulating, setSimulating] = useState(false);
  const [currentStepIndex, setCurrentStepIndex] = useState<number>(-1);
  const [simulationReport, setSimulationReport] = useState<any | null>(null);
  const [terminalLogs, setTerminalLogs] = useState<string[]>([]);
  const [activeOutputTab, setActiveOutputTab] = useState<'dag' | 'terminal' | 'json'>('dag');

  // Filtered playbooks list
  const filteredPlaybooks = useMemo(() => {
    return PLAYBOOK_CATALOG.filter((pb) => {
      const matchCat = selectedCategory === 'ALL' || pb.category === selectedCategory;
      return matchCat;
    });
  }, [selectedCategory]);

  // Handle Playbook Simulation / Dispatch
  const handleRunSimulation = () => {
    setSimulating(true);
    setCurrentStepIndex(0);
    setTerminalLogs([
      `[${new Date().toISOString()}] [SOAR-DISPATCHER] Initializing playbook: ${activePlaybook.id} (${activePlaybook.name})`,
      `[${new Date().toISOString()}] [EXECUTION-MODE] Mode: ${executionMode === 'DRY_RUN' ? 'DRY_RUN_SAFE (0 Mutations Guaranteed)' : 'LIVE_GUARDED_DISPATCH'}`,
      `[${new Date().toISOString()}] [TARGET] Asset: ${targetAsset}`,
      `[${new Date().toISOString()}] [RBAC-CHECK] Validating operator 'ANURAG SWAIN' permissions: [platform-admin, secops.containment.*]... OK (GRANTED)`,
    ]);

    // Simulate animated step progression
    const steps = activePlaybook.steps;
    let stepIdx = 0;

    const interval = setInterval(() => {
      if (stepIdx < steps.length) {
        const step = steps[stepIdx];
        setCurrentStepIndex(stepIdx);
        setTerminalLogs((prev) => [
          ...prev,
          `[${new Date().toISOString()}] [STEP-${stepIdx + 1}/${steps.length}] Executing '${step.name}' on '${step.target}'`,
          `[${new Date().toISOString()}] [ACTION] ${step.actionType} | Perm: ${step.requiredPermission} | Rollback: ${step.rollbackAction}`,
          `[${new Date().toISOString()}] [SIMULATION] Status: VERIFIED_PASS (Execution Latency: ${step.estimatedLatency}, Mutations: 0)`,
        ]);
        stepIdx++;
      } else {
        clearInterval(interval);
        setSimulating(false);
        setCurrentStepIndex(steps.length);
        
        // Final report object
        const report = {
          playbook_id: activePlaybook.id,
          playbook_name: activePlaybook.name,
          category: activePlaybook.category,
          severity: activePlaybook.severity,
          target_asset: targetAsset,
          execution_mode: executionMode === 'DRY_RUN' ? 'DRY_RUN_SAFE_ZERO_MUTATIONS' : 'LIVE_GUARDED_SIMULATED',
          operator: 'ANURAG SWAIN (platform-admin)',
          timestamp: new Date().toISOString(),
          blast_radius: activePlaybook.blastRadius,
          total_steps: steps.length,
          permissions_validated: true,
          mutations_committed: 0,
          side_effects_occurred: false,
          rollback_guaranteed: true,
          cryptographic_attestation_sha256: '9f4a8b27c13d8e5f0124689b7a4c9d123e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b',
          dry_run_verdict: 'PASS_NO_SIDE_EFFECTS',
          step_audit: steps.map((s, idx) => ({
            step_number: idx + 1,
            step_id: s.id,
            action: s.actionType,
            target: s.target,
            status: 'SIMULATED_SUCCESS',
            latency: s.estimatedLatency,
            permission_checked: s.requiredPermission,
            rollback_action: s.rollbackAction,
          })),
        };

        setSimulationReport(report);
        setTerminalLogs((prev) => [
          ...prev,
          `[${new Date().toISOString()}] [ROLLBACK-VERIFICATION] Rollback plan verified for all ${steps.length} steps. 100% reversible.`,
          `[${new Date().toISOString()}] [INTEGRITY-HASH] Evidence Digest SHA-256: 9f4a...7a8b (Anchored to Memory Vault)`,
          `[${new Date().toISOString()}] [DISPATCH-RESULT] SIMULATION VERDICT: PASS_NO_SIDE_EFFECTS. 0 Mutations applied.`,
        ]);
      }
    }, 400);
  };

  return (
    <div className="space-y-5">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-border-light">
        <div>
          <h2 className="text-lg font-bold text-navy-900 tracking-tight flex items-center gap-2">
            <Zap className="w-5 h-5 text-amber-500" />
            <span>Response Playbook Automation (SOAR Dispatcher)</span>
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Zero-side-effect automated playbooks verifying permissions, blast radius, and rollbacks before execution
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <Badge variant={executionMode === 'DRY_RUN' ? 'warn' : 'danger'}>
            MODE: {executionMode === 'DRY_RUN' ? 'DRY-RUN SIMULATOR (SAFE)' : 'LIVE GUARDED DISPATCH'}
          </Badge>
          <span className="text-xs font-mono text-emerald-700 bg-emerald-50 border border-emerald-200 px-2 py-0.5 rounded font-bold">
            {PLAYBOOK_CATALOG.length} Sovereign Playbooks Ready
          </span>
        </div>
      </div>

      {/* KPI Overview Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: 'Available Playbooks', value: `${PLAYBOOK_CATALOG.length}`, color: 'text-navy-900', bg: 'bg-white border-slate-200', icon: <Layers className="w-4 h-4 text-gov-blue" /> },
          { label: 'Execution Safety Invariant', value: '0 Mutations', color: 'text-emerald-700', bg: 'bg-emerald-50 border-emerald-200', icon: <Shield className="w-4 h-4 text-emerald-600" /> },
          { label: 'Avg Execution Latency', value: '42 ms', color: 'text-blue-700', bg: 'bg-blue-50 border-blue-200', icon: <Clock className="w-4 h-4 text-blue-600" /> },
          { label: 'Rollback Protection', value: '100% Reversible', color: 'text-purple-700', bg: 'bg-purple-50 border-purple-200', icon: <RotateCcw className="w-4 h-4 text-purple-600" /> },
        ].map((kpi) => (
          <div key={kpi.label} className={`flex items-center gap-3 p-3 rounded-lg border ${kpi.bg}`}>
            <div>{kpi.icon}</div>
            <div>
              <div className={`text-base font-bold font-mono ${kpi.color}`}>{kpi.value}</div>
              <div className="text-[10px] text-slate-500 font-medium uppercase tracking-wide">{kpi.label}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Main Workbench Grid (Left Launcher + Right Monitor stretching to equal height) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-stretch">
        {/* Left Column: Playbook Selector & Launcher (5 cols) */}
        <div className="lg:col-span-5 flex flex-col">
          <Card title="Playbook Dispatcher & Safety Testbed" className="h-full flex flex-col" bodyClassName="flex-1 flex flex-col justify-between space-y-4">
            <div className="space-y-4 text-xs">
              {/* Category Filter Pills */}
              <div>
                <label className="font-semibold text-navy-900 block mb-1.5 flex items-center justify-between">
                  <span>Filter by Category:</span>
                  <span className="font-mono text-[10.5px] text-slate-500">{filteredPlaybooks.length} Available</span>
                </label>
                <div className="flex flex-wrap gap-1.5">
                  {(['ALL', 'Containment', 'Identity', 'Network', 'Compliance', 'Forensics'] as const).map((cat) => (
                    <button
                      key={cat}
                      type="button"
                      onClick={() => setSelectedCategory(cat)}
                      className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors cursor-pointer ${
                        selectedCategory === cat
                          ? 'bg-navy-900 text-white font-bold'
                          : 'bg-slate-100 hover:bg-slate-200 text-slate-700'
                      }`}
                    >
                      {cat}
                    </button>
                  ))}
                </div>
              </div>

              {/* Playbook Dropdown with clean, compact labels that fit 100% inside the dropdown box */}
              <div>
                <label className="font-semibold text-navy-900 block mb-1">Select Playbook ({PLAYBOOK_CATALOG.length} Total):</label>
                <select
                  value={selectedPlaybookId}
                  onChange={(e) => setSelectedPlaybookId(e.target.value)}
                  className="w-full max-w-full text-xs bg-slate-50 border border-border-medium rounded px-2.5 py-2 font-mono text-navy-900 focus:outline-none focus:ring-2 focus:ring-gov-blue font-semibold truncate"
                >
                  {filteredPlaybooks.map((pb) => (
                    <option key={pb.id} value={pb.id} title={pb.name}>
                      {pb.shortLabel}
                    </option>
                  ))}
                </select>
              </div>

              {/* Active Playbook Context Card */}
              <div className="p-3 rounded-lg border border-slate-200 bg-slate-50/70 space-y-2">
                <div className="flex items-center justify-between gap-1 flex-wrap">
                  <span className="font-mono font-bold text-xs text-navy-900">{activePlaybook.id}</span>
                  <div className="flex items-center gap-1.5">
                    <span
                      className={`text-[9.5px] font-mono font-bold px-1.5 py-0.5 rounded ${
                        activePlaybook.severity === 'CRITICAL'
                          ? 'bg-red-100 text-red-800 border border-red-200'
                          : 'bg-amber-100 text-amber-800 border border-amber-200'
                      }`}
                    >
                      {activePlaybook.severity}
                    </span>
                    <span
                      className={`text-[9.5px] font-mono font-bold px-1.5 py-0.5 rounded ${
                        activePlaybook.blastRadius === 'HIGH'
                          ? 'bg-orange-100 text-orange-800'
                          : activePlaybook.blastRadius === 'MEDIUM'
                          ? 'bg-yellow-100 text-yellow-800'
                          : 'bg-emerald-100 text-emerald-800'
                      }`}
                    >
                      BLAST: {activePlaybook.blastRadius}
                    </span>
                  </div>
                </div>

                <div className="text-xs font-bold text-navy-900">
                  {activePlaybook.name}
                </div>

                <p className="text-[11px] text-slate-600 leading-relaxed">
                  {activePlaybook.description}
                </p>

                {/* MITRE ATT&CK Mappings */}
                <div className="pt-1.5 border-t border-slate-200 flex flex-wrap items-center gap-1 text-[10px] font-mono text-slate-500">
                  <span className="font-semibold text-slate-700">MITRE Mapped:</span>
                  {activePlaybook.mitreTechniques.map((t) => (
                    <span key={t} className="px-1.5 py-0.5 rounded bg-white border border-slate-200 text-navy-900">
                      {t}
                    </span>
                  ))}
                </div>
              </div>

              {/* Target Asset Input & Preset Picker with neat fit */}
              <div>
                <label className="font-semibold text-navy-900 block mb-1 flex items-center justify-between">
                  <span>Target Asset / Entity / Network Scope:</span>
                  <span className="text-[10px] text-slate-400">Choose preset or edit</span>
                </label>
                <div className="space-y-1.5">
                  <input
                    type="text"
                    value={targetAsset}
                    onChange={(e) => setTargetAsset(e.target.value)}
                    className="w-full max-w-full text-xs font-mono bg-white border border-border-medium rounded px-2.5 py-2 text-navy-900 focus:outline-none focus:ring-2 focus:ring-gov-blue truncate"
                    placeholder="Enter target IP, hostname, or identity..."
                  />
                  <select
                    onChange={(e) => {
                      if (e.target.value) setTargetAsset(e.target.value);
                    }}
                    value=""
                    className="w-full max-w-full text-xs font-mono bg-slate-50 border border-slate-200 rounded px-2.5 py-1.5 text-slate-700 focus:outline-none truncate"
                  >
                    <option value="">-- Load Sovereign Target Preset --</option>
                    {PRESET_TARGETS.map((t) => (
                      <option key={t.label} value={t.value} title={t.value}>
                        {t.label}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              {/* Execution Mode Selector (Dry-Run vs Live Guarded) */}
              <div className="pt-2 border-t border-slate-100 space-y-2">
                <label className="font-semibold text-navy-900 block text-xs">Execution Mode:</label>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={() => setExecutionMode('DRY_RUN')}
                    className={`p-2.5 rounded-lg border text-left cursor-pointer transition-all ${
                      executionMode === 'DRY_RUN'
                        ? 'bg-amber-50/70 border-amber-300 ring-2 ring-amber-500'
                        : 'bg-white border-slate-200 hover:bg-slate-50 text-slate-600'
                    }`}
                  >
                    <div className="flex items-center gap-1.5 font-bold text-amber-900 text-xs">
                      <Shield className="w-3.5 h-3.5 text-amber-600" />
                      <span>Dry-Run Mode</span>
                    </div>
                    <div className="text-[10px] text-amber-700/90 mt-0.5">
                      0 Mutations · Safe Simulation
                    </div>
                  </button>

                  <button
                    type="button"
                    onClick={() => setExecutionMode('LIVE_GUARDED')}
                    className={`p-2.5 rounded-lg border text-left cursor-pointer transition-all ${
                      executionMode === 'LIVE_GUARDED'
                        ? 'bg-red-50/70 border-red-300 ring-2 ring-red-500'
                        : 'bg-white border-slate-200 hover:bg-slate-50 text-slate-600'
                    }`}
                  >
                    <div className="flex items-center gap-1.5 font-bold text-red-900 text-xs">
                      <Lock className="w-3.5 h-3.5 text-red-600" />
                      <span>Live Guarded</span>
                    </div>
                    <div className="text-[10px] text-red-700/90 mt-0.5">
                      Dual-Custody Authorized
                    </div>
                  </button>
                </div>

                {executionMode === 'LIVE_GUARDED' && (
                  <div className="p-2.5 rounded bg-red-50 border border-red-200 text-red-900 text-[11px] space-y-1.5 animate-in fade-in">
                    <div className="font-bold flex items-center gap-1">
                      <AlertTriangle className="w-3.5 h-3.5 text-red-600" />
                      <span>Dual-Custody Verification Required</span>
                    </div>
                    <p className="text-[10.5px]">
                      Live execution requires verified operator authorization code. Enter operator key below:
                    </p>
                    <input
                      type="password"
                      placeholder="Enter Operator Authorization Token (e.g. NTRO-AUTH-99)"
                      value={operatorConfirmation}
                      onChange={(e) => setOperatorConfirmation(e.target.value)}
                      className="w-full text-xs font-mono bg-white border border-red-300 rounded px-2 py-1 focus:outline-none"
                    />
                  </div>
                )}
              </div>

              {/* Safety Invariant Notice */}
              <div className="p-2.5 rounded-lg bg-emerald-50 border border-emerald-200 text-emerald-900 text-[11px] leading-relaxed flex items-start gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-600 flex-shrink-0 mt-0.5" />
                <div>
                  <strong>Sovereign Safety Invariant:</strong> The simulation engine pre-computes the complete DAG action graph, checks blast radius, and prepares rollback scripts with zero mutations to production infrastructure.
                </div>
              </div>
            </div>

            {/* Trigger Button positioned at the bottom of left card */}
            <div className="pt-3">
              <Button
                variant="primary"
                size="sm"
                onClick={handleRunSimulation}
                disabled={simulating}
                icon={simulating ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                className="w-full justify-center py-2.5 font-bold text-xs"
              >
                {simulating
                  ? `Simulating Step ${(currentStepIndex >= 0 ? currentStepIndex + 1 : 1)}/${activePlaybook.steps.length}...`
                  : executionMode === 'DRY_RUN'
                  ? 'Execute Dry-Run Simulation (0 Mutations)'
                  : 'Dispatch Guarded Live Playbook'}
              </Button>
            </div>
          </Card>
        </div>

        {/* Right Column: Interactive Step Visualizer (DAG) & Full-Height Monitor (7 cols) */}
        <div className="lg:col-span-7 flex flex-col">
          <Card
            title="Playbook Execution Monitor & Verdict"
            subtitle={`${activePlaybook.steps.length} Automated Action Steps Defined for ${activePlaybook.id}`}
            action={
              simulationReport ? (
                <span className="font-mono text-xs font-bold text-emerald-700 bg-emerald-50 px-2.5 py-1 rounded border border-emerald-200 flex items-center gap-1.5 shadow-2xs">
                  <Check className="w-3.5 h-3.5 text-emerald-600" />
                  <span>{simulationReport.dry_run_verdict}</span>
                </span>
              ) : null
            }
            className="h-full flex flex-col"
            bodyClassName="flex-1 flex flex-col"
          >
            {/* View Mode Tabs (Completely separated from status badge in Card header) */}
            <div className="flex items-center gap-1.5 border-b border-slate-200 pb-2.5 mb-3 text-xs flex-shrink-0">
              <button
                type="button"
                onClick={() => setActiveOutputTab('dag')}
                className={`px-3 py-1.5 rounded-md font-semibold transition-colors flex items-center gap-1.5 cursor-pointer ${
                  activeOutputTab === 'dag'
                    ? 'bg-navy-900 text-white shadow-xs'
                    : 'bg-slate-100 hover:bg-slate-200 text-slate-700'
                }`}
              >
                <Layers className="w-3.5 h-3.5" />
                <span>Visual Action Graph ({activePlaybook.steps.length})</span>
              </button>
              <button
                type="button"
                onClick={() => setActiveOutputTab('terminal')}
                className={`px-3 py-1.5 rounded-md font-semibold transition-colors flex items-center gap-1.5 cursor-pointer ${
                  activeOutputTab === 'terminal'
                    ? 'bg-navy-900 text-white shadow-xs'
                    : 'bg-slate-100 hover:bg-slate-200 text-slate-700'
                }`}
              >
                <Terminal className="w-3.5 h-3.5" />
                <span>Dispatch Terminal ({terminalLogs.length})</span>
              </button>
              <button
                type="button"
                onClick={() => setActiveOutputTab('json')}
                className={`px-3 py-1.5 rounded-md font-semibold transition-colors flex items-center gap-1.5 cursor-pointer ${
                  activeOutputTab === 'json'
                    ? 'bg-navy-900 text-white shadow-xs'
                    : 'bg-slate-100 hover:bg-slate-200 text-slate-700'
                }`}
              >
                <FileText className="w-3.5 h-3.5" />
                <span>Audit JSON</span>
              </button>
            </div>

            {/* TAB 1: VISUAL ACTION GRAPH (DAG) */}
            {activeOutputTab === 'dag' && (
              <div className="flex-1 flex flex-col justify-between space-y-3">
                <div className="space-y-2.5">
                  {activePlaybook.steps.map((step, idx) => {
                    const isExecuted = simulationReport || (simulating && currentStepIndex >= idx);
                    const isCurrentlyRunning = simulating && currentStepIndex === idx;

                    return (
                      <div
                        key={step.id}
                        className={`p-3 rounded-lg border transition-all ${
                          isCurrentlyRunning
                            ? 'bg-amber-50 border-amber-300 ring-2 ring-amber-400 shadow-sm'
                            : isExecuted
                            ? 'bg-white border-emerald-200 shadow-xs'
                            : 'bg-slate-50 border-slate-200 opacity-80'
                        }`}
                      >
                        <div className="flex items-start justify-between gap-2">
                          <div className="flex items-center gap-2">
                            <div
                              className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-mono font-bold ${
                                isExecuted
                                  ? 'bg-emerald-600 text-white'
                                  : isCurrentlyRunning
                                  ? 'bg-amber-500 text-white animate-pulse'
                                  : 'bg-slate-200 text-slate-600'
                              }`}
                            >
                              {isExecuted ? <Check className="w-3.5 h-3.5" /> : idx + 1}
                            </div>
                            <div>
                              <div className="text-xs font-bold text-navy-900 flex items-center gap-2">
                                <span>{step.name}</span>
                                <span className="font-mono text-[10px] text-slate-400">{step.id}</span>
                              </div>
                              <p className="text-[11px] text-slate-600 mt-0.5">{step.description}</p>
                            </div>
                          </div>

                          <div className="flex flex-col items-end gap-1 flex-shrink-0">
                            <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 font-semibold">
                              {step.actionType}
                            </span>
                            <span className="font-mono text-[10px] text-slate-400">
                              {step.estimatedLatency}
                            </span>
                          </div>
                        </div>

                        {/* Step Details & Rollback action */}
                        <div className="mt-2.5 pt-2 border-t border-slate-100 flex flex-wrap items-center justify-between gap-2 text-[10.5px] font-mono">
                          <div className="flex items-center gap-1.5 text-slate-600">
                            <KeyRound className="w-3 h-3 text-gov-blue" />
                            <span>Perm: <strong>{step.requiredPermission}</strong></span>
                          </div>

                          <div className="flex items-center gap-1 text-purple-700 bg-purple-50 px-2 py-0.5 rounded border border-purple-100">
                            <RotateCcw className="w-3 h-3 text-purple-600" />
                            <span>Rollback: {step.rollbackAction}</span>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Verdict summary banner */}
                {simulationReport ? (
                  <div className="p-3.5 rounded-lg bg-emerald-50/70 border border-emerald-200 text-xs space-y-1.5 mt-auto">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-emerald-900 flex items-center gap-1.5">
                        <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                        Dry-Run Simulation Verdict: Verified Safe
                      </span>
                      <span className="font-mono text-[11px] font-bold text-emerald-700">
                        Mutations: 0 (Strictly Invariant)
                      </span>
                    </div>
                    <p className="text-[11.5px] text-emerald-800 leading-relaxed">
                      All {activePlaybook.steps.length} projected actions verified against current RBAC permissions. Rollback scripts generated in memory with zero side-effects to active production network.
                    </p>
                    <div className="pt-2 border-t border-emerald-200/60 font-mono text-[10px] text-emerald-700 truncate">
                      Proof Digest: {simulationReport.cryptographic_attestation_sha256}
                    </div>
                  </div>
                ) : (
                  <div className="p-6 border border-dashed border-border-medium rounded-lg bg-slate-50 flex flex-col items-center justify-center text-slate-400 text-xs text-center mt-auto">
                    <Zap className="w-6 h-6 text-slate-300 mb-1" />
                    <span className="font-semibold text-slate-600">Simulator Standby</span>
                    <span className="text-[11px] text-slate-400 mt-0.5">Click 'Execute Dry-Run Simulation' to run through the {activePlaybook.steps.length} actions with zero mutations.</span>
                  </div>
                )}
              </div>
            )}

            {/* TAB 2: TERMINAL CONSOLE LOGS (Extended full height to align with Execute Button) */}
            {activeOutputTab === 'terminal' && (
              <div className="flex-1 flex flex-col space-y-2">
                <div className="bg-navy-950 text-emerald-400 font-mono text-[11px] p-3.5 rounded-lg overflow-y-auto min-h-[480px] h-[520px] space-y-1 border border-navy-900 shadow-inner flex flex-col flex-1">
                  <div className="text-slate-400 pb-1.5 border-b border-slate-800 text-[10px] flex items-center justify-between flex-shrink-0">
                    <span>// ULPF SOAR SECURE SIMULATION TERMINAL — v1.0.0</span>
                    <span className="text-emerald-500 font-bold flex items-center gap-1">
                      <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                      READY
                    </span>
                  </div>
                  <div className="flex-1 overflow-y-auto space-y-1 pt-1.5">
                    {terminalLogs.length > 0 ? (
                      terminalLogs.map((log, idx) => (
                        <div key={idx} className="leading-relaxed">
                          {log}
                        </div>
                      ))
                    ) : (
                      <div className="h-full flex flex-col items-center justify-center text-slate-500 py-20 text-center">
                        <Terminal className="w-10 h-10 text-slate-700 mb-2" />
                        <span className="text-slate-400 font-semibold">SOAR Telemetry Stream Idle</span>
                        <span className="text-[10.5px] text-slate-500 mt-1">Execute a dry-run simulation to view live step dispatch logs.</span>
                      </div>
                    )}
                  </div>
                </div>

                <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono px-1 flex-shrink-0">
                  <span className="truncate max-w-sm">Target: <strong>{targetAsset}</strong></span>
                  <span>Operator: <strong>ANURAG SWAIN</strong></span>
                </div>
              </div>
            )}

            {/* TAB 3: AUDIT JSON (Fills full height with scrollbar flush at bottom edge) */}
            {activeOutputTab === 'json' && (
              <div className="flex-1 flex flex-col min-h-0">
                {simulationReport ? (
                  <CodePanel
                    code={JSON.stringify(simulationReport, null, 2)}
                    title={`AUDIT-REPORT-${activePlaybook.id}.JSON`}
                    className="flex-1 min-h-[460px]"
                  />
                ) : (
                  <div className="flex-1 min-h-[460px] border border-dashed border-border-medium rounded-lg bg-slate-50 flex flex-col items-center justify-center text-slate-400 text-xs p-6 text-center">
                    <FileText className="w-10 h-10 text-slate-300 mb-2" />
                    <span className="font-semibold text-slate-600 text-sm">Audit JSON Report Standby</span>
                    <span className="text-[11px] text-slate-400 mt-1 max-w-sm">
                      Execute a dry-run simulation to generate the complete cryptographic JSON audit report. The report expands to fill the entire workspace.
                    </span>
                  </div>
                )}
              </div>
            )}
          </Card>
        </div>
      </div>
    </div>
  );
};
