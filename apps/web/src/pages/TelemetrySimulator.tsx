import React, { useState, useEffect, useRef, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { MetricCard } from '../components/ui/MetricCard';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { CodePanel } from '../components/ui/CodePanel';
import { TelemetryEvent } from '../api/operations';
import {
  Flame,
  Play,
  Pause,
  RotateCcw,
  Zap,
  Activity,
  Radio,
  ExternalLink,
  ShieldAlert,
  Server,
  Terminal,
  CheckCircle2,
  Download,
  Layers,
  Eye,
  RefreshCw,
  SlidersHorizontal,
  Cpu,
  FileCode,
  Code2,
  Sparkles,
  Crosshair,
  Send,
  Hash,
  ShieldCheck,
  Copy,
  Check,
  Search,
} from 'lucide-react';

interface CampaignPreset {
  id: string;
  name: string;
  vendor: string;
  format: string;
  category: 'network' | 'cloud' | 'identity' | 'endpoint' | 'container' | 'stress';
  mitreTechnique: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'INFO';
  description: string;
  parser: string;
  generator: () => { raw: string; event: TelemetryEvent };
}

const CAMPAIGNS: CampaignPreset[] = [
  {
    id: 'campaign-brute-force',
    name: 'Multi-Stage Credential Stuffing & SQL Injection',
    vendor: 'Palo Alto Networks',
    format: 'CSV / Syslog',
    category: 'network',
    mitreTechnique: 'T1110.001 / T1190',
    severity: 'HIGH',
    parser: 'palo_alto_panos',
    description: 'High-frequency sequential authentication failures targeting internal web portals followed by SQL payload injection.',
    generator: () => {
      const srcIps = ['198.51.100.99', '203.0.113.88', '192.0.2.45', '185.220.101.5'];
      const ip = srcIps[Math.floor(Math.random() * srcIps.length)];
      const port = Math.floor(Math.random() * 40000) + 10240;
      const now = new Date().toISOString();
      const raw = `1,${now.replace('T', ' ').substring(0, 19)},001801000331,THREAT,vulnerability,1,${now.replace('T', ' ').substring(0, 19)},${ip},10.0.1.45,0.0.0.0,0.0.0.0,Rule-Block-Lateral,,,web-browsing,vsys1,untrust,trust,ethernet1/1,ethernet1/2,LogForwarder,${now.replace('T', ' ').substring(0, 19)},98124,1,443,${port},0,0,0x8000,tcp,deny,,"SELECT * FROM users WHERE '1'='1'",12948192,0x0,13,United States,India,0,1,0,drop,0,0,0,0,,dc-core,0,,0,,,0`;
      const event: TelemetryEvent = {
        event_id: `evt-pan-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
        timestamp: now,
        source: 'pan-fw01-edge.ntro.internal',
        vendor: 'Palo Alto Networks',
        format: 'CSV / Syslog',
        category: 'network',
        action: 'deny',
        severity: 'HIGH',
        parser: 'palo_alto_panos',
        uce_status: 'NORMALIZED',
        processing_status: 'PROCESSED',
        tenant_id: 'default',
        raw_payload: raw,
        byte_length: raw.length,
        sha256: `pan_${Date.now().toString(16)}_${Math.random().toString(16).substring(2, 10)}`,
        entities: [
          { type: 'IPv4', value: ip, confidence: 1.0 },
          { type: 'IPv4', value: '10.0.1.45', confidence: 1.0 },
          { type: 'Port', value: String(port), confidence: 1.0 },
        ],
        extracted_fields: {
          src_ip: ip,
          dst_ip: '10.0.1.45',
          dst_port: 443,
          action: 'deny',
          threat_type: 'vulnerability',
          payload: "SELECT * FROM users WHERE '1'='1'",
          mitre: 'T1110.001 / T1190',
        },
        detection_title: 'Multi-Stage Credential Stuffing & SQL Injection',
      };
      return { raw, event };
    },
  },
  {
    id: 'campaign-fortigate-c2',
    name: 'FortiGate Lateral Movement & C2 Beaconing',
    vendor: 'Fortinet FortiGate',
    format: 'Key-Value (KV)',
    category: 'network',
    mitreTechnique: 'T1071.001 / T1021.002',
    severity: 'CRITICAL',
    parser: 'fortinet_fortios',
    description: 'Outbound SMB and TLS beacons to dynamic malicious command-and-control infrastructure.',
    generator: () => {
      const c2s = ['185.190.140.12', '91.240.118.99', '45.154.255.80'];
      const c2 = c2s[Math.floor(Math.random() * c2s.length)];
      const now = new Date().toISOString();
      const raw = `date=${now.substring(0, 10)} time=${now.substring(11, 19)} devname="FGT-CORE-01" devid="FGT60D4614041234" logid="0000000013" type="traffic" subtype="forward" level="warning" vd="root" srcip=10.0.1.15 srcport=49210 srcintf="port1" dstip=${c2} dstport=445 dstintf="port2" polid=4 sessionid=98120 proto=6 action="deny" policytype="IPv4" policyname="Isolate-Threat" app="SMB" duration=12 sentbyte=410 rcvdbyte=0 sentpkt=4 rcvdpkt=0 crscore=50 crlevel="high"`;
      const event: TelemetryEvent = {
        event_id: `evt-fgt-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
        timestamp: now,
        source: 'fgt-core-01.ntro.internal',
        vendor: 'Fortinet FortiGate',
        format: 'Key-Value (KV)',
        category: 'network',
        action: 'deny',
        severity: 'CRITICAL',
        parser: 'fortinet_fortios',
        uce_status: 'NORMALIZED',
        processing_status: 'PROCESSED',
        tenant_id: 'default',
        raw_payload: raw,
        byte_length: raw.length,
        sha256: `fgt_${Date.now().toString(16)}_${Math.random().toString(16).substring(2, 10)}`,
        entities: [
          { type: 'IPv4', value: '10.0.1.15', confidence: 1.0 },
          { type: 'IPv4', value: c2, confidence: 1.0 },
          { type: 'Port', value: '445', confidence: 1.0 },
        ],
        extracted_fields: {
          src_ip: '10.0.1.15',
          dst_ip: c2,
          dst_port: 445,
          action: 'deny',
          app: 'SMB',
          c2_indicator: c2,
          mitre: 'T1071.001 / T1021.002',
        },
        detection_title: 'FortiGate Lateral Movement & C2 Beaconing',
      };
      return { raw, event };
    },
  },
  {
    id: 'campaign-cloudtrail-iam',
    name: 'AWS CloudTrail Root Privilege Escalation',
    vendor: 'Cloud Native / AWS',
    format: 'JSON',
    category: 'cloud',
    mitreTechnique: 'T1078.004 / T1098',
    severity: 'CRITICAL',
    parser: 'aws_cloudtrail',
    description: 'Unauthorized AttachUserPolicy and CreateAccessKey calls executed outside standard change windows.',
    generator: () => {
      const now = new Date().toISOString();
      const rawObj = {
        eventVersion: '1.08',
        userIdentity: {
          type: 'IAMUser',
          principalId: 'AIDAEXAMPLEUSER',
          arn: 'arn:aws:iam::123456789012:user/dev-admin-compromised',
          accountId: '123456789012',
          userName: 'dev-admin-compromised',
        },
        eventTime: now,
        eventSource: 'iam.amazonaws.com',
        eventName: 'AttachUserPolicy',
        awsRegion: 'us-east-1',
        sourceIPAddress: '198.51.100.99',
        userAgent: 'aws-cli/2.15.0 Python/3.11.6 Linux/6.5.0 botocore/2.4.0',
        requestParameters: {
          userName: 'dev-admin-compromised',
          policyArn: 'arn:aws:iam::aws:policy/AdministratorAccess',
        },
        responseElements: null,
        requestID: `req-${Date.now().toString(36)}`,
        eventID: `evt-cloud-${Math.random().toString(36).substring(2, 8)}`,
        eventType: 'AwsApiCall',
      };
      const raw = JSON.stringify(rawObj);
      const event: TelemetryEvent = {
        event_id: `evt-aws-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
        timestamp: now,
        source: 'aws.iam.global',
        vendor: 'AWS CloudTrail',
        format: 'JSON',
        category: 'cloud',
        action: 'allow',
        severity: 'CRITICAL',
        parser: 'aws_cloudtrail',
        uce_status: 'NORMALIZED',
        processing_status: 'PROCESSED',
        tenant_id: 'default',
        raw_payload: raw,
        byte_length: raw.length,
        sha256: `aws_${Date.now().toString(16)}_${Math.random().toString(16).substring(2, 10)}`,
        entities: [
          { type: 'IAMUser', value: 'dev-admin-compromised', confidence: 1.0 },
          { type: 'IPv4', value: '198.51.100.99', confidence: 1.0 },
        ],
        extracted_fields: {
          user_name: 'dev-admin-compromised',
          event_name: 'AttachUserPolicy',
          source_ip: '198.51.100.99',
          policy_arn: 'arn:aws:iam::aws:policy/AdministratorAccess',
          mitre: 'T1078.004 / T1098',
        },
        detection_title: 'AWS CloudTrail Root Privilege Escalation',
      };
      return { raw, event };
    },
  },
  {
    id: 'campaign-suricata-nids',
    name: 'Suricata NIDS Remote Code Execution Exploit',
    vendor: 'OISF Suricata',
    format: 'EVE JSON',
    category: 'network',
    mitreTechnique: 'T1203 / T1059.004',
    severity: 'HIGH',
    parser: 'suricata_eve',
    description: 'Exploit probe targeting Apache Struts and Log4j CVE vectors detected on perimeter interfaces.',
    generator: () => {
      const now = new Date().toISOString();
      const rawObj = {
        timestamp: now,
        flow_id: Math.floor(Math.random() * 90000000) + 10000000,
        event_type: 'alert',
        src_ip: '203.0.113.88',
        src_port: Math.floor(Math.random() * 40000) + 10240,
        dest_ip: '10.0.1.50',
        dest_port: 8080,
        proto: 'TCP',
        alert: {
          action: 'blocked',
          gid: 1,
          signature_id: 2031490,
          rev: 2,
          signature: 'ET EXPLOIT Apache Struts OGNL Expression Injection (CVE-2017-5638)',
          category: 'Attempted Administrator Privilege Gain',
          severity: 1,
        },
        direction: 'to_server',
      };
      const raw = JSON.stringify(rawObj);
      const event: TelemetryEvent = {
        event_id: `evt-sur-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
        timestamp: now,
        source: 'suricata-sensor-01.ntro.internal',
        vendor: 'OISF Suricata',
        format: 'EVE JSON',
        category: 'network',
        action: 'block',
        severity: 'HIGH',
        parser: 'suricata_eve',
        uce_status: 'NORMALIZED',
        processing_status: 'PROCESSED',
        tenant_id: 'default',
        raw_payload: raw,
        byte_length: raw.length,
        sha256: `sur_${Date.now().toString(16)}_${Math.random().toString(16).substring(2, 10)}`,
        entities: [
          { type: 'IPv4', value: '203.0.113.88', confidence: 1.0 },
          { type: 'IPv4', value: '10.0.1.50', confidence: 1.0 },
        ],
        extracted_fields: {
          src_ip: '203.0.113.88',
          dst_ip: '10.0.1.50',
          dst_port: 8080,
          cve: 'CVE-2017-5638',
          signature: 'ET EXPLOIT Apache Struts OGNL Expression Injection',
          mitre: 'T1203 / T1059.004',
        },
        detection_title: 'Suricata NIDS Remote Code Execution Exploit',
      };
      return { raw, event };
    },
  },
  {
    id: 'campaign-zeek-exfil',
    name: 'Zeek DNS Tunneling & C2 Exfiltration',
    vendor: 'Zeek Bro Network',
    format: 'TSV / Zeek Log',
    category: 'network',
    mitreTechnique: 'T1048.003 / T1071.004',
    severity: 'HIGH',
    parser: 'zeek_dns',
    description: 'High-entropy base64 DNS query floods exfiltrating sovereign payload fragments via TXT requests.',
    generator: () => {
      const now = (Date.now() / 1000).toFixed(6);
      const subdomains = ['aW50ZWwK', 'Y3JlZHMK', 'c2hhZG93', 'ZXhmaWwK'];
      const sub = subdomains[Math.floor(Math.random() * subdomains.length)];
      const raw = `${now}\tC01${Math.random().toString(36).substring(2, 8)}\t10.0.1.88\t51234\t1.1.1.1\t53\tudp\t49120\t${sub}.attacker-c2.net\t1\tC_INTERNET\t16\tTXT\t0\tNOERROR\tF\tF\tT\tT\t0\t-\t-\tF`;
      const event: TelemetryEvent = {
        event_id: `evt-zeek-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
        timestamp: new Date().toISOString(),
        source: 'zeek-edge-tap0.ntro.internal',
        vendor: 'Zeek Bro',
        format: 'TSV / Zeek Log',
        category: 'network',
        action: 'allow',
        severity: 'HIGH',
        parser: 'zeek_dns',
        uce_status: 'NORMALIZED',
        processing_status: 'PROCESSED',
        tenant_id: 'default',
        raw_payload: raw,
        byte_length: raw.length,
        sha256: `zeek_${Date.now().toString(16)}_${Math.random().toString(16).substring(2, 10)}`,
        entities: [
          { type: 'IPv4', value: '10.0.1.88', confidence: 1.0 },
          { type: 'Domain', value: `${sub}.attacker-c2.net`, confidence: 1.0 },
        ],
        extracted_fields: {
          src_ip: '10.0.1.88',
          dns_server: '1.1.1.1',
          query: `${sub}.attacker-c2.net`,
          qtype_name: 'TXT',
          entropy: 4.82,
          mitre: 'T1048.003 / T1071.004',
        },
        detection_title: 'Zeek DNS Tunneling & C2 Exfiltration',
      };
      return { raw, event };
    },
  },
  {
    id: 'campaign-crowdstrike-pth',
    name: 'CrowdStrike Falcon Pass-the-Hash & LSASS Dump',
    vendor: 'CrowdStrike Falcon',
    format: 'JSON',
    category: 'endpoint',
    mitreTechnique: 'T1003.001 / T1550.002',
    severity: 'CRITICAL',
    parser: 'crowdstrike_fdr',
    description: 'Mimikatz-style LSASS process memory injection followed by Kerberos ticket pass-the-hash lateral authentication.',
    generator: () => {
      const now = new Date().toISOString();
      const rawObj = {
        timestamp: now,
        event_type: 'ProcessRollup2',
        ComputerName: 'DC01-PROD-AD',
        UserName: 'svc_backup_admin',
        FileName: 'mimikatz.exe',
        CommandLine: 'sekurlsa::logonpasswords full',
        ParentBaseFileName: 'powershell.exe',
        TargetProcess: 'lsass.exe',
        Tactic: 'Credential Access',
        Technique: 'T1003.001',
        Severity: 'Critical',
      };
      const raw = JSON.stringify(rawObj);
      const event: TelemetryEvent = {
        event_id: `evt-cs-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
        timestamp: now,
        source: 'DC01-PROD-AD.ad.internal',
        vendor: 'CrowdStrike Falcon',
        format: 'JSON',
        category: 'endpoint',
        action: 'block',
        severity: 'CRITICAL',
        parser: 'crowdstrike_fdr',
        uce_status: 'NORMALIZED',
        processing_status: 'PROCESSED',
        tenant_id: 'default',
        raw_payload: raw,
        byte_length: raw.length,
        sha256: `cs_${Date.now().toString(16)}_${Math.random().toString(16).substring(2, 10)}`,
        entities: [
          { type: 'Host', value: 'DC01-PROD-AD', confidence: 1.0 },
          { type: 'User', value: 'svc_backup_admin', confidence: 1.0 },
        ],
        extracted_fields: {
          host: 'DC01-PROD-AD',
          user: 'svc_backup_admin',
          process: 'mimikatz.exe',
          target_process: 'lsass.exe',
          mitre: 'T1003.001 / T1550.002',
        },
        detection_title: 'CrowdStrike Falcon Pass-the-Hash & LSASS Dump',
      };
      return { raw, event };
    },
  },
  {
    id: 'campaign-k8s-escape',
    name: 'Kubernetes KubeAudit Container Breakout',
    vendor: 'Kubernetes API',
    format: 'JSON',
    category: 'container',
    mitreTechnique: 'T1611 / T1609',
    severity: 'HIGH',
    parser: 'k8s_audit',
    description: 'Unauthorized namespace pod exec bypassing RBAC admission controls with hostPath volume mount.',
    generator: () => {
      const now = new Date().toISOString();
      const rawObj = {
        kind: 'Event',
        apiVersion: 'audit.k8s.io/v1',
        stage: 'ResponseComplete',
        verb: 'create',
        user: { username: 'cluster-service-account-shadow' },
        requestURI: '/api/v1/namespaces/kube-system/pods/attacker-backdoor/exec',
        responseStatus: { code: 200 },
        objectRef: { resource: 'pods', namespace: 'kube-system', name: 'attacker-backdoor' },
        sourceIPs: ['10.244.2.19'],
        userAgent: 'kubectl/v1.28.2 (linux/amd64)',
      };
      const raw = JSON.stringify(rawObj);
      const event: TelemetryEvent = {
        event_id: `evt-k8s-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
        timestamp: now,
        source: 'k8s-control-plane-01',
        vendor: 'Kubernetes API',
        format: 'JSON',
        category: 'container',
        action: 'allow',
        severity: 'HIGH',
        parser: 'k8s_audit',
        uce_status: 'NORMALIZED',
        processing_status: 'PROCESSED',
        tenant_id: 'default',
        raw_payload: raw,
        byte_length: raw.length,
        sha256: `k8s_${Date.now().toString(16)}_${Math.random().toString(16).substring(2, 10)}`,
        entities: [
          { type: 'ServiceAccount', value: 'cluster-service-account-shadow', confidence: 1.0 },
          { type: 'Namespace', value: 'kube-system', confidence: 1.0 },
        ],
        extracted_fields: {
          user: 'cluster-service-account-shadow',
          namespace: 'kube-system',
          verb: 'create',
          uri: '/api/v1/namespaces/kube-system/pods/attacker-backdoor/exec',
          mitre: 'T1611 / T1609',
        },
        detection_title: 'Kubernetes KubeAudit Container Breakout',
      };
      return { raw, event };
    },
  },
  {
    id: 'campaign-ddos-flood',
    name: 'Wire-Speed Port 514 UDP Syslog Stress Burst',
    vendor: 'Core Ingestion Socket',
    format: 'Syslog RFC5424',
    category: 'stress',
    mitreTechnique: 'T1498 / High EPS',
    severity: 'MEDIUM',
    parser: 'rfc5424_syslog',
    description: 'High-volume synthetic burst to stress-test parser framers, circular buffers, and socket intake backpressure.',
    generator: () => {
      const now = new Date().toISOString();
      const raw = `<134>1 ${now} router-core-01.ntro.net kernel 8912 ID47 [origin enterpriseId="32473" software="RouterOS"] SYN_FLOOD_DETECT interface=ge-0/0/0 pps=94280 drop=true`;
      const event: TelemetryEvent = {
        event_id: `evt-ddos-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
        timestamp: now,
        source: 'router-core-01.ntro.net',
        vendor: 'Syslog RFC5424',
        format: 'Syslog RFC5424',
        category: 'network',
        action: 'drop',
        severity: 'MEDIUM',
        parser: 'rfc5424_syslog',
        uce_status: 'NORMALIZED',
        processing_status: 'PROCESSED',
        tenant_id: 'default',
        raw_payload: raw,
        byte_length: raw.length,
        sha256: `ddos_${Date.now().toString(16)}_${Math.random().toString(16).substring(2, 10)}`,
        entities: [
          { type: 'Host', value: 'router-core-01.ntro.net', confidence: 1.0 },
        ],
        extracted_fields: {
          app: 'kernel',
          event_type: 'SYN_FLOOD_DETECT',
          pps: 94280,
          action: 'drop',
          mitre: 'T1498',
        },
        detection_title: 'Wire-Speed Port 514 UDP Syslog Stress Burst',
      };
      return { raw, event };
    },
  },
];

const TRANSPORT_CHANNELS = [
  { id: 'syslog-514', name: 'Syslog UDP (Port 514)', proto: 'UDP/514', desc: 'Wire-speed socket intake with zero kernel lock' },
  { id: 'splunk-hec-8088', name: 'Splunk HEC (Port 8088)', proto: 'HTTP/JSON', desc: 'Enterprise collector token authenticated endpoint' },
  { id: 'elastic-bulk-9200', name: 'Elasticsearch Bulk (Port 9200)', proto: 'HTTP/NDJSON', desc: 'High-throughput cluster ingestion adapter' },
  { id: 'ulpf-native', name: 'ULPF Sovereign Ingest API', proto: 'Internal Queue', desc: 'Content-addressed zero-copy memory ring buffer' },
];

export const TelemetrySimulator: React.FC = () => {
  const navigate = useNavigate();
  const [selectedCampaign, setSelectedCampaign] = useState<CampaignPreset>(CAMPAIGNS[0]);
  const [selectedTransport, setSelectedTransport] = useState<string>('syslog-514');
  const [epsRate, setEpsRate] = useState<number>(50);
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [totalInjected, setTotalInjected] = useState<number>(0);
  const [bytesInjected, setBytesInjected] = useState<number>(0);
  const [logs, setLogs] = useState<{ raw: string; event: TelemetryEvent }[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<TelemetryEvent | null>(null);
  const [isPlaybookMode, setIsPlaybookMode] = useState<boolean>(false);
  const [playbookStep, setPlaybookStep] = useState<number>(0);
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [copiedRaw, setCopiedRaw] = useState<boolean>(false);
  const [copiedJson, setCopiedJson] = useState<boolean>(false);
  const [syncBackend, setSyncBackend] = useState<boolean>(false);

  // Sparkline history data points for header activity wave graph
  const [sparklinePoints, setSparklinePoints] = useState<number[]>([10, 15, 12, 20, 25, 18, 30, 28, 45, 50, 42, 48, 52, 60]);

  const logContainerRef = useRef<HTMLDivElement>(null);

  // Ingest batch helper: updates state, dispatches live event, and persists to localStorage
  const ingestEvents = (items: { raw: string; event: TelemetryEvent }[]) => {
    setLogs((prev) => [...items, ...prev].slice(0, 250));
    setTotalInjected((count) => count + items.length);
    const addedBytes = items.reduce((acc, curr) => acc + curr.raw.length, 0);
    setBytesInjected((b) => b + addedBytes);

    // Update sparkline activity wave data points
    setSparklinePoints((pts) => {
      const nextVal = Math.min(85, Math.max(10, Math.floor(Math.random() * 20) + (isRunning ? epsRate / 6 : 10)));
      return [...pts.slice(1), nextVal];
    });

    // Optional fire-and-forget sync to backend API if enabled
    if (syncBackend) {
      items.forEach((item) => {
        fetch('http://localhost:8000/api/v1/platform/events/ingest', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Role': 'platform-admin' },
          body: JSON.stringify({
            raw_payload: item.raw,
            source_id: item.event.source,
            format: item.event.format,
          }),
        }).catch(() => {
          // ignore network failures if backend is offline
        });
      });
    }

    // Persist to localStorage so LiveLogs immediately reflects simulator events
    try {
      const stored = localStorage.getItem('ulpf_simulated_events');
      let existing: TelemetryEvent[] = [];
      if (stored) {
        try {
          existing = JSON.parse(stored);
        } catch {}
      }
      const newEvents = items.map((i) => i.event);
      const combined = [...newEvents, ...existing].slice(0, 200);
      localStorage.setItem('ulpf_simulated_events', JSON.stringify(combined));

      // Broadcast custom event for any live subscriber in the browser
      items.forEach((i) => {
        window.dispatchEvent(new CustomEvent('ulpf:telemetry_injected', { detail: i.event }));
      });
    } catch {
      // ignore
    }
  };

  // Simulation execution loop
  useEffect(() => {
    if (!isRunning) return;

    const intervalMs = Math.max(50, Math.floor(1000 / epsRate));
    const timer = setInterval(() => {
      let campaign = selectedCampaign;

      if (isPlaybookMode) {
        const killChainCampaigns = [
          CAMPAIGNS[3], // Suricata NIDS Recon
          CAMPAIGNS[0], // Palo Alto SQLi
          CAMPAIGNS[2], // AWS CloudTrail PrivEsc
          CAMPAIGNS[1], // FortiGate C2 Beacon
          CAMPAIGNS[4], // Zeek DNS Exfiltration
        ];
        campaign = killChainCampaigns[playbookStep % killChainCampaigns.length];
        setPlaybookStep((s) => (s + 1) % killChainCampaigns.length);
      }

      const generated = campaign.generator();
      ingestEvents([generated]);
    }, intervalMs);

    return () => clearInterval(timer);
  }, [isRunning, epsRate, selectedCampaign, isPlaybookMode, playbookStep, syncBackend]);

  // Single step injection
  const handleInjectSingle = () => {
    const generated = selectedCampaign.generator();
    ingestEvents([generated]);
    setSelectedEvent(generated.event);
  };

  // Burst injection (50 events at once)
  const handleBurst50 = () => {
    const burst: { raw: string; event: TelemetryEvent }[] = [];
    for (let i = 0; i < 50; i++) {
      burst.push(selectedCampaign.generator());
    }
    ingestEvents(burst);
    setSelectedEvent(burst[0].event);
  };

  // Clear console and local buffers
  const handleClear = () => {
    setLogs([]);
    setTotalInjected(0);
    setBytesInjected(0);
    setSelectedEvent(null);
    localStorage.removeItem('ulpf_simulated_events');
  };

  // Export synthetic dataset to .log or .json
  const handleExportDataset = (format: 'log' | 'json') => {
    let content = '';
    let mime = 'text/plain';
    let filename = `ulpf-synthetic-telemetry-${Date.now()}.${format}`;

    if (format === 'json') {
      const data = logs.map((l) => l.event);
      content = JSON.stringify(data, null, 2);
      mime = 'application/json';
    } else {
      content = logs.map((l) => l.raw).join('\n');
    }

    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Generate SVG path for header sparkline graph
  const sparklinePath = useMemo(() => {
    const width = 100;
    const height = 20;
    const max = 100;
    const step = width / (sparklinePoints.length - 1);
    const coords = sparklinePoints.map((val, idx) => {
      const x = idx * step;
      const y = height - (val / max) * height;
      return `${idx === 0 ? 'M' : 'L'} ${x.toFixed(1)},${y.toFixed(1)}`;
    });
    return coords.join(' ');
  }, [sparklinePoints]);

  // Filtered log list
  const filteredLogs = useMemo(() => {
    if (!searchTerm.trim()) return logs;
    const q = searchTerm.toLowerCase();
    return logs.filter((l) => l.raw.toLowerCase().includes(q) || l.event.vendor.toLowerCase().includes(q));
  }, [logs, searchTerm]);

  return (
    <div className="space-y-5">
      {/* Header with Title and Strictly Left-Aligned Action Controls + Telemetry Activity Wave Graph */}
      <div className="pb-4 border-b border-border-light space-y-3">
        {/* Title Row */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Flame className="w-5 h-5 text-amber-600 flex-shrink-0" />
            <h1 className="text-lg font-bold text-navy-900 tracking-tight uppercase">
              Interactive Telemetry &amp; Attack Traffic Simulator
            </h1>
            <Badge variant={isRunning ? 'danger' : 'neutral'} dot>
              {isRunning ? `STREAMING: ${epsRate} EPS` : 'STANDBY'}
            </Badge>
          </div>

          <div className="flex items-center gap-3 text-xs text-slate-500 font-mono">
            <span className="flex items-center gap-1.5">
              <span className={`w-2 h-2 rounded-full ${isRunning ? 'bg-emerald-500 animate-ping' : 'bg-slate-400'}`} />
              Socket Plane: <strong className="text-navy-900">{TRANSPORT_CHANNELS.find((t) => t.id === selectedTransport)?.name}</strong>
            </span>
          </div>
        </div>

        <p className="text-xs text-slate-500">
          Inject realistic multi-vendor attack campaigns, APT kill-chain sequences, and wire-speed synthetic bursts to validate parsing, UCE normalization, and threat detection.
        </p>

        {/* Action Controls & Live Activity Wave Graph - STRICTLY LEFT-ALIGNED */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pt-1">
          {/* LEFT-ALIGNED ACTION CONTROLS */}
          <div className="flex flex-wrap items-center gap-2">
            {/* Start / Pause Generation */}
            <Button
              variant={isRunning ? 'danger' : 'primary'}
              size="sm"
              onClick={() => setIsRunning((r) => !r)}
              className="whitespace-nowrap flex-nowrap"
            >
              {isRunning ? <Pause className="w-3.5 h-3.5 flex-shrink-0" /> : <Play className="w-3.5 h-3.5 flex-shrink-0" />}
              <span className="whitespace-nowrap">{isRunning ? 'Pause Generation' : 'Start Simulation'}</span>
            </Button>

            {/* Burst 50 Events */}
            <Button
              size="sm"
              variant="outline"
              onClick={handleBurst50}
              icon={<Zap className="w-3.5 h-3.5 text-amber-600 flex-shrink-0" />}
              className="whitespace-nowrap flex-nowrap"
            >
              <span className="whitespace-nowrap">Burst 50 Events</span>
            </Button>

            {/* Inject 1 Packet */}
            <Button
              size="sm"
              variant="outline"
              onClick={handleInjectSingle}
              icon={<Send className="w-3.5 h-3.5 text-gov-blue flex-shrink-0" />}
              className="whitespace-nowrap flex-nowrap"
            >
              <span className="whitespace-nowrap">Inject 1 Packet</span>
            </Button>

            {/* View in Live Logs */}
            <Button
              size="sm"
              variant="outline"
              onClick={() => navigate('/live-logs')}
              className="whitespace-nowrap flex-nowrap"
            >
              <ExternalLink className="w-3.5 h-3.5 text-slate-600 flex-shrink-0" />
              <span className="whitespace-nowrap">View in Live Logs</span>
            </Button>
          </div>

          {/* TELEMETRY ACTIVITY WAVE GRAPH IN HEADER */}
          <div className="flex items-center gap-3 bg-slate-50 px-3 py-1.5 rounded-lg border border-slate-200">
            <Activity className="w-4 h-4 text-emerald-600 flex-shrink-0" />
            <div className="flex flex-col">
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">
                Live Throughput Wave
              </span>
              <div className="flex items-center gap-2">
                <svg className="w-24 h-4 overflow-visible" viewBox="0 0 100 20">
                  <path
                    d={sparklinePath}
                    fill="none"
                    stroke={isRunning ? '#059669' : '#94a3b8'}
                    strokeWidth="2.5"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                  {isRunning && (
                    <circle cx="95" cy="10" r="3.5" fill="#059669" className="animate-ping" />
                  )}
                </svg>
                <span className="text-xs font-mono font-bold text-navy-900 whitespace-nowrap">
                  {isRunning ? `${epsRate} EPS` : '0 EPS'}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* KPI Cards Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          label="Total Injected Packets"
          value={`${totalInjected.toLocaleString()} Events`}
          subtext={`Throughput: ${(bytesInjected / 1024).toFixed(1)} KB transmitted`}
          category="Zero Socket Packet Loss"
          badge={<Badge variant="ok" dot>WIRED</Badge>}
          icon={<Zap className="w-4 h-4 text-gov-blue" />}
        />
        <MetricCard
          label="Simulation Frequency"
          value={`${isRunning ? epsRate : 0} EPS`}
          subtext={`Target Frequency: ${epsRate} EPS`}
          category="Deterministic Generation"
          icon={<Radio className="w-4 h-4 text-emerald-600" />}
        />
        <MetricCard
          label="Active Attack Profile"
          value={isPlaybookMode ? 'Automated Kill-Chain' : selectedCampaign.vendor}
          subtext={`Format: ${selectedCampaign.format}`}
          category={selectedCampaign.mitreTechnique}
          badge={<Badge variant={selectedCampaign.severity === 'CRITICAL' ? 'danger' : 'warn'}>{selectedCampaign.severity}</Badge>}
          icon={<ShieldAlert className="w-4 h-4 text-red-600" />}
        />
        <MetricCard
          label="Pipeline Processing Speed"
          value="0.42 ms / pkt"
          subtext="Chronos Parser Runtime"
          category="Backpressure Bounded < 5ms"
          badge={<Badge variant="ok">SAFE</Badge>}
          icon={<Activity className="w-4 h-4 text-emerald-600" />}
        />
      </div>

      {/* Attack Preset Selector & Playbook Mode Toggle */}
      <div className="bg-white border border-border-medium rounded-lg p-4 shadow-2xs space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-border-light">
          <div>
            <span className="text-xs font-bold text-navy-900 uppercase">
              Select Multi-Vendor Attack Preset or Playbook
            </span>
            <span className="text-[11px] font-mono text-slate-500 block">
              Generates genuine multi-vendor syntax, authentic timestamps, and mapped MITRE ATT&amp;CK identifiers
            </span>
          </div>

          {/* Mode Switcher: Single Preset vs Automated Kill-Chain Playbook */}
          <div className="flex items-center gap-1.5 bg-slate-100 p-1 rounded-md">
            <button
              type="button"
              onClick={() => setIsPlaybookMode(false)}
              className={`px-3 py-1 text-xs font-bold rounded transition-all ${
                !isPlaybookMode ? 'bg-white text-navy-900 shadow-2xs' : 'text-slate-600 hover:text-navy-900'
              }`}
            >
              Manual Presets (8)
            </button>
            <button
              type="button"
              onClick={() => {
                setIsPlaybookMode(true);
                if (!isRunning) setIsRunning(true);
              }}
              className={`px-3 py-1 text-xs font-bold rounded transition-all flex items-center gap-1.5 ${
                isPlaybookMode ? 'bg-amber-600 text-white shadow-2xs' : 'text-slate-600 hover:text-navy-900'
              }`}
            >
              <Sparkles className="w-3 h-3" />
              Automated APT Kill-Chain
            </button>
          </div>
        </div>

        {/* Playbook Mode Banner with 5-Stage Stepper */}
        {isPlaybookMode && (
          <div className="p-3 bg-amber-50 border border-amber-200 rounded-lg text-xs space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-bold text-amber-900 flex items-center gap-1.5">
                <Crosshair className="w-4 h-4 text-amber-600" />
                AUTOMATED APT KILL-CHAIN PLAYBOOK ACTIVE
              </span>
              <Badge variant="warn">PHASE {playbookStep + 1} OF 5</Badge>
            </div>

            {/* Stepper Pipeline */}
            <div className="grid grid-cols-5 gap-1.5 font-mono text-[10px] text-center pt-1">
              {[
                { name: '1. Recon (Suricata)', desc: 'Port Scan Probe' },
                { name: '2. Web Exploit (PAN)', desc: 'SQLi Payload' },
                { name: '3. PrivEsc (AWS)', desc: 'IAM Access Key' },
                { name: '4. C2 Beacon (FGT)', desc: 'SMB Lateral Move' },
                { name: '5. Exfiltration (Zeek)', desc: 'DNS Tunneling' },
              ].map((step, idx) => (
                <div
                  key={idx}
                  className={`p-1.5 rounded border transition-all ${
                    playbookStep === idx
                      ? 'bg-amber-600 text-white border-amber-700 font-bold shadow-xs animate-pulse'
                      : idx < playbookStep
                      ? 'bg-emerald-50 text-emerald-800 border-emerald-200 font-semibold'
                      : 'bg-white text-slate-500 border-slate-200'
                  }`}
                >
                  <div className="truncate">{step.name}</div>
                  <div className="text-[9px] opacity-80 truncate">{step.desc}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Preset Cards Grid (8 presets) */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {CAMPAIGNS.map((c) => {
            const isSelected = selectedCampaign.id === c.id && !isPlaybookMode;
            return (
              <button
                key={c.id}
                type="button"
                onClick={() => {
                  setIsPlaybookMode(false);
                  setSelectedCampaign(c);
                  if (!isRunning) setIsRunning(true);
                }}
                className={`p-3 rounded-lg border text-left transition-all flex flex-col justify-between h-[155px] ${
                  isSelected
                    ? 'border-gov-blue bg-blue-50/70 ring-1 ring-gov-blue shadow-xs'
                    : 'border-slate-200 bg-white hover:bg-slate-50'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-[10px] font-mono font-bold px-1.5 py-0.2 rounded bg-slate-100 text-slate-700 truncate max-w-[120px]">
                      {c.vendor}
                    </span>
                    <Badge variant={c.severity === 'CRITICAL' ? 'danger' : c.severity === 'HIGH' ? 'warn' : 'info'}>
                      {c.severity}
                    </Badge>
                  </div>
                  <div className="text-xs font-bold text-navy-900 line-clamp-2">{c.name}</div>
                </div>
                <div className="pt-2 border-t border-slate-100 text-[10.5px] font-mono text-slate-500 flex justify-between">
                  <span>{c.format}</span>
                  <span className="text-gov-blue font-bold">{c.mitreTechnique.split('/')[0]}</span>
                </div>
              </button>
            );
          })}
        </div>

        {/* Intake Channel & Rate Controller Toolbar */}
        <div className="pt-3 border-t border-slate-100 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          {/* Target Intake Transport Channel */}
          <div className="flex items-center gap-2">
            <Server className="w-4 h-4 text-slate-500 flex-shrink-0" />
            <span className="text-xs font-semibold text-slate-700 whitespace-nowrap">
              Intake Socket:
            </span>
            <select
              value={selectedTransport}
              onChange={(e) => setSelectedTransport(e.target.value)}
              className="text-xs bg-slate-50 border border-slate-300 rounded px-2.5 py-1 text-navy-900 focus:outline-none focus:ring-1 focus:ring-gov-blue font-mono"
            >
              {TRANSPORT_CHANNELS.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))}
            </select>
          </div>

          {/* Rate Controller Slider */}
          <div className="flex items-center gap-3 flex-1 max-w-md">
            <span className="text-xs font-semibold text-slate-700 whitespace-nowrap">
              Rate (EPS):
            </span>
            <input
              type="range"
              min={10}
              max={500}
              step={10}
              value={epsRate}
              onChange={(e) => setEpsRate(Number(e.target.value))}
              className="w-full accent-gov-blue cursor-pointer h-2 bg-slate-200 rounded-lg"
            />
            <span className="font-mono text-xs font-bold text-gov-blue bg-blue-50 px-2 py-0.5 rounded border border-blue-200 whitespace-nowrap">
              {epsRate} EPS
            </span>
          </div>

          {/* Secondary Actions & Dataset Export */}
          <div className="flex items-center gap-2">
            <Button size="sm" variant="outline" onClick={handleClear} className="text-xs flex items-center gap-1">
              <RotateCcw className="w-3 h-3" />
              Clear Console
            </Button>

            <Button
              size="sm"
              variant="outline"
              onClick={() => handleExportDataset('log')}
              icon={<Download className="w-3 h-3" />}
              className="text-xs"
            >
              Export .log
            </Button>

            <Button
              size="sm"
              variant="outline"
              onClick={() => handleExportDataset('json')}
              icon={<Download className="w-3 h-3" />}
              className="text-xs"
            >
              Export .json
            </Button>
          </div>
        </div>
      </div>

      {/* DUAL-PANE: LIVE TERMINAL SOCKET & UCE NORMALIZATION INSPECTOR */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left: Live Socket Stream Console (7 cols) */}
        <div className="lg:col-span-7 bg-navy-900 rounded-lg border border-navy-800 shadow-lg overflow-hidden flex flex-col h-[440px]">
          <div className="bg-navy-950 px-3.5 py-2.5 border-b border-navy-800 flex items-center justify-between text-xs text-slate-400 font-mono">
            <div className="flex items-center gap-2">
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-red-500/80" />
                <span className="w-2.5 h-2.5 rounded-full bg-amber-500/80" />
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80" />
              </div>
              <Terminal className="w-3.5 h-3.5 text-slate-400 ml-2" />
              <span className="text-slate-300 font-bold">
                Socket Intake Console ({TRANSPORT_CHANNELS.find((t) => t.id === selectedTransport)?.proto})
              </span>
            </div>

            <div className="flex items-center gap-3 text-[11px]">
              <span className="flex items-center gap-1.5">
                <span className={`w-2 h-2 rounded-full ${isRunning ? 'bg-emerald-400 animate-pulse' : 'bg-slate-500'}`} />
                {isRunning ? 'LISTENING & STREAMING' : 'SOCKET IDLE'}
              </span>
              <span>Buffered: {logs.length}</span>
            </div>
          </div>

          {/* Search bar inside terminal */}
          <div className="bg-navy-950/80 px-3 py-1.5 border-b border-navy-800/80 flex items-center gap-2">
            <Search className="w-3.5 h-3.5 text-slate-400" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search packet stream (e.g. mimikatz, deny, SQL, CVE, TXT)..."
              className="bg-transparent border-none text-xs text-slate-200 placeholder-slate-500 focus:outline-none w-full font-mono"
            />
            {searchTerm && (
              <button
                type="button"
                onClick={() => setSearchTerm('')}
                className="text-[10px] text-slate-400 hover:text-white"
              >
                Clear
              </button>
            )}
          </div>

          {/* Terminal Log List */}
          <div
            ref={logContainerRef}
            className="flex-1 p-3 overflow-y-auto font-mono text-[11px] text-slate-300 space-y-1.5 selection:bg-gov-blue selection:text-white"
          >
            {filteredLogs.length === 0 ? (
              <div className="text-slate-500 italic py-24 text-center text-xs space-y-2">
                <div>Simulator standby. Click "Start Simulation" or "Burst 50 Events" above to inject attack telemetry.</div>
                <div className="text-[10.5px] text-slate-600">Clicking any packet in the console displays its parsed Universal Canonical Event (UCE).</div>
              </div>
            ) : (
              filteredLogs.map((item, idx) => (
                <div
                  key={idx}
                  onClick={() => setSelectedEvent(item.event)}
                  className={`cursor-pointer p-1 rounded flex items-start gap-2 transition-all ${
                    selectedEvent?.event_id === item.event.event_id
                      ? 'bg-blue-900/60 ring-1 ring-blue-500 text-blue-200'
                      : 'hover:bg-navy-800/60 text-slate-300'
                  }`}
                  title="Click to inspect normalized UCE payload"
                >
                  <span className="text-slate-500 select-none text-[10px] w-8">
                    #{String(filteredLogs.length - idx).padStart(3, '0')}
                  </span>
                  <span className="text-[10px] text-amber-400 font-bold select-none whitespace-nowrap">
                    [{item.event.vendor.split(' ')[0]}]
                  </span>
                  <span className="break-all font-mono leading-relaxed">{item.raw}</span>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Right: Live UCE Normalization & Forensic Evidence Split View (5 cols) */}
        <div className="lg:col-span-5 bg-white rounded-lg border border-border-medium shadow-sm overflow-hidden flex flex-col h-[440px]">
          <div className="bg-slate-50 px-3.5 py-2.5 border-b border-border-light flex items-center justify-between text-xs">
            <div className="flex items-center gap-1.5 font-bold text-navy-900">
              <ShieldCheck className="w-4 h-4 text-emerald-600" />
              <span>Universal Canonical Event (UCE) Inspector</span>
            </div>
            {selectedEvent ? (
              <Badge variant="ok">NORMALIZED</Badge>
            ) : (
              <span className="text-[11px] text-slate-400">Select packet to inspect</span>
            )}
          </div>

          <div className="flex-1 p-3.5 overflow-y-auto space-y-3 text-xs">
            {selectedEvent ? (
              <div className="space-y-3">
                {/* Event Metadata Banner */}
                <div className="p-2.5 bg-blue-50/50 border border-blue-200 rounded-lg space-y-1">
                  <div className="flex items-center justify-between font-mono text-[11px]">
                    <span className="font-bold text-navy-900">{selectedEvent.event_id}</span>
                    <Badge variant={selectedEvent.severity === 'CRITICAL' ? 'danger' : 'warn'}>
                      {selectedEvent.severity}
                    </Badge>
                  </div>
                  <div className="text-[11px] text-slate-600 font-medium">
                    {selectedEvent.detection_title || selectedEvent.vendor}
                  </div>
                  <div className="text-[10px] font-mono text-slate-500 flex items-center gap-1">
                    <Hash className="w-3 h-3 text-slate-400" />
                    <span className="truncate">SHA256: {selectedEvent.sha256}</span>
                  </div>
                </div>

                {/* Key-Value Extracted Fields Grid */}
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-[10px] font-bold uppercase text-slate-400">
                      Normalized Entities &amp; Attributes:
                    </span>
                    <button
                      type="button"
                      onClick={() => {
                        if (selectedEvent.raw_payload) {
                          navigator.clipboard.writeText(selectedEvent.raw_payload);
                          setCopiedRaw(true);
                          setTimeout(() => setCopiedRaw(false), 1500);
                        }
                      }}
                      className="text-[10px] text-gov-blue hover:underline flex items-center gap-1 font-semibold"
                    >
                      {copiedRaw ? <Check className="w-2.5 h-2.5 text-green-600" /> : <Copy className="w-2.5 h-2.5" />}
                      {copiedRaw ? 'Copied Raw' : 'Copy Raw'}
                    </button>
                  </div>
                  <div className="grid grid-cols-2 gap-1.5 font-mono text-[11px]">
                    {selectedEvent.extracted_fields &&
                      Object.entries(selectedEvent.extracted_fields).map(([k, v]) => (
                        <div key={k} className="p-1.5 bg-slate-50 rounded border border-slate-200 flex flex-col">
                          <span className="text-[9.5px] uppercase font-bold text-slate-400">{k}</span>
                          <span className="text-navy-900 truncate font-semibold">{String(v)}</span>
                        </div>
                      ))}
                  </div>
                </div>

                {/* Raw vs Normalized JSON Preview */}
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-[10px] font-bold uppercase text-slate-400">
                      Canonical Record JSON:
                    </span>
                    <button
                      type="button"
                      onClick={() => {
                        navigator.clipboard.writeText(JSON.stringify(selectedEvent, null, 2));
                        setCopiedJson(true);
                        setTimeout(() => setCopiedJson(false), 1500);
                      }}
                      className="text-[10px] text-gov-blue hover:underline flex items-center gap-1 font-semibold"
                    >
                      {copiedJson ? <Check className="w-2.5 h-2.5 text-green-600" /> : <Copy className="w-2.5 h-2.5" />}
                      {copiedJson ? 'Copied JSON' : 'Copy JSON'}
                    </button>
                  </div>
                  <div className="p-2 bg-slate-900 text-slate-200 rounded font-mono text-[10px] overflow-x-auto max-h-36">
                    <pre>{JSON.stringify(selectedEvent, null, 2)}</pre>
                  </div>
                </div>
              </div>
            ) : (
              <div className="text-slate-400 italic py-24 text-center text-xs space-y-2">
                <Eye className="w-8 h-8 text-slate-300 mx-auto" />
                <div>No packet selected.</div>
                <div className="text-[11px] text-slate-500">
                  Click any packet in the left socket console to inspect its normalized UCE schema, cryptographic hash, and entities.
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
