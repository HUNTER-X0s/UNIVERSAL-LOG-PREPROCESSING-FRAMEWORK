import { ParserEntry } from '../types/parsers';

export const PARSERS_DATA: ParserEntry[] = [
  // ==========================================
  // Tier A: 10 Core Generic & SIEM Standard Parsers
  // ==========================================
  {
    id: 'parser.generic.json',
    name: 'Generic JSON Parser',
    vendor: 'Universal / RFC 8259',
    tier: 'Tier A',
    category: 'Generic & Standards',
    format: 'json',
    status: 'VERIFIED',
    testsPassed: '38/38',
    throughputEps: 58400,
    p99LatencyMs: 0.5,
    residuePreserved: true,
    sampleLog: '{"src_ip": "10.0.0.1", "dst_port": 443, "action": "allow", "proto": "TCP", "bytes": 1024, "msg": "TLS Session Established"}',
    ocsfClass: 'Network Activity',
    ocsfClassId: 4001,
    redosSafety: 'O(N) Linear Time Guaranteed • Recursive-Descent Bounded Parser',
    supportedFormats: ['json', 'rfc8259'],
    supportedVendors: ['Generic', 'Universal', 'Multi-Vendor'],
    description: 'High-throughput deterministic JSON parser with depth-bounded nesting (max depth 32) and key count limits to prevent algorithmic complexity DoS.',
    targetFields: ['src_endpoint.ip', 'dst_endpoint.port', 'action', 'connection_info.protocol_name', 'traffic.bytes'],
    mappedFieldsCount: 6,
    internetSamples: [
      {
        label: 'API Gateway Flow (Compact)',
        payload: '{"src_ip": "10.0.0.1", "dst_port": 443, "action": "allow", "proto": "TCP", "bytes": 1024, "msg": "TLS Session Established"}',
        description: 'High-frequency telemetry stream from ingress API gateway.'
      },
      {
        label: 'OWASP WAF Threat (Prettified)',
        payload: '{\n  "timestamp": "2026-09-29T12:00:00Z",\n  "event_type": "waf_inspection",\n  "client_ip": "198.51.100.45",\n  "dst_port": 443,\n  "action": "deny",\n  "rule_id": "OWASP-CRS-942100",\n  "severity": "CRITICAL",\n  "http_method": "POST",\n  "uri": "/api/v1/auth/login",\n  "user_agent": "sqlmap/1.7.2#stable",\n  "bytes": 2048,\n  "msg": "SQL injection attempt blocked by core rule set"\n}',
        description: 'Formatted multi-line incident telemetry from edge web application firewall.'
      },
      {
        label: 'Kubernetes Audit (RFC 8259)',
        payload: '{\n  "kind": "Event",\n  "apiVersion": "audit.k8s.io/v1",\n  "level": "Metadata",\n  "auditID": "4f9b2b3a-87ef-4e20-91a5-812e95a0e10b",\n  "stage": "ResponseComplete",\n  "requestURI": "/api/v1/namespaces/kube-system/secrets",\n  "verb": "get",\n  "user": "system:serviceaccount:kube-system:generic-controller",\n  "sourceIPs": "10.244.0.1",\n  "status_code": 200,\n  "action": "allow"\n}',
        description: 'Control plane Kubernetes API server cluster audit log.'
      }
    ]
  },
  {
    id: 'parser.generic.ndjson',
    name: 'Newline-Delimited JSON (NDJSON)',
    vendor: 'Universal / Cloud Native',
    tier: 'Tier A',
    category: 'Generic & Standards',
    format: 'ndjson',
    status: 'VERIFIED',
    testsPassed: '32/32',
    throughputEps: 64200,
    p99LatencyMs: 0.4,
    residuePreserved: true,
    sampleLog: '{"timestamp": "2026-09-29T03:00:00Z", "level": "INFO", "service": "auth-gateway", "event": "user_authenticated", "user_id": "usr-8921", "client_ip": "192.168.1.105"}',
    ocsfClass: 'Authentication',
    ocsfClassId: 3001,
    redosSafety: 'O(N) Linear Time Guaranteed • Streaming Zero-Copy Framer',
    supportedFormats: ['ndjson', 'json_lines'],
    supportedVendors: ['Generic', 'Kubernetes', 'Docker', 'Vector'],
    description: 'Streaming line-by-line JSON record framer and parser optimized for Kubernetes stdout, vector sinks, and cloud-native ingestion streams.',
    targetFields: ['time', 'severity', 'metadata.product.feature.name', 'activity_name', 'actor.user.uid', 'src_endpoint.ip'],
    mappedFieldsCount: 6,
    internetSamples: [
      {
        label: 'K8s Container Auth stdout',
        payload: '{"timestamp": "2026-09-29T03:00:00Z", "level": "INFO", "service": "auth-gateway", "event": "user_authenticated", "user_id": "usr-8921", "client_ip": "192.168.1.105"}',
        description: 'Ingress authentication stdout stream from cloud native pods.'
      },
      {
        label: 'Vector Ingress Flow Event',
        payload: '{"timestamp": "2026-09-29T03:00:05Z", "host": "k8s-node-04", "stream": "stderr", "app": "payment-api", "error_code": "ERR_INVALID_HMAC", "client_ip": "203.0.113.88", "action": "drop"}',
        description: 'Vector high-throughput log aggregator stream event.'
      },
      {
        label: 'Docker Daemon Log Line',
        payload: '{"time":"2026-09-29T03:00:10.123456Z","level":"warning","msg":"Container network bridge ingress dropped unknown frame","container_id":"c7a91f82b04c","veth":"veth89a12c"}',
        description: 'Docker container network bridge warning log.'
      }
    ]
  },
  {
    id: 'parser.generic.csv',
    name: 'Generic Delimited CSV / TSV',
    vendor: 'Universal / RFC 4180',
    tier: 'Tier A',
    category: 'Generic & Standards',
    format: 'csv',
    status: 'VERIFIED',
    testsPassed: '34/34',
    throughputEps: 72100,
    p99LatencyMs: 0.3,
    residuePreserved: true,
    sampleLog: 'timestamp,src_ip,dst_ip,dst_port,protocol,action\n2026-09-29T03:00:00Z,192.168.1.100,10.0.0.1,443,TCP,ALLOW',
    ocsfClass: 'Network Activity',
    ocsfClassId: 4001,
    redosSafety: 'O(N) Linear Time Guaranteed • RFC 4180 State Machine',
    supportedFormats: ['csv', 'tsv', 'psv'],
    supportedVendors: ['Generic', 'Relational', 'Data Warehouse'],
    description: 'RFC 4180 compliant delimited record engine with automatic delimiter sniffing (comma, tab, pipe, semicolon) and sanitized column headers.',
    targetFields: ['time', 'src_endpoint.ip', 'dst_endpoint.ip', 'dst_endpoint.port', 'connection_info.protocol_name', 'action'],
    mappedFieldsCount: 6,
    internetSamples: [
      {
        label: 'Standard Firewall Flow CSV',
        payload: 'timestamp,src_ip,dst_ip,dst_port,protocol,action\n2026-09-29T03:00:00Z,192.168.1.100,10.0.0.1,443,TCP,ALLOW',
        description: 'Comma-separated perimeter network flow session records.'
      },
      {
        label: 'Tab-Separated TSV Audit Stream',
        payload: 'user\taction\tresult\tsrc_ip\tduration_ms\nadmin\tauth_token_grant\tsuccess\t198.51.100.22\t14.2',
        description: 'Tab-delimited IAM and session token grant records.'
      },
      {
        label: 'Pipe-Delimited Proxy Export',
        payload: 'host|service|status|active_connections|load_avg\nedge-proxy-01|envoy|running|14890|0.84',
        description: 'Pipe-separated load balancer infrastructure metrics export.'
      }
    ]
  },
  {
    id: 'parser.generic.keyvalue',
    name: 'Key-Value (logfmt / KV)',
    vendor: 'Universal / POSIX',
    tier: 'Tier A',
    category: 'Generic & Standards',
    format: 'key_value',
    status: 'VERIFIED',
    testsPassed: '36/36',
    throughputEps: 56900,
    p99LatencyMs: 0.5,
    residuePreserved: true,
    sampleLog: 'time="2026-09-29T03:00:00Z" level=warn msg="Failed login attempt" user=sec-admin src_ip=198.51.100.42 reason="invalid_token"',
    ocsfClass: 'Authentication',
    ocsfClassId: 3001,
    redosSafety: 'O(N) Linear Time Guaranteed • Zero-Backtracking Tokenizer',
    supportedFormats: ['key_value', 'logfmt', 'kv'],
    supportedVendors: ['Generic', 'Splunk', 'Grafana Loki', 'Heroku'],
    description: 'POSIX logfmt tokenizer handling bare and double-quoted values, escaped characters, message prefixes, and duplicate key deduplication.',
    targetFields: ['time', 'severity', 'message', 'actor.user.name', 'src_endpoint.ip', 'status_detail'],
    mappedFieldsCount: 6,
    internetSamples: [
      {
        label: 'Logfmt Security Warning',
        payload: 'time="2026-09-29T03:00:00Z" level=warn msg="Failed login attempt" user=sec-admin src_ip=198.51.100.42 reason="invalid_token"',
        description: 'Standard logfmt security authentication event.'
      },
      {
        label: 'Perimeter Appliance Drop',
        payload: 'action=deny src=198.51.100.99 dst=10.0.1.10 sport=51234 dport=22 proto=tcp devname="EDGE-GW" policy_id=14',
        description: 'Bare key-value network boundary drop log.'
      },
      {
        label: 'Heroku Router Metrics',
        payload: 'at=info method=POST path="/api/v1/auth/session" host=api.cloud.corp request_id=req_8921fa9 status=401 service=18ms bytes=284',
        description: 'PaaS web application HTTP router logfmt telemetry.'
      }
    ]
  },
  {
    id: 'parser.syslog.rfc3164',
    name: 'BSD Syslog (RFC 3164)',
    vendor: 'IETF / BSD Standard',
    tier: 'Tier A',
    category: 'Generic & Standards',
    format: 'syslog_rfc3164',
    status: 'VERIFIED',
    testsPassed: '30/30',
    throughputEps: 68500,
    p99LatencyMs: 0.4,
    residuePreserved: true,
    sampleLog: "<34>Oct 11 22:14:15 edge-router-01 su[4821]: 'su root' failed for sec-analyst on /dev/pts/8",
    ocsfClass: 'System Activity',
    ocsfClassId: 1001,
    redosSafety: 'O(N) Linear Time Guaranteed • Non-Capturing Positional Scan',
    supportedFormats: ['syslog_rfc3164', 'rfc3164'],
    supportedVendors: ['Generic', 'Linux', 'BSD', 'Cisco', 'Juniper'],
    description: 'Classic BSD Syslog parser with PRI priority facility and severity mathematical decomposition, hostname extraction, tag/process PID parsing.',
    targetFields: ['device.hostname', 'process.name', 'process.pid', 'message', 'severity_id', 'facility_id'],
    mappedFieldsCount: 7,
    internetSamples: [
      {
        label: 'Linux PAM Su Failure',
        payload: "<34>Oct 11 22:14:15 edge-router-01 su[4821]: 'su root' failed for sec-analyst on /dev/pts/8",
        description: 'Standard BSD Syslog priority 34 with authentication error.'
      },
      {
        label: 'OpenSSH Auth Failure',
        payload: '<85>Sep 29 03:00:00 bastion sshd[28491]: Failed password for invalid user root from 203.0.113.88 port 48219 ssh2',
        description: 'Remote SSH brute-force attempt captured via BSD syslog.'
      },
      {
        label: 'Kernel Netfilter Drop',
        payload: '<4>Sep 29 03:00:05 srv-db-01 kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:15:5d:01:ca:02 SRC=198.51.100.55 DST=10.0.2.15 LEN=60 PROTO=TCP SPT=49152 DPT=3306',
        description: 'Linux kernel iptables firewall drop notification.'
      }
    ]
  },
  {
    id: 'parser.syslog.rfc5424',
    name: 'IETF Syslog (RFC 5424)',
    vendor: 'IETF Standard',
    tier: 'Tier A',
    category: 'Generic & Standards',
    format: 'syslog_rfc5424',
    status: 'VERIFIED',
    testsPassed: '35/35',
    throughputEps: 63800,
    p99LatencyMs: 0.4,
    residuePreserved: true,
    sampleLog: '<165>1 2026-09-29T03:00:00.003Z sec-host.corp app 8710 ID47 [exampleSDID@32473 eventSource="SecurityEngine" eventID="1011" severity="HIGH"] Threat mitigation triggered',
    ocsfClass: 'Security Finding',
    ocsfClassId: 2001,
    redosSafety: 'O(N) Linear Time Guaranteed • RFC 5424 ABNF Grammar',
    supportedFormats: ['syslog_rfc5424', 'rfc5424'],
    supportedVendors: ['Generic', 'Enterprise Unix', 'Network Appliances'],
    description: 'Strict IETF RFC 5424 parser supporting version headers, ISO-8601 high-resolution timestamps, structured data elements (SD-ID/SD-PARAM), and NIL exclusions.',
    targetFields: ['device.hostname', 'process.name', 'process.pid', 'message_id', 'unmapped.structured_data', 'message'],
    mappedFieldsCount: 9,
    internetSamples: [
      {
        label: 'RFC 5424 Structured Finding',
        payload: '<165>1 2026-09-29T03:00:00.003Z sec-host.corp app 8710 ID47 [exampleSDID@32473 eventSource="SecurityEngine" eventID="1011" severity="HIGH"] Threat mitigation triggered',
        description: 'Structured Data with enterprise security parameters and high-res timestamp.'
      },
      {
        label: 'Auditd RFC 5424 Forward',
        payload: '<134>1 2026-09-29T03:00:02Z core-api.internal auditd 1492 ID88 [origin ip="10.0.0.5" sw="auditd" swVersion="3.0.7"] SYSCALL=execve exe="/bin/busybox" success=no',
        description: 'Forwarded audit event with custom origin structured data element.'
      },
      {
        label: 'Switch Interface State Change',
        payload: '<189>1 2026-09-29T03:00:15.892Z tor-sw-01 os-switch - MSG-001 [device vendor="Arista" model="7050SX"] Interface Ethernet1/1 state transitioned to DOWN',
        description: 'Network operating system structured telemetry message.'
      }
    ]
  },
  {
    id: 'parser.generic.cef',
    name: 'Common Event Format (CEF)',
    vendor: 'ArcSight / Micro Focus',
    tier: 'Tier A',
    category: 'Generic & Standards',
    format: 'cef',
    status: 'VERIFIED',
    testsPassed: '40/40',
    throughputEps: 52400,
    p99LatencyMs: 0.6,
    residuePreserved: true,
    sampleLog: 'CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232 dpt=443 act=block',
    ocsfClass: 'Security Finding',
    ocsfClassId: 2001,
    redosSafety: 'O(N) Linear Time Guaranteed • Pipe Delimiter State Automaton',
    supportedFormats: ['cef'],
    supportedVendors: ['ArcSight', 'Micro Focus', 'CyberArk', 'Check Point', 'Imperva'],
    description: 'Industry standard ArcSight CEF parser with pipe-delimited 7-tuple header validation, syslog prefix stripping, and typed extension key-value extraction.',
    targetFields: ['metadata.version', 'device.vendor', 'device.product', 'finding_info.title', 'severity', 'src_endpoint.ip', 'dst_endpoint.ip', 'action'],
    mappedFieldsCount: 8,
    internetSamples: [
      {
        label: 'ArcSight Worm Block',
        payload: 'CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232 dpt=443 act=block',
        description: 'Standard ArcSight 7-tuple header with typed extensions.'
      },
      {
        label: 'CyberArk Vault Logon Failure',
        payload: 'CEF:0|CyberArk|Vault|12.2|101|Logon Failed|5|suser=operator msg=Invalid credentials from client src=198.51.100.77 act=LogonFail',
        description: 'Privileged Access Management security authentication event.'
      },
      {
        label: 'Check Point Firewall Drop',
        payload: 'CEF:0|Check Point|VPN-1 & FireWall-1|Check Point|drop|Drop|Low|act=drop src=203.0.113.99 dst=10.0.0.1 proto=tcp spt=54123 dpt=8080',
        description: 'Perimeter firewall access policy rejection.'
      }
    ]
  },
  {
    id: 'parser.generic.leef',
    name: 'Log Event Extended Format (LEEF)',
    vendor: 'IBM Security / QRadar',
    tier: 'Tier A',
    category: 'Generic & Standards',
    format: 'leef',
    status: 'VERIFIED',
    testsPassed: '34/34',
    throughputEps: 55100,
    p99LatencyMs: 0.5,
    residuePreserved: true,
    sampleLog: 'LEEF:1.0|Microsoft|MSExchange|2013|AuthSuccess|src=192.168.1.1\tdst=10.0.0.2\tusr=admin\tstatus=ALLOW',
    ocsfClass: 'Authentication',
    ocsfClassId: 3001,
    redosSafety: 'O(N) Linear Time Guaranteed • Custom Delimiter Engine',
    supportedFormats: ['leef'],
    supportedVendors: ['IBM', 'QRadar', 'Microsoft', 'Trend Micro'],
    description: 'IBM QRadar LEEF 1.0 and 2.0 parser with dynamic delimiter negotiation (tab, caret, pipe), 5-tuple header extraction, and normalized event mappings.',
    targetFields: ['metadata.version', 'device.vendor', 'device.product', 'activity_name', 'src_endpoint.ip', 'dst_endpoint.ip', 'actor.user.name', 'status'],
    mappedFieldsCount: 8,
    internetSamples: [
      {
        label: 'LEEF 1.0 Auth Success',
        payload: 'LEEF:1.0|Microsoft|MSExchange|2013|AuthSuccess|src=192.168.1.1\tdst=10.0.0.2\tusr=admin\tstatus=ALLOW',
        description: 'IBM QRadar standard tab-delimited enterprise authentication.'
      },
      {
        label: 'LEEF 2.0 Caret Delimited',
        payload: 'LEEF:2.0|Trend Micro|Deep Security|20.0|4000000|^|src=198.51.100.50^dst=10.0.1.25^act=block^msg=Malicious payload quarantined',
        description: 'LEEF 2.0 with dynamic custom delimiter negotiation.'
      },
      {
        label: 'QRadar Netfilter Telemetry',
        payload: 'LEEF:1.0|Linux|Iptables|2.6|1000|src=203.0.113.12\tdst=10.0.0.5\tproto=TCP\tspt=49152\tdpt=22\tact=DENY',
        description: 'Endpoint network packet denial captured for SIEM.'
      }
    ]
  },
  {
    id: 'parser.generic.w3c',
    name: 'W3C Extended Log Format',
    vendor: 'W3C / IIS / CloudFront',
    tier: 'Tier A',
    category: 'Generic & Standards',
    format: 'w3c',
    status: 'VERIFIED',
    testsPassed: '30/30',
    throughputEps: 66300,
    p99LatencyMs: 0.4,
    residuePreserved: true,
    sampleLog: '#Fields: date time c-ip cs-method cs-uri-stem sc-status\n2023-01-01 12:00:00 192.168.1.5 GET /index.html 200',
    ocsfClass: 'HTTP Activity',
    ocsfClassId: 4002,
    redosSafety: 'O(N) Linear Time Guaranteed • Directive Header Tracking',
    supportedFormats: ['w3c'],
    supportedVendors: ['W3C', 'Microsoft IIS', 'AWS CloudFront', 'Squid Proxy'],
    description: 'W3C Extended Log format parser with dynamic #Fields directive tracking, prefix handling (c-, s-, cs-, sc-), and HTTP response status normalization.',
    targetFields: ['time', 'src_endpoint.ip', 'http_request.method', 'http_request.url.path', 'http_response.status_code'],
    mappedFieldsCount: 5,
    internetSamples: [
      {
        label: 'W3C Extended GET Request',
        payload: '#Fields: date time c-ip cs-method cs-uri-stem sc-status\n2023-01-01 12:00:00 192.168.1.5 GET /index.html 200',
        description: 'Standard W3C HTTP transaction with directive line.'
      },
      {
        label: 'IIS 10.0 API Ingress Line',
        payload: '#Fields: date time c-ip cs-method cs-uri-stem sc-status sc-bytes time-taken\n2026-09-29 03:00:00 198.51.100.22 POST /api/v1/auth/token 401 512 18',
        description: 'Microsoft IIS web server authentication token probe.'
      },
      {
        label: 'CloudFront Proxy Request',
        payload: '#Fields: date time c-ip cs-method cs-uri-stem sc-status\n2026-09-29 03:00:05 10.0.1.45 CONNECT internal-vault.corp:443 200',
        description: 'Proxy tunnel transaction log with upstream response code.'
      }
    ]
  },
  {
    id: 'parser.generic.xml',
    name: 'Structured XML Event Parser',
    vendor: 'W3C / Windows EventLog',
    tier: 'Tier A',
    category: 'Generic & Standards',
    format: 'xml',
    status: 'VERIFIED',
    testsPassed: '36/36',
    throughputEps: 39800,
    p99LatencyMs: 1.1,
    residuePreserved: true,
    sampleLog: '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4624</EventID><Channel>Security</Channel></System></Event>',
    ocsfClass: 'System Activity',
    ocsfClassId: 1001,
    redosSafety: 'O(N) Linear Time Guaranteed • XXE Entity Expansion Shield Active',
    supportedFormats: ['xml'],
    supportedVendors: ['Generic', 'Microsoft Windows', 'IBM', 'Oracle'],
    description: 'Hardened XML DOM parser with defused entity expansion, Billion Laughs DoS protection, DTD system entity disabling, and nested XPath-to-key normalization.',
    targetFields: ['metadata.product.name', 'activity_id', 'unmapped.channel'],
    mappedFieldsCount: 4,
    internetSamples: [
      {
        label: 'Windows Event 4624 (Logon)',
        payload: '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4624</EventID><Channel>Security</Channel></System></Event>',
        description: 'Windows Security Event Log successful authentication.'
      },
      {
        label: 'Windows Event 4625 (Failed Logon)',
        payload: '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4625</EventID><Channel>Security</Channel></System><EventData><Data Name="TargetUserName">sec-admin</Data><Data Name="IpAddress">192.168.1.50</Data></EventData></Event>',
        description: 'Failed logon attempt containing IP and target username.'
      },
      {
        label: 'Sysmon Process Create (Event 1)',
        payload: '<Event><System><EventID>1</EventID><Provider Name="Microsoft-Windows-Sysmon"/></System><EventData><Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data><Data Name="CommandLine">cmd.exe /c whoami</Data></EventData></Event>',
        description: 'Sysinternals Sysmon process launch telemetry.'
      }
    ]
  },

  // ==========================================
  // Tier B: 8 Specialized Perimeter & Security Telemetry Parsers
  // ==========================================
  {
    id: 'parser.paloalto.panos',
    name: 'Palo Alto PAN-OS CSV',
    vendor: 'Palo Alto Networks',
    tier: 'Tier B',
    category: 'Network Firewall',
    format: 'panos_csv',
    status: 'VERIFIED',
    testsPassed: '44/44',
    throughputEps: 45200,
    p99LatencyMs: 0.8,
    residuePreserved: true,
    sampleLog: '1,2026/09/10 14:40:00,001801000000,TRAFFIC,drop,1,2026/09/10 14:40:00,10.0.1.5,198.51.100.22,0.0.0.0,0.0.0.0,RULE-THREAT,test-user,,dns,vsys1,trust,untrust',
    ocsfClass: 'Network Activity',
    ocsfClassId: 4001,
    redosSafety: 'O(N) Linear Time Guaranteed • PAN-OS 9.x/10.x/11.x Schema Positional Parser',
    supportedFormats: ['panos_csv', 'csv'],
    supportedVendors: ['Palo Alto Networks', 'PaloAlto', 'PAN-OS'],
    description: 'Enterprise NGFW traffic and threat log parser with support for PAN-OS versions 8.x through 11.x, NAT address mapping, and threat categorization.',
    targetFields: ['src_endpoint.ip', 'dst_endpoint.ip', 'action', 'connection_info.protocol_name', 'rule.name', 'actor.user.name', 'traffic.bytes'],
    mappedFieldsCount: 15,
    internetSamples: [
      {
        label: 'PAN-OS Standard Traffic Drop',
        payload: '1,2026/09/10 14:40:00,001801000000,TRAFFIC,drop,1,2026/09/10 14:40:00,10.0.1.5,198.51.100.22,0.0.0.0,0.0.0.0,RULE-THREAT,test-user,,dns,vsys1,trust,untrust',
        description: 'Standard perimeter firewall drop telemetry.'
      },
      {
        label: 'PAN-OS Critical Threat Exploit',
        payload: '1,2026/09/10 14:42:15,001801000000,THREAT,drop,1,2026/09/10 14:42:15,198.51.100.99,10.0.2.15,0.0.0.0,0.0.0.0,RULE-IPS-BLOCK,attacker-c2,(9999),vulnerability,vsys1,untrust,trust,ethernet1/1,ethernet1/2,alert-syslog,2026/09/10 14:42:15,12345,1,51234,80,0,0,0x0,tcp,alert,"HTTP Remote Command Execution Exploit",c2-traffic(30001),any,informational,client-to-server',
        description: 'Real-world exploit attack telemetry captured from external untrusted zone.'
      },
      {
        label: 'PAN-OS GlobalProtect VPN Log',
        payload: '1,2026/09/10 14:45:00,001801000000,GLOBALPROTECT,login,1,2026/09/10 14:45:00,203.0.113.88,10.0.1.5,0.0.0.0,0.0.0.0,GP-GATEWAY,sec-analyst,,ssl,vsys1,untrust,trust',
        description: 'Enterprise remote access VPN session establishment.'
      }
    ]
  },
  {
    id: 'parser.fortinet.fortigate',
    name: 'Fortinet FortiGate UTM',
    vendor: 'Fortinet',
    tier: 'Tier B',
    category: 'Network Firewall',
    format: 'fortigate_kv',
    status: 'VERIFIED',
    testsPassed: '40/40',
    throughputEps: 49500,
    p99LatencyMs: 0.8,
    residuePreserved: true,
    sampleLog: 'date=2026-09-29 time=03:00:00 devname="FGT-CORP-01" devid="FGT60D12345" type="traffic" subtype="forward" level="warning" action="deny" srcip=10.10.10.25 dstip=198.51.100.40 srcport=54210 dstport=445 proto=6',
    ocsfClass: 'Network Activity',
    ocsfClassId: 4001,
    redosSafety: 'O(N) Linear Time Guaranteed • FortiOS Key-Value Tokenizer',
    supportedFormats: ['fortigate_kv', 'key_value'],
    supportedVendors: ['Fortinet', 'FortiGate', 'FortiOS'],
    description: 'High-throughput FortiOS traffic, UTM, IPS, and VPN event parser with custom quote handling and standard security attribute extraction.',
    targetFields: ['device.name', 'device.uid', 'action', 'severity', 'src_endpoint.ip', 'dst_endpoint.ip', 'src_endpoint.port', 'dst_endpoint.port', 'connection_info.protocol_num'],
    mappedFieldsCount: 12,
    internetSamples: [
      {
        label: 'FortiGate Traffic Deny',
        payload: 'date=2026-09-29 time=03:00:00 devname="FGT-CORP-01" devid="FGT60D12345" type="traffic" subtype="forward" level="warning" action="deny" srcip=10.10.10.25 dstip=198.51.100.40 srcport=54210 dstport=445 proto=6',
        description: 'FortiOS forward traffic denial on SMB port.'
      },
      {
        label: 'FortiGate IPS Exploit Signature',
        payload: 'date=2026-09-29 time=03:00:10 devname="FGT-CORP-01" devid="FGT60D12345" type="utm" subtype="ips" level="alert" attack="Apache.Log4j.JNDI.Remote.Code.Execution" action="dropped" srcip=198.51.100.99 dstip=10.10.10.100 attackid=51000',
        description: 'Next-Gen IPS attack detection and drop telemetry.'
      },
      {
        label: 'FortiGate SSL-VPN Tunnel',
        payload: 'date=2026-09-29 time=03:00:20 devname="FGT-CORP-01" devid="FGT60D12345" type="event" subtype="vpn" level="notice" action="tunnel-up" user="sec-admin" remip=203.0.113.44 tunneltype="ssl-tunnel"',
        description: 'SSL-VPN endpoint authentication notification.'
      }
    ]
  },
  {
    id: 'parser.cisco.asa_ios',
    name: 'Cisco ASA & IOS Syslog',
    vendor: 'Cisco Systems',
    tier: 'Tier B',
    category: 'Network Firewall',
    format: 'cisco_syslog',
    status: 'VERIFIED',
    testsPassed: '38/38',
    throughputEps: 46100,
    p99LatencyMs: 0.9,
    residuePreserved: true,
    sampleLog: 'Sep  5 14:00:02 fw %ASA-4-106023: Deny tcp src outside:203.0.113.88/61234 dst inside:10.0.0.1/445 by access-group "OUTSIDE-IN"',
    ocsfClass: 'Network Activity',
    ocsfClassId: 4001,
    redosSafety: 'O(N) Linear Time Guaranteed • Cisco Mnemonic Decomposition Engine',
    supportedFormats: ['cisco_syslog', 'syslog_rfc3164'],
    supportedVendors: ['Cisco', 'Cisco Systems'],
    description: 'Comprehensive Cisco ASA and IOS syslog parser with facility mnemonic extraction (%ASA-X-XXXXXX), interface resolution, and access-list rule mapping.',
    targetFields: ['device.hostname', 'unmapped.cisco_facility', 'severity_id', 'unmapped.cisco_mnemonic', 'action', 'src_endpoint.ip', 'src_endpoint.port', 'dst_endpoint.ip', 'dst_endpoint.port', 'rule.name'],
    mappedFieldsCount: 10,
    internetSamples: [
      {
        label: 'Cisco ASA ACL Deny Rule',
        payload: 'Sep  5 14:00:02 fw %ASA-4-106023: Deny tcp src outside:203.0.113.88/61234 dst inside:10.0.0.1/445 by access-group "OUTSIDE-IN"',
        description: 'Perimeter access-list denial on port 445 (SMB).'
      },
      {
        label: 'Cisco ASA Teardown Connection',
        payload: 'Sep  5 14:00:02 fw %ASA-6-302014: Teardown TCP connection 123456 for outside:203.0.113.88/61234 to inside:10.0.0.1/443 duration 0:00:30 bytes 4521 TCP FINs',
        description: 'Session termination with duration and byte count accounting.'
      },
      {
        label: 'Cisco ASA Built Connection',
        payload: 'Sep  5 14:00:00 fw %ASA-6-302013: Built inbound TCP connection 987654 for outside:198.51.100.50/54321 (198.51.100.50/54321) to inside:10.0.2.15/443 (10.0.2.15/443)',
        description: 'Session initialization and dynamic translation audit.'
      }
    ]
  },
  {
    id: 'parser.suricata.eve',
    name: 'Suricata EVE JSON NIDS/IPS',
    vendor: 'OISF / Suricata',
    tier: 'Tier B',
    category: 'NIDS / IPS',
    format: 'suricata_eve_json',
    status: 'VERIFIED',
    testsPassed: '42/42',
    throughputEps: 58000,
    p99LatencyMs: 0.5,
    residuePreserved: true,
    sampleLog: '{"timestamp":"2026-09-10T14:30:00Z","event_type":"alert","src_ip":"192.168.1.50","src_port":54321,"dest_ip":"10.0.0.1","dest_port":80,"proto":"TCP","alert":{"action":"blocked","gid":1,"signature_id":2010935,"signature":"ET MALWARE Suspicious Request"}}',
    ocsfClass: 'Security Finding',
    ocsfClassId: 2001,
    redosSafety: 'O(N) Linear Time Guaranteed • Fast EVE Schema Demuxer',
    supportedFormats: ['suricata_eve_json', 'json', 'ndjson'],
    supportedVendors: ['Suricata', 'OISF'],
    description: 'Suricata EVE JSON engine extracting alerts, DNS telemetry, HTTP transactions, TLS handshakes, flow metrics, and payload metadata.',
    targetFields: ['time', 'activity_name', 'src_endpoint.ip', 'src_endpoint.port', 'dst_endpoint.ip', 'dst_endpoint.port', 'finding_info.title', 'finding_info.uid', 'action'],
    mappedFieldsCount: 11,
    internetSamples: [
      {
        label: 'Suricata NIDS Threat Alert',
        payload: '{"timestamp":"2026-09-10T14:30:00Z","event_type":"alert","src_ip":"192.168.1.50","src_port":54321,"dest_ip":"10.0.0.1","dest_port":80,"proto":"TCP","alert":{"action":"blocked","gid":1,"signature_id":2010935,"signature":"ET MALWARE Suspicious Request"}}',
        description: 'High-severity signature detection blocked by inline IPS engine.'
      },
      {
        label: 'Suricata Flow Telemetry Event',
        payload: '{"timestamp":"2026-09-10T14:31:05Z","flow_id":1849201948,"event_type":"flow","src_ip":"10.0.1.25","src_port":49152,"dest_ip":"203.0.113.15","dest_port":443,"proto":"TCP","app_proto":"tls","flow":{"pkts_toserver":15,"pkts_toclient":22,"bytes_toserver":2450,"bytes_toclient":18920,"start":"2026-09-10T14:30:00Z","end":"2026-09-10T14:31:05Z","age":65,"state":"closed","reason":"shutdown"}}',
        description: 'Bidirectional network flow state metadata for SOC analytics.'
      },
      {
        label: 'Suricata DNS Transaction',
        payload: '{"timestamp":"2026-09-10T14:33:10Z","event_type":"dns","src_ip":"10.0.1.45","src_port":51234,"dest_ip":"1.1.1.1","dest_port":53,"proto":"UDP","dns":{"type":"query","rrname":"c2-beacon.darknet.ru","rrtype":"A","tx_id":48921}}',
        description: 'DNS query telemetry for threat hunting.'
      }
    ]
  },
  {
    id: 'parser.opnsense.filterlog',
    name: 'OPNsense / pfSense Filterlog',
    vendor: 'OPNsense / Netgate',
    tier: 'Tier B',
    category: 'Network Firewall',
    format: 'opnsense_filterlog',
    status: 'VERIFIED',
    testsPassed: '34/34',
    throughputEps: 48900,
    p99LatencyMs: 0.7,
    residuePreserved: true,
    sampleLog: 'filterlog: 4,16777216,,1000000103,vtnet0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,198.51.100.99,10.0.0.15,51234,445,0,S,12345678,,65535,,',
    ocsfClass: 'Network Activity',
    ocsfClassId: 4001,
    redosSafety: 'O(N) Linear Time Guaranteed • BSD Filterlog Positional Scanner',
    supportedFormats: ['opnsense_filterlog', 'csv'],
    supportedVendors: ['OPNsense', 'pfSense', 'Netgate', 'Deciso'],
    description: 'Positional CSV filterlog parser for OPNsense and pfSense perimeter firewalls with automatic IPv4/IPv6 discriminator and TCP flag decoding.',
    targetFields: ['device.interface.name', 'action', 'connection_info.direction', 'src_endpoint.ip', 'dst_endpoint.ip', 'src_endpoint.port', 'dst_endpoint.port', 'connection_info.protocol_name'],
    mappedFieldsCount: 21,
    internetSamples: [
      {
        label: 'OPNsense Block Inbound TCP',
        payload: 'filterlog: 4,16777216,,1000000103,vtnet0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,198.51.100.99,10.0.0.15,51234,445,0,S,12345678,,65535,,',
        description: 'BSD filterlog CSV format blocking SMB port scan.'
      },
      {
        label: 'pfSense UDP DNS Pass',
        payload: 'filterlog: 4,16777216,,1000000104,em0,match,pass,out,4,0x0,,64,0,0,DF,17,udp,78,192.168.1.105,1.1.1.1,53214,53,58',
        description: 'Outbound DNS query passed by firewall policy.'
      },
      {
        label: 'OPNsense IPv6 SYN Drop',
        payload: 'filterlog: 4,16777216,,1000000105,vtnet0,match,block,in,6,0x00,0x00000,64,6,tcp,40,2001:db8::1,2001:db8::2,49152,22,0,S,98765432,,65535,,',
        description: 'IPv6 perimeter rule rejection on SSH port.'
      }
    ]
  },
  {
    id: 'parser.snort.fast',
    name: 'Snort Fast Alert NIDS',
    vendor: 'Cisco / Sourcefire',
    tier: 'Tier B',
    category: 'NIDS / IPS',
    format: 'snort_fast',
    status: 'VERIFIED',
    testsPassed: '28/28',
    throughputEps: 41200,
    p99LatencyMs: 1.0,
    residuePreserved: true,
    sampleLog: '[**] [1:1000001:1] COMMUNITY WEB-ATTACK /etc/passwd access attempt [**] [Classification: Web Application Attack] [Priority: 1] 09/05-14:00:01.123456 198.51.100.15:49152 -> 10.0.0.10:80 TCP TTL:64 TOS:0x0 ID:12345 IpLen:20 DgmLen:450 [**]',
    ocsfClass: 'Security Finding',
    ocsfClassId: 2001,
    redosSafety: 'O(N) Linear Time Guaranteed • DFA Fast Header Scanner',
    supportedFormats: ['snort_fast'],
    supportedVendors: ['Snort', 'Cisco'],
    description: 'Snort Fast alert format parser extracting Generator ID (GID), Signature ID (SID), signature text, attack classification, priority, and endpoint tuple.',
    targetFields: ['finding_info.title', 'finding_info.uid', 'category_name', 'severity_id', 'time', 'src_endpoint.ip', 'src_endpoint.port', 'dst_endpoint.ip', 'dst_endpoint.port', 'connection_info.protocol_name'],
    mappedFieldsCount: 12,
    internetSamples: [
      {
        label: 'Snort Web Application Attack',
        payload: '[**] [1:1000001:1] COMMUNITY WEB-ATTACK /etc/passwd access attempt [**] [Classification: Web Application Attack] [Priority: 1] 09/05-14:00:01.123456 198.51.100.15:49152 -> 10.0.0.10:80 TCP TTL:64 TOS:0x0 ID:12345 IpLen:20 DgmLen:450 [**]',
        description: 'Priority 1 intrusion alert with IP endpoints and packet header metrics.'
      },
      {
        label: 'Snort Potential VNC Scan',
        payload: '[**] [1:2001219:2] ET SCAN Potential VNC Scan 5900-5920 [**] [Classification: Attempted Information Leak] [Priority: 3] 09/05-14:00:05.654321 203.0.113.77:51234 -> 10.0.0.25:5900 TCP TTL:55 TOS:0x0 ID:54321 IpLen:20 DgmLen:40 [**]',
        description: 'Reconnaissance port scan alert across VNC range.'
      },
      {
        label: 'Snort SSH Brute Force Inbound',
        payload: '[**] [1:2001219:18] ET SCAN Potential SSH Brute Force [**] [Classification: Attempted Admin Privilege] [Priority: 1] 09/05-14:00:10.987654 198.51.100.99:41234 -> 10.0.1.10:22 TCP TTL:64 TOS:0x0 ID:34125 IpLen:20 DgmLen:60 [**]',
        description: 'Targeted admin brute force probe notification.'
      }
    ]
  },
  {
    id: 'parser.web.access',
    name: 'Web Access (NGINX / Apache)',
    vendor: 'NGINX / Apache Foundation',
    tier: 'Tier B',
    category: 'Web & Gateway',
    format: 'combined_access',
    status: 'VERIFIED',
    testsPassed: '34/34',
    throughputEps: 67500,
    p99LatencyMs: 0.4,
    residuePreserved: true,
    sampleLog: '192.168.1.100 - admin [10/Oct/2026:13:55:36 +0000] "GET /api/v1/health HTTP/1.1" 200 1024 "https://example.com" "Mozilla/5.0"',
    ocsfClass: 'HTTP Activity',
    ocsfClassId: 4002,
    redosSafety: 'O(N) Linear Time Guaranteed • Combined Log Format Automaton',
    supportedFormats: ['combined_access', 'clf_access', 'web_access'],
    supportedVendors: ['NGINX', 'Apache', 'Caddy', 'Web'],
    description: 'Comprehensive web server access log engine for Common (CLF) and Combined formats with HTTP request methods, URIs, status codes, referrers, and user agents.',
    targetFields: ['src_endpoint.ip', 'actor.user.name', 'time', 'http_request.method', 'http_request.url.path', 'http_response.status_code', 'http_response.length', 'http_request.referrer', 'http_request.user_agent'],
    mappedFieldsCount: 10,
    internetSamples: [
      {
        label: 'NGINX Combined Health Check (200)',
        payload: '192.168.1.100 - admin [10/Oct/2026:13:55:36 +0000] "GET /api/v1/health HTTP/1.1" 200 1024 "https://example.com" "Mozilla/5.0"',
        description: 'Standard Combined Access Log Format with authenticated user.'
      },
      {
        label: 'Apache 401 Unauthorized Probe',
        payload: '203.0.113.88 - admin [29/Sep/2026:03:00:15 +0000] "POST /admin/login HTTP/1.1" 401 128 "-" "sqlmap/1.7.2#stable"',
        description: 'Automated vulnerability scanner probe targeting administrative portal.'
      },
      {
        label: 'Reverse Proxy 404 Scanner',
        payload: '198.51.100.12 - - [29/Sep/2026:03:00:20 +0000] "GET /phpmyadmin/scripts/setup.php HTTP/1.1" 404 4523 "-" "Nikto/2.1.6"',
        description: 'Directory traversal web scanner probe.'
      }
    ]
  },
  {
    id: 'parser.zeek.telemetry',
    name: 'Zeek (Bro) Connection Logs',
    vendor: 'Zeek Project / Corelight',
    tier: 'Tier B',
    category: 'Network Flow & TSV',
    format: 'zeek_tsv',
    status: 'VERIFIED',
    testsPassed: '38/38',
    throughputEps: 54100,
    p99LatencyMs: 0.7,
    residuePreserved: true,
    sampleLog: '1620000000.123\tC123456\t192.168.1.10\t49152\t10.0.0.1\t443\ttcp\tssl\t12.5\t1024\t8192\tSF\t-\t-\t0\tShADadfF\t10\t1500\t14\t8600\t-',
    ocsfClass: 'Network Activity',
    ocsfClassId: 4001,
    redosSafety: 'O(N) Linear Time Guaranteed • Tab-Separated Zero-Copy Scanner',
    supportedFormats: ['zeek_tsv', 'zeek_json', 'tsv'],
    supportedVendors: ['Zeek', 'Bro', 'Corelight'],
    description: 'Zeek conn.log TSV and JSON telemetry parser mapping connection UIDs, orig/resp IPs and ports, service layer identification, duration, and TCP state flags.',
    targetFields: ['connection_info.uid', 'src_endpoint.ip', 'src_endpoint.port', 'dst_endpoint.ip', 'dst_endpoint.port', 'connection_info.protocol_name', 'service.name', 'traffic.bytes'],
    mappedFieldsCount: 18,
    internetSamples: [
      {
        label: 'Zeek conn.log TLS Session',
        payload: '1620000000.123\tC123456\t192.168.1.10\t49152\t10.0.0.1\t443\ttcp\tssl\t12.5\t1024\t8192\tSF\t-\t-\t0\tShADadfF\t10\t1500\t14\t8600\t-',
        description: 'TSV connection record with UID, endpoints, and byte metrics.'
      },
      {
        label: 'Zeek SSH Inbound Session',
        payload: '1620000010.456\tC789012\t198.51.100.77\t51234\t10.0.1.10\t22\ttcp\tssh\t4.2\t512\t1024\tSF\t-\t-\t0\tShAdDafF\t8\t800\t10\t1200\t-',
        description: 'SSH connection log line with packet counts and TCP state.'
      },
      {
        label: 'Zeek DNS Query Session',
        payload: '1620000025.789\tC345678\t192.168.1.50\t58912\t1.1.1.1\t53\tudp\tdns\t0.05\t78\t128\tSF\t-\t-\t0\tDd\t1\t78\t1\t128\t-',
        description: 'DNS query transaction telemetry line.'
      }
    ]
  },

  // ==========================================
  // Tier C: 2 Universal Extension Parsers
  // ==========================================
  {
    id: 'parser.cloud.audit_flow',
    name: 'Multi-Cloud Audit & VPC Flow',
    vendor: 'AWS / Azure / GCP',
    tier: 'Tier C',
    category: 'Cloud Audit & OS',
    format: 'cloud_audit_json',
    status: 'VERIFIED',
    testsPassed: '38/38',
    throughputEps: 36800,
    p99LatencyMs: 1.2,
    residuePreserved: true,
    sampleLog: '{"eventVersion":"1.08","userIdentity":{"type":"IAMUser","userName":"alice"},"eventTime":"2026-09-05T14:00:00Z","eventSource":"s3.amazonaws.com","eventName":"GetObject","awsRegion":"us-east-1","sourceIPAddress":"198.51.100.1"}',
    ocsfClass: 'Cloud Activity',
    ocsfClassId: 6001,
    redosSafety: 'O(N) Linear Time Guaranteed • Multi-Provider Cloud Demuxer',
    supportedFormats: ['cloud_audit_json', 'aws_vpc_flow', 'json'],
    supportedVendors: ['AWS', 'Azure', 'GCP', 'Amazon', 'Microsoft', 'Google'],
    description: 'Universal cloud governance parser normalizing AWS CloudTrail, AWS VPC Flow v2-v5, Azure Monitor Activity, and GCP Audit logs into unified schema.',
    targetFields: ['cloud.provider', 'actor.user.name', 'api.service.name', 'api.operation', 'cloud.region', 'src_endpoint.ip', 'time'],
    mappedFieldsCount: 10,
    internetSamples: [
      {
        label: 'AWS CloudTrail S3 GetObject',
        payload: '{"eventVersion":"1.08","userIdentity":{"type":"IAMUser","userName":"alice"},"eventTime":"2026-09-05T14:00:00Z","eventSource":"s3.amazonaws.com","eventName":"GetObject","awsRegion":"us-east-1","sourceIPAddress":"198.51.100.1"}',
        description: 'CloudTrail IAM user object retrieval audit log.'
      },
      {
        label: 'AWS VPC Flow Log (Accept)',
        payload: '2 123456789010 eni-1235b8ca123456789 198.51.100.10 10.0.0.5 49152 443 6 20 8400 1620000000 1620000060 ACCEPT OK',
        description: 'VPC network interface flow record format.'
      },
      {
        label: 'Azure Monitor Security Write',
        payload: '{"time":"2026-09-29T03:00:00Z","operationName":"Microsoft.Security/securitySolutions/write","status":{"value":"Succeeded"},"caller":"sec-operator@gov.in","cloud_provider":"Azure"}',
        description: 'Azure ARM management activity control plane log.'
      }
    ]
  },
  {
    id: 'parser.linux.auditd',
    name: 'Linux Auditd & SELinux',
    vendor: 'Linux Foundation / Red Hat',
    tier: 'Tier C',
    category: 'Cloud Audit & OS',
    format: 'linux_auditd',
    status: 'VERIFIED',
    testsPassed: '35/35',
    throughputEps: 48200,
    p99LatencyMs: 0.8,
    residuePreserved: true,
    sampleLog: 'type=SYSCALL msg=audit(1620000000.123:456): arch=c000003e syscall=59 success=yes exit=0 a0=7ffd01 a1=7ffd02 a2=7ffd03 a3=7ffd04 items=2 ppid=1000 pid=1234 auid=1000 uid=0 gid=0 euid=0 comm="sudo" exe="/usr/bin/sudo" key="priv_esc"',
    ocsfClass: 'Process Activity',
    ocsfClassId: 1007,
    redosSafety: 'O(N) Linear Time Guaranteed • Kernel Key-Value State Scanner',
    supportedFormats: ['linux_auditd', 'key_value'],
    supportedVendors: ['Linux', 'RedHat', 'Canonical', 'SUSE'],
    description: 'Linux kernel audit subsystem parser decomposing SYSCALL, EXECVE, AVC, PATH, and USER_CMD events with epoch timestamps and UID resolution.',
    targetFields: ['unmapped.record_type', 'process.name', 'process.file.path', 'actor.user.uid', 'actor.user.id', 'process.pid', 'process.parent_process.pid', 'unmapped.key'],
    mappedFieldsCount: 21,
    internetSamples: [
      {
        label: 'Linux Auditd Sudo Syscall',
        payload: 'type=SYSCALL msg=audit(1620000000.123:456): arch=c000003e syscall=59 success=yes exit=0 a0=7ffd01 a1=7ffd02 a2=7ffd03 a3=7ffd04 items=2 ppid=1000 pid=1234 auid=1000 uid=0 gid=0 euid=0 comm="sudo" exe="/usr/bin/sudo" key="priv_esc"',
        description: 'Kernel privilege escalation audit syscall record.'
      },
      {
        label: 'SELinux AVC Access Denial',
        payload: 'type=AVC msg=audit(1620000005.456:789): avc: denied { read } for pid=4821 comm="httpd" name="shadow" dev="sda1" ino=142981 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:shadow_t:s0 tclass=file permissive=0',
        description: 'Mandatory access control policy violation on sensitive file.'
      },
      {
        label: 'Auditd Execve Process Spawn',
        payload: 'type=EXECVE msg=audit(1620000010.789:101): argc=3 a0="/bin/bash" a1="-c" a2="cat /etc/passwd"',
        description: 'Command line argument execution telemetry.'
      }
    ]
  }
];
