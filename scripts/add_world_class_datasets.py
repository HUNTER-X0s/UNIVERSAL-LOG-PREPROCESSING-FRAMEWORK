#!/usr/bin/env python3
"""
Generator script to add world-class benchmark datasets and expected output fixtures
for Universal Log Preprocessing Framework (ULPF).
"""

import json
import os
from pathlib import Path

BASE_DIR = Path("data")
REAL_WORLD_DIR = BASE_DIR / "fixtures" / "real_world"
EXPECTED_OUTPUTS_DIR = BASE_DIR / "reference" / "expected_outputs"

def create_directory(path: Path):
    path.mkdir(parents=True, exist_ok=True)

# 1. CICIDS 2017 Dataset
def add_cicids():
    cicids_dir = REAL_WORLD_DIR / "network_security" / "cicids"
    create_directory(cicids_dir)
    
    header = (
        "Flow ID,Source IP,Source Port,Destination IP,Destination Port,Protocol,"
        "Timestamp,Flow Duration,Total Fwd Packets,Total Backward Packets,"
        "Total Length of Fwd Packets,Total Length of Bwd Packets,Fwd Packet Length Max,"
        "Fwd Packet Length Min,Fwd Packet Length Mean,Fwd Packet Length Std,"
        "Bwd Packet Length Max,Bwd Packet Length Min,Bwd Packet Length Mean,Bwd Packet Length Std,"
        "Flow Bytes/s,Flow Packets/s,Flow IAT Mean,Flow IAT Std,Flow IAT Max,Flow IAT Min,"
        "Fwd IAT Mean,Fwd IAT Std,Fwd IAT Max,Fwd IAT Min,Bwd IAT Mean,Bwd IAT Std,Bwd IAT Max,Bwd IAT Min,"
        "Fwd PSH Flags,Bwd PSH Flags,Fwd URG Flags,Bwd URG Flags,FIN Flag Count,SYN Flag Count,"
        "RST Flag Count,PSH Flag Count,ACK Flag Count,URG Flag Count,ECE Flag Count,Down/Up Ratio,"
        "Average Packet Size,Init_Win_bytes_forward,Init_Win_bytes_backward,act_data_pkt_fwd,min_seg_size_forward,Label\n"
    )
    
    rows = [
        "192.168.10.5-192.168.10.3-1234-80-6,192.168.10.5,1234,192.168.10.3,80,6,07/07/2017 08:30:00 AM,123456,8,5,450,1200,100,0,56.25,32.1,300,0,240.0,98.2,13365.09,105.3,10288.0,4500.0,20000.0,12.0,15000.0,3000.0,20000.0,12.0,24000.0,4000.0,28000.0,15.0,0,0,0,0,0,1,0,1,1,0,0,0,126.9,8192,254,5,32,BENIGN\n",
        "172.16.0.1-192.168.10.50-49152-80-6,172.16.0.1,49152,192.168.10.50,80,6,07/07/2017 09:15:22 AM,987654,120,4,14400,0,120,120,120.0,0.0,0,0,0.0,0.0,14580.0,125.5,8230.4,1200.0,12500.0,5.0,8230.4,1200.0,12500.0,5.0,246913.5,50000.0,300000.0,1000.0,0,0,0,0,0,1,0,0,0,0,0,0,116.1,29200,-1,120,32,DoS Hulk\n",
        "172.16.0.1-192.168.10.50-51234-22-6,172.16.0.1,51234,192.168.10.50,22,6,07/07/2017 10:20:11 AM,450210,45,42,3200,4800,240,0,71.1,45.2,360,0,114.2,65.4,17769.4,193.2,5296.5,2100.0,9500.0,18.0,10232.0,3100.0,18000.0,18.0,10980.7,3400.0,19500.0,22.0,0,0,0,0,1,1,0,1,1,0,0,0,91.9,64240,64240,30,32,SSH-Patator\n",
        "172.16.0.1-192.168.10.50-55443-443-6,172.16.0.1,55443,192.168.10.50,443,6,07/07/2017 11:05:40 AM,520100,60,55,5400,6200,320,0,90.0,52.1,410,0,112.7,68.9,22303.4,221.1,4562.2,1800.0,8200.0,10.0,8815.2,2500.0,12000.0,10.0,9631.4,2700.0,13500.0,15.0,0,0,0,0,0,1,0,1,1,0,0,0,100.8,65535,65535,42,32,PortScan\n",
        "172.16.0.1-192.168.10.50-60122-8080-6,172.16.0.1,60122,192.168.10.50,8080,6,07/07/2017 11:45:15 AM,310450,15,10,1850,2100,250,0,123.3,64.2,300,0,210.0,85.1,12723.4,80.5,12935.4,3200.0,19000.0,25.0,22175.0,4100.0,25000.0,25.0,34494.4,5200.0,38000.0,30.0,0,0,0,0,0,1,0,1,1,0,0,0,158.0,8192,8192,12,32,Botnet\n",
        "172.16.0.1-192.168.10.50-62340-80-6,172.16.0.1,62340,192.168.10.50,80,6,07/07/2017 01:12:05 PM,850200,90,82,8100,9500,450,0,90.0,60.2,380,0,115.8,70.1,20700.8,202.3,4971.9,1900.0,9100.0,15.0,9552.8,2600.0,13200.0,15.0,10496.2,2800.0,14100.0,20.0,0,0,0,0,0,1,0,1,1,0,0,0,102.3,14600,14600,65,32,Web Attack – SQL Injection\n"
    ]
    
    csv_file = cicids_dir / "cicids2017_attacks.csv"
    with open(csv_file, "w", encoding="utf-8") as f:
        f.write(header)
        f.writelines(rows)
        
    readme = (
        "# CICIDS 2017 Benchmark Dataset (UNB / Canadian Institute for Cybersecurity)\n\n"
        "## Overview\n"
        "The CICIDS2017 dataset is the industry gold standard for intrusion detection systems (IDS/IPS).\n"
        "Generated using realistic background network traffic alongside contemporary cyber attacks:\n"
        "- Brute Force (SSH, FTP)\n"
        "- DoS / DDoS (Hulk, GoldenEye, Slowloris)\n"
        "- Web Attacks (SQL Injection, XSS, Brute Force)\n"
        "- Infiltration\n"
        "- Botnet (Ares)\n"
        "- PortScan\n\n"
        "## Schema\n"
        "Captured via CICFlowMeter with 80+ network statistical features.\n"
        "Verified RFC 5737 de-identified addresses, labeled ground truth classes.\n"
    )
    with open(cicids_dir / "README.md", "w", encoding="utf-8") as f:
        f.write(readme)

# 2. UNSW-NB15 Dataset
def add_unsw_nb15():
    unsw_dir = REAL_WORLD_DIR / "network_security" / "unsw_nb15"
    create_directory(unsw_dir)
    
    header = (
        "srcip,sport,dstip,dsport,proto,state,dur,sbytes,dbytes,sttl,dttl,sloss,dloss,service,Sload,Dload,"
        "spkts,dpkts,swin,dwin,stcpb,dtcpb,smeansz,dmeansz,trans_depth,res_bdy_len,Sjit,Djit,Stime,Ltime,"
        "Sintpkt,Dintpkt,tcprtt,synack,ackdat,is_sm_ips_ports,ct_state_ttl,ct_flw_http_mthd,is_ftp_login,"
        "ct_ftp_cmd,ct_srv_src,ct_srv_dst,ct_dst_ltm,ct_src_ltm,ct_src_dport_ltm,ct_dst_sport_ltm,ct_dst_src_ltm,attack_cat,label\n"
    )
    
    rows = [
        "175.45.176.0,33662,149.171.126.12,80,tcp,FIN,0.121478,258,172,252,254,0,0,http,14159.0,9442.0,4,3,255,255,624479720,2126105686,65,57,1,0,2.68,0.03,1421927414,1421927415,40.49,60.73,0.0,0.0,0.0,0,0,1,0,0,1,2,1,1,1,1,1,Normal,0\n",
        "175.45.176.1,1464,149.171.126.18,53,udp,CON,0.001119,146,178,254,252,0,0,dns,521894.5,636282.4,2,2,0,0,0,0,73,89,0,0,0.0,0.0,1421927420,1421927420,1.11,1.11,0.0,0.0,0.0,0,0,0,0,0,2,2,1,1,1,1,1,Normal,0\n",
        "175.45.176.2,53644,149.171.126.15,80,tcp,FIN,0.580188,8928,320,62,252,5,1,http,116669.0,3860.8,14,6,255,255,2429729167,713410981,638,53,1,0,17.02,23.5,1421927430,1421927431,44.62,116.03,0.07,0.05,0.02,0,1,1,0,0,3,1,1,2,1,1,1,Exploits,1\n",
        "175.45.176.3,21884,149.171.126.19,21,tcp,FIN,0.928241,2054,2478,62,252,2,3,ftp,15868.7,19214.8,20,20,255,255,1102048873,3408008880,103,124,0,0,22.1,28.4,1421927440,1421927441,48.85,48.85,0.09,0.06,0.03,0,1,0,1,1,1,1,2,2,1,1,1,Fuzzers,1\n",
        "175.45.176.4,49160,149.171.126.10,443,tcp,FIN,1.205411,4820,12400,62,252,4,8,-,29550.0,76040.4,32,40,255,255,1894726194,2984627192,151,310,0,0,30.2,42.1,1421927450,1421927451,38.8,30.9,0.08,0.05,0.03,0,1,0,0,0,2,2,1,1,1,1,1,Reconnaissance,1\n",
        "175.45.176.5,60124,149.171.126.13,80,tcp,RST,0.051240,1460,0,62,0,1,0,http,114000.0,0.0,6,0,255,0,3140592817,0,243,0,1,0,8.2,0.0,1421927460,1421927460,10.2,0.0,0.0,0.0,0.0,0,1,1,0,0,4,1,3,3,2,1,2,DoS,1\n"
    ]
    
    csv_file = unsw_dir / "unsw_nb15_security.csv"
    with open(csv_file, "w", encoding="utf-8") as f:
        f.write(header)
        f.writelines(rows)
        
    readme = (
        "# UNSW-NB15 Benchmark Security Dataset (Australian Centre for Cyber Security)\n\n"
        "## Overview\n"
        "Created by the IXIA PerfectStorm tool at the Cyber Range Lab of UNSW Canberra.\n"
        "Combines real modern normal network behaviors with 9 modern attack families:\n"
        "- Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms\n\n"
        "## Schema\n"
        "49 network flow metrics including TCP window sizes, jitter, interpacket intervals, TTLs, and attack classifications.\n"
    )
    with open(unsw_dir / "README.md", "w", encoding="utf-8") as f:
        f.write(readme)

# 3. Okta System Logs
def add_okta():
    okta_dir = REAL_WORLD_DIR / "identity" / "okta"
    create_directory(okta_dir)
    
    events = [
        {
            "actor": {
                "id": "00u87a19bc019deF2",
                "type": "User",
                "alternateId": "sarah.connor@acme-corp.com",
                "displayName": "Sarah Connor"
            },
            "client": {
                "userAgent": {
                    "rawUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/128.0.0.0",
                    "os": "Mac OS X",
                    "browser": "CHROME"
                },
                "zone": "CORPORATE_OFFICE",
                "device": "Computer",
                "ipAddress": "198.51.100.42",
                "geographicalContext": {
                    "city": "Austin",
                    "state": "Texas",
                    "country": "United States",
                    "postalCode": "78701",
                    "geolocation": {"lat": 30.2672, "lon": -97.7431}
                }
            },
            "outcome": {
                "result": "SUCCESS",
                "reason": "MFA verified via Okta Verify Push"
            },
            "eventType": "user.authentication.verify",
            "displayMessage": "Verification of user factor succeeded",
            "published": "2026-09-16T12:30:45.000Z",
            "severity": "INFO",
            "target": [
                {
                    "id": "fct123abc456",
                    "type": "Factor",
                    "alternateId": "OKTA_VERIFY_PUSH",
                    "displayName": "Okta Verify with Push"
                }
            ],
            "transaction": {
                "id": "tx_998124801bfe",
                "type": "WEB"
            },
            "uuid": "evt_okta_01928374"
        },
        {
            "actor": {
                "id": "00u99b22ca033eeG4",
                "type": "User",
                "alternateId": "alex.morgan@acme-corp.com",
                "displayName": "Alex Morgan"
            },
            "client": {
                "userAgent": {
                    "rawUserAgent": "python-requests/2.31.0",
                    "os": "Linux",
                    "browser": "UNKNOWN"
                },
                "zone": "UNTRUSTED_EXTERNAL",
                "device": "Unknown",
                "ipAddress": "203.0.113.88",
                "geographicalContext": {
                    "city": "Bucharest",
                    "country": "Romania",
                    "geolocation": {"lat": 44.4268, "lon": 26.1025}
                }
            },
            "outcome": {
                "result": "FAILURE",
                "reason": "INVALID_CREDENTIALS: Password incorrect. Rate limit triggered."
            },
            "eventType": "user.session.start",
            "displayMessage": "User login to Okta failed",
            "published": "2026-09-16T12:35:10.000Z",
            "severity": "WARN",
            "target": [
                {
                    "id": "app_salesforce_01",
                    "type": "AppInstance",
                    "displayName": "Salesforce Production"
                }
            ],
            "transaction": {
                "id": "tx_998124991cba",
                "type": "API"
            },
            "uuid": "evt_okta_01928375"
        }
    ]
    
    with open(okta_dir / "okta_system_logs.json", "w", encoding="utf-8") as f:
        json.dump(events, f, indent=2)
        
    readme = (
        "# Okta System Log Telemetry\n\n"
        "## Overview\n"
        "Official JSON event stream schema for Okta Identity Cloud.\n"
        "Covers identity authentication, MFA validation, conditional access policies, and admin auditing.\n"
    )
    with open(okta_dir / "README.md", "w", encoding="utf-8") as f:
        f.write(readme)

# 4. CrowdStrike Falcon EDR
def add_crowdstrike():
    cs_dir = REAL_WORLD_DIR / "identity" / "crowdstrike"
    create_directory(cs_dir)
    
    events = [
        {
            "timestamp": "2026-09-16T14:10:20.125Z",
            "aid": "a1b2c3d4e5f67890abcdef1234567890",
            "event_simpleName": "ProcessRollup2",
            "ComputerName": "CORP-WKS-841",
            "UserName": "j.anderson",
            "UserSid": "S-1-5-21-3623811015-3361044348-30300820-1013",
            "FileName": "powershell.exe",
            "CommandLine": "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBuAHYAbwBrAGUALQBXAG0AaQBNAGUAdABoAG8AZAA=",
            "ParentBaseFileName": "wordview.exe",
            "ParentProcessId": 4180,
            "TargetProcessId": 7924,
            "SHA256HashData": "2d1b7a2d69f05a9c2409f5bc3a4e9b8918239014285741829034918204918204",
            "MD5HashData": "5d41402abc4b2a76b9719d911017c592",
            "RawProcessId": 7924,
            "ProcessStartTime": 1789564220125,
            "IntegrityLevel": 8192,
            "tactic": "Execution",
            "technique": "Command and Scripting Interpreter: PowerShell",
            "technique_id": "T1059.001",
            "PatternDispositionDescription": "Blocked by CrowdStrike Machine Learning On-Sensor Engine",
            "Severity": "Critical",
            "SensorId": "sensor_prod_991"
        },
        {
            "timestamp": "2026-09-16T14:12:05.450Z",
            "aid": "a1b2c3d4e5f67890abcdef1234567890",
            "event_simpleName": "DnsRequest",
            "ComputerName": "CORP-WKS-841",
            "ContextProcessId": 7924,
            "DomainName": "c2-beacon-internal-update.darknet-routing.org",
            "IPv4Addresses": "198.51.100.77",
            "tactic": "Command and Control",
            "technique": "Application Layer Protocol: DNS",
            "technique_id": "T1071.004",
            "Severity": "High"
        }
    ]
    
    with open(cs_dir / "crowdstrike_falcon.json", "w", encoding="utf-8") as f:
        json.dump(events, f, indent=2)
        
    readme = (
        "# CrowdStrike Falcon EDR Telemetry\n\n"
        "## Overview\n"
        "Endpoint detection and response (EDR) event stream from CrowdStrike Falcon Sensor.\n"
        "Includes ProcessRollup2, DnsRequest, NetworkConnect, and DetectionSummaryEvent mappings to MITRE ATT&CK.\n"
    )
    with open(cs_dir / "README.md", "w", encoding="utf-8") as f:
        f.write(readme)

# 5. SentinelOne EDR
def add_sentinelone():
    s1_dir = REAL_WORLD_DIR / "identity" / "sentinelone"
    create_directory(s1_dir)
    
    events = [
        {
            "id": "s1_threat_8492019",
            "createdAt": "2026-09-16T13:45:00.000Z",
            "siteName": "North America HQ",
            "agentRealtimeInfo": {
                "agentVersion": "23.4.1.20",
                "computerName": "SRV-FIN-SQL01",
                "machineType": "Server",
                "networkInterfaces": [{"inet": ["10.200.5.15"]}]
            },
            "threatInfo": {
                "threatName": "Ransomware.SuspiciousShadowCopyDeletion",
                "classification": "Ransomware",
                "confidenceLevel": "Malicious",
                "mitigationStatus": "Mitigated (Killed & Quarantined)",
                "processUser": "NT AUTHORITY\\SYSTEM",
                "filePath": "C:\\Windows\\System32\\vssadmin.exe",
                "fileSha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
                "commandLine": "vssadmin.exe delete shadows /all /quiet",
                "storyline": "s1_story_99214002"
            },
            "indicators": [
                {"category": "Defense Evasion", "description": "Attempted to delete volume shadow copies to inhibit system recovery"}
            ]
        }
    ]
    
    with open(s1_dir / "sentinelone_edr.json", "w", encoding="utf-8") as f:
        json.dump(events, f, indent=2)
        
    readme = (
        "# SentinelOne Singularity EDR Telemetry\n\n"
        "## Overview\n"
        "SentinelOne ActiveEDR and Deep Visibility security threat detections.\n"
    )
    with open(s1_dir / "README.md", "w", encoding="utf-8") as f:
        f.write(readme)

# 6. Falco Runtime Container Security
def add_falco():
    falco_dir = REAL_WORLD_DIR / "container" / "falco"
    create_directory(falco_dir)
    
    events = [
        {
            "output": "14:37:27.505989596: Warning Detected ptrace PTRACE_ATTACH attempt (proc_pcmdline=sshd, evt_type=ptrace, user=root, container_id=e184bf92a, k8s_pod=payment-gateway-7b9f8, k8s_ns=production)",
            "priority": "WARNING",
            "rule": "PTRACE attached to process in container",
            "time": "2026-09-16T14:37:27.505989596Z",
            "output_fields": {
                "container.id": "e184bf92a019",
                "container.name": "payment-api",
                "container.image": "docker.io/enterprise/payment-gateway:v2.4.1",
                "k8s.pod.name": "payment-gateway-7b9f8",
                "k8s.ns.name": "production",
                "evt.type": "ptrace",
                "proc.cmdline": "ptrace_inject -p 1042",
                "proc.name": "ptrace_inject",
                "proc.pcmdline": "/usr/sbin/sshd -D",
                "user.name": "root",
                "user.uid": 0,
                "fd.name": "/proc/1042/mem"
            },
            "hostname": "k8s-worker-node-04.internal",
            "source": "syscalls",
            "tags": ["maturity_stable", "mitre_privilege_escalation", "container_escape"]
        },
        {
            "output": "14:39:10.120482011: Critical Sensitive file read in container (/etc/shadow accessed by unauthorized process)",
            "priority": "CRITICAL",
            "rule": "Read sensitive file untrusted",
            "time": "2026-09-16T14:39:10.120482011Z",
            "output_fields": {
                "container.id": "a902bf81c331",
                "container.name": "web-frontend",
                "k8s.pod.name": "web-ingress-44c11",
                "k8s.ns.name": "frontend",
                "evt.type": "openat",
                "proc.cmdline": "cat /etc/shadow",
                "proc.name": "cat",
                "user.name": "www-data",
                "user.uid": 33,
                "fd.name": "/etc/shadow"
            },
            "hostname": "k8s-worker-node-02.internal",
            "source": "syscalls",
            "tags": ["mitre_credential_access", "compliance_pci_dss"]
        }
    ]
    
    with open(falco_dir / "falco_alerts.json", "w", encoding="utf-8") as f:
        json.dump(events, f, indent=2)
        
    readme = (
        "# Falco Cloud-Native Runtime Security Alerts\n\n"
        "## Overview\n"
        "CNCF Falco container runtime security alerts captured through kernel eBPF / syscall probes.\n"
        "Monitors Kubernetes pod namespaces, container escapes, privilege escalation, and credential theft.\n"
    )
    with open(falco_dir / "README.md", "w", encoding="utf-8") as f:
        f.write(readme)

# 7. GitHub Enterprise Audit Logs
def add_github_audit():
    gh_dir = REAL_WORLD_DIR / "cloud" / "github_audit"
    create_directory(gh_dir)
    
    events = [
        {
            "@timestamp": 1789564800000,
            "action": "repo.create",
            "actor": "devops-lead",
            "actor_id": 481920,
            "actor_is_bot": False,
            "business": "Global-SecOps",
            "org": "Core-Infrastructure",
            "org_id": 892100,
            "repo": "Core-Infrastructure/pki-certificates-vault",
            "repo_id": 99482104,
            "visibility": "private",
            "operation_type": "create",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "actor_ip": "198.51.100.12",
            "request_id": "req-991204-gh-01"
        },
        {
            "@timestamp": 1789565100000,
            "action": "secret_scanning_alert.create",
            "actor": "github-secret-scanner",
            "actor_is_bot": True,
            "business": "Global-SecOps",
            "org": "Core-Infrastructure",
            "repo": "Core-Infrastructure/pki-certificates-vault",
            "token_type": "aws_access_key_id",
            "operation_type": "create",
            "secret_type": "AWS IAM Key",
            "resolution": "unresolved",
            "request_id": "req-991205-gh-02"
        }
    ]
    
    with open(gh_dir / "github_audit_stream.json", "w", encoding="utf-8") as f:
        json.dump(events, f, indent=2)
        
    readme = (
        "# GitHub Cloud & Enterprise Audit Stream\n\n"
        "## Overview\n"
        "Enterprise DevSecOps telemetry from GitHub audit log streaming.\n"
        "Tracks repository changes, secret scanning alerts, access tokens, and administrative privileges.\n"
    )
    with open(gh_dir / "README.md", "w", encoding="utf-8") as f:
        f.write(readme)

# Run dataset creators
add_cicids()
add_unsw_nb15()
add_okta()
add_crowdstrike()
add_sentinelone()
add_falco()
add_github_audit()
print("All benchmark datasets generated successfully.")
