#!/usr/bin/env python3
"""
Expected Output Fixture Generator for ULPF.
Generates raw input samples and ground truth expected Universal Canonical Event (UCE) v1
JSON fixtures for all supported vendor parsers.
"""

import json
import hashlib
from pathlib import Path
from datetime import UTC, datetime

from ulpf_parser_runtime.framing import RecordFramer
from ulpf_normalization.canonical import CanonicalEventBuilder

from ulpf_parser_runtime.parsers.specialized.paloalto import PaloAltoPanOSParser
from ulpf_parser_runtime.parsers.specialized.fortigate import FortiGateParser
from ulpf_parser_runtime.parsers.specialized.cisco import CiscoSyslogParser
from ulpf_parser_runtime.parsers.specialized.suricata import SuricataEveParser
from ulpf_parser_runtime.parsers.specialized.zeek import ZeekParser
from ulpf_parser_runtime.parsers.specialized.snort import SnortFastParser
from ulpf_parser_runtime.parsers.specialized.opnsense import OPNsenseFilterlogParser
from ulpf_parser_runtime.parsers.specialized.linux_auditd import LinuxAuditdParser
from ulpf_parser_runtime.parsers.specialized.cloud_audit import CloudAuditParser
from ulpf_parser_runtime.parsers.specialized.web_access import WebAccessLogParser

from ulpf_parser_runtime.parsers.cef_parser import CefParser
from ulpf_parser_runtime.parsers.leef_parser import LeefParser
from ulpf_parser_runtime.parsers.syslog_rfc5424 import SyslogRFC5424Parser
from ulpf_parser_runtime.parsers.syslog_rfc3164 import SyslogRFC3164Parser
from ulpf_parser_runtime.parsers.json_parser import GenericJsonParser
from ulpf_parser_runtime.parsers.xml_parser import XmlParser

OUTPUT_BASE = Path("data/reference/expected_outputs")
framer = RecordFramer()
builder = CanonicalEventBuilder()

FIXTURE_SPECS = [
    {
        "id": "paloalto",
        "vendor": "Palo Alto Networks",
        "product": "PA-Series Firewall",
        "parser": PaloAltoPanOSParser(),
        "raw_file": "raw_input.log",
        "raw_content": "1,2026/09/16 10:15:30,001234567890,TRAFFIC,drop,1,2026/09/16 10:15:30,198.51.100.25,203.0.113.10,0.0.0.0,0.0.0.0,Perimeter-Drop,,,ssh,vsys1,trust,untrust,ethernet1/1,ethernet1/2,default,1,1001,1,49152,22,0,0,0x0,tcp,deny,128,64,64,2,2026/09/16 10:15:30,0,any\n",
        "description": "Palo Alto Networks PAN-OS 10.x Traffic Log (CSV format) showing dropped TCP session."
    },
    {
        "id": "fortigate",
        "vendor": "Fortinet",
        "product": "FortiGate UTM",
        "parser": FortiGateParser(),
        "raw_file": "raw_input.log",
        "raw_content": 'date=2026-09-16 time=11:20:00 devname="FGT-CORP-01" devid="FGT60D4614041234" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.10.10.25 srcport=54321 srcintf="port1" dstip=198.51.100.40 dstport=443 dstintf="port2" proto=6 action="close" policyid=1 service="HTTPS" trandisp="snat" duration=12 sentbyte=1200 rcvdbyte=4500\n',
        "description": "Fortinet FortiGate FortiOS UTM forward traffic log in Key-Value format."
    },
    {
        "id": "cisco_asa",
        "vendor": "Cisco",
        "product": "Adaptive Security Appliance (ASA)",
        "parser": CiscoSyslogParser(),
        "raw_file": "raw_input.log",
        "raw_content": "%ASA-4-106023: Deny tcp src outside:198.51.100.80/51234 dst inside:10.0.0.5/80 by access_group \"outside_access_in\" [0x0, 0x0]\n",
        "description": "Cisco ASA perimeter firewall syslog event 106023 (access-list deny)."
    },
    {
        "id": "suricata",
        "vendor": "OISF",
        "product": "Suricata EVE IDS/IPS",
        "parser": SuricataEveParser(),
        "raw_file": "raw_input.json",
        "raw_content": '{"timestamp":"2026-09-16T12:00:01.000123+0000","flow_id":192837465,"event_type":"alert","src_ip":"198.51.100.105","src_port":41230,"dest_ip":"10.0.1.20","dest_port":80,"proto":"TCP","alert":{"action":"blocked","gid":1,"signature_id":2010935,"rev":3,"signature":"ET SCAN Potential SSH Brute Force","category":"Attempted Information Leak","severity":2}}\n',
        "description": "Suricata EVE JSON IDS/IPS signature alert with attack signature and action."
    },
    {
        "id": "zeek",
        "vendor": "Zeek",
        "product": "Zeek Network Security Monitor",
        "parser": ZeekParser(),
        "raw_file": "raw_input.tsv",
        "raw_content": "1789560000.123456\tCH9281\t198.51.100.22\t49150\t203.0.113.5\t53\tudp\tdns\t0.002100\t84\t150\tSF\t-\t-\t0\tDd\t1\t112\t1\t178\t-\n",
        "description": "Zeek conn.log TSV record capturing DNS lookup flow metrics."
    },
    {
        "id": "snort",
        "vendor": "Cisco / Sourcefire",
        "product": "Snort IDS",
        "parser": SnortFastParser(),
        "raw_file": "raw_input.log",
        "raw_content": "[**] [1:1000001:1] COMMUNITY WEB-ATTACK /etc/passwd access attempt [**] [Classification: Web Application Attack] [Priority: 1] 09/16-12:00:01.123456 198.51.100.15:49152 -> 10.0.0.10:80 TCP TTL:64 TOS:0x0 ID:12345 IpLen:20 DgmLen:450 [**]\n",
        "description": "Snort fast alert log indicating unauthorized file access attempt."
    },
    {
        "id": "opnsense",
        "vendor": "Deciso",
        "product": "OPNsense Firewall",
        "parser": OPNsenseFilterlogParser(),
        "raw_file": "raw_input.log",
        "raw_content": "filterlog[12345]: 100,,,010000,em0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,198.51.100.99,10.0.0.1,51234,443,0,S,123456789,,65535,,mss;sackOK;TS\n",
        "description": "OPNsense filterlog CSV packet filter drop event."
    },
    {
        "id": "linux_auditd",
        "vendor": "Linux Foundation",
        "product": "Linux Kernel Auditd",
        "parser": LinuxAuditdParser(),
        "raw_file": "raw_input.log",
        "raw_content": "type=EXECVE msg=audit(1789560000.500:102): argc=3 a0=\"cat\" a1=\"/etc/shadow\" a2=\"--quiet\"\n",
        "description": "Linux kernel auditd EXECVE record tracing process execution."
    },
    {
        "id": "aws_cloudtrail",
        "vendor": "Amazon Web Services",
        "product": "AWS CloudTrail",
        "parser": CloudAuditParser(),
        "raw_file": "raw_input.json",
        "raw_content": '{"eventVersion":"1.08","userIdentity":{"type":"IAMUser","principalId":"AIDASAMPLEUSER","arn":"arn:aws:iam::123456789012:user/Alice","accountId":"123456789012","userName":"Alice"},"eventTime":"2026-09-16T12:00:00Z","eventSource":"iam.amazonaws.com","eventName":"CreateAccessKey","awsRegion":"us-east-1","sourceIPAddress":"198.51.100.50","userAgent":"aws-cli/2.15.0","requestParameters":{"userName":"Alice"},"responseElements":{"accessKey":{"accessKeyId":"AKIAIOSFODNN7EXAMPLE","status":"Active"}}}\n',
        "description": "AWS CloudTrail governance event showing IAM Access Key creation."
    },
    {
        "id": "web_access",
        "vendor": "Apache / Nginx",
        "product": "Combined Web Access Log",
        "parser": WebAccessLogParser(),
        "raw_file": "raw_input.log",
        "raw_content": '198.51.100.44 - john.doe [16/Sep/2026:12:34:56 +0000] "POST /api/v1/auth/login HTTP/1.1" 200 452 "https://portal.enterprise.com" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"\n',
        "description": "Standard Nginx/Apache Combined Access Log for authentication API endpoint."
    },
    {
        "id": "cef",
        "vendor": "Micro Focus / ArcSight",
        "product": "Common Event Format (CEF)",
        "parser": CefParser(),
        "raw_file": "raw_input.log",
        "raw_content": "CEF:0|SecurityCompany|ThreatDetector|3.2.1|PORT_SCAN|TCP Port Scan Detected|7|src=198.51.100.60 dst=10.0.0.15 spt=51234 dpt=80 proto=TCP act=blocked msg=High rate of SYN packets\n",
        "description": "ArcSight Common Event Format (CEF) standard security alert."
    },
    {
        "id": "leef",
        "vendor": "IBM",
        "product": "QRadar LEEF",
        "parser": LeefParser(),
        "raw_file": "raw_input.log",
        "raw_content": "LEEF:2.0|IBM|CustomApp|4.0|AuthFailed|src=198.51.100.72\tdst=10.0.0.8\tsrcPort=52110\tdstPort=22\tusrName=admin\tproto=TCP\tcat=Authentication\n",
        "description": "IBM QRadar Log Event Extended Format (LEEF 2.0) authentication failure."
    },
    {
        "id": "syslog_rfc5424",
        "vendor": "IETF",
        "product": "RFC 5424 Syslog Protocol",
        "parser": SyslogRFC5424Parser(),
        "raw_file": "raw_input.log",
        "raw_content": "<165>1 2026-09-16T12:45:00.123Z gateway.corp.internal firewall 8492 ID47 [meta sequenceId=\"1042\"] Connection dropped by ingress ACL\n",
        "description": "Standard IETF RFC 5424 structured syslog message with PRI, timestamp, host, and app-name."
    },
    {
        "id": "syslog_rfc3164",
        "vendor": "IETF",
        "product": "RFC 3164 BSD Syslog",
        "parser": SyslogRFC3164Parser(),
        "raw_file": "raw_input.log",
        "raw_content": "<34>Sep 16 12:50:22 edge-router-01 sshd[9124]: Failed password for invalid user root from 198.51.100.89 port 41298 ssh2\n",
        "description": "Classic BSD RFC 3164 syslog daemon record capturing SSH authentication failure."
    },
    {
        "id": "windows_security",
        "vendor": "Microsoft",
        "product": "Windows Security / Sysmon XML",
        "parser": XmlParser(),
        "raw_file": "raw_input.xml",
        "raw_content": '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}"/><EventID>4624</EventID><Level>0</Level><TimeCreated SystemTime="2026-09-16T13:00:00.0000000Z"/></System><EventData><Data Name="TargetUserName">Administrator</Data><Data Name="TargetDomainName">CORP</Data><Data Name="IpAddress">198.51.100.33</Data><Data Name="IpPort">51200</Data><Data Name="LogonType">3</Data></EventData></Event>\n',
        "description": "Windows Security Event ID 4624 (Successful Network Logon) in Windows XML Event schema."
    },
    {
        "id": "gcp_audit",
        "vendor": "Google Cloud",
        "product": "GCP Cloud Audit Logs",
        "parser": GenericJsonParser(),
        "raw_file": "raw_input.json",
        "raw_content": '{"protoPayload":{"@type":"type.googleapis.com/google.cloud.audit.AuditLog","authenticationInfo":{"principalEmail":"admin@enterprise.com"},"serviceName":"compute.googleapis.com","methodName":"v1.compute.instances.delete","resourceName":"projects/prod-cluster/zones/us-central1-a/instances/vm-db-primary"},"insertId":"gcp_audit_019283","resource":{"type":"gce_instance","labels":{"instance_id":"918237192"}},"timestamp":"2026-09-16T13:15:00.000000Z","severity":"NOTICE"}\n',
        "description": "Google Cloud Platform (GCP) Cloud Audit Log showing administrative VM instance deletion."
    },
    {
        "id": "azure_activity",
        "vendor": "Microsoft Azure",
        "product": "Azure Monitor Activity Log",
        "parser": GenericJsonParser(),
        "raw_file": "raw_input.json",
        "raw_content": '{"time":"2026-09-16T13:20:00.000Z","resourceId":"/subscriptions/sub-001/resourceGroups/SecOps/providers/Microsoft.Network/networkSecurityGroups/nsg-perimeter","operationName":"Microsoft.Network/networkSecurityGroups/write","category":"Administrative","resultType":"Success","caller":"admin@azurecorp.com","clientIpAddress":"198.51.100.90"}\n',
        "description": "Microsoft Azure Activity Log showing Network Security Group administrative modification."
    },
    {
        "id": "okta",
        "vendor": "Okta",
        "product": "Okta Identity Cloud",
        "parser": GenericJsonParser(),
        "raw_file": "raw_input.json",
        "raw_content": '{"published":"2026-09-16T13:30:00.000Z","eventType":"user.authentication.verify","severity":"INFO","actor":{"alternateId":"dev@enterprise.com","displayName":"Developer"},"client":{"ipAddress":"198.51.100.44","device":"Computer"},"outcome":{"result":"SUCCESS"},"displayMessage":"User MFA factor verification succeeded"}\n',
        "description": "Okta System Log capturing verified multi-factor authentication event."
    },
    {
        "id": "crowdstrike",
        "vendor": "CrowdStrike",
        "product": "CrowdStrike Falcon Sensor",
        "parser": GenericJsonParser(),
        "raw_file": "raw_input.json",
        "raw_content": '{"timestamp":"2026-09-16T13:40:00.000Z","event_simpleName":"ProcessRollup2","aid":"a1b2c3d4e5f67890abcdef1234567890","ComputerName":"CORP-SEC-01","UserName":"analyst","FileName":"powershell.exe","CommandLine":"powershell.exe -Enc SGVsbG8=","SHA256HashData":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","Severity":"High"}\n',
        "description": "CrowdStrike Falcon Sensor ProcessRollup2 EDR event capturing executed command and hash."
    },
    {
        "id": "falco",
        "vendor": "CNCF / Sysdig",
        "product": "Falco Runtime Security",
        "parser": GenericJsonParser(),
        "raw_file": "raw_input.json",
        "raw_content": '{"time":"2026-09-16T13:50:00.000Z","rule":"PTRACE attached to process in container","priority":"WARNING","output":"Warning Detected ptrace PTRACE_ATTACH attempt","output_fields":{"container.id":"c10928a","k8s.pod.name":"ingress-pod","evt.type":"ptrace","proc.cmdline":"ptrace_inject -p 1"},"hostname":"node-k8s-01","source":"syscalls"}\n',
        "description": "Falco container runtime security alert capturing unauthorized syscall ptrace invocation."
    }
]

def generate_fixtures():
    OUTPUT_BASE.mkdir(parents=True, exist_ok=True)
    
    count = 0
    for spec in FIXTURE_SPECS:
        vendor_dir = OUTPUT_BASE / spec["id"]
        vendor_dir.mkdir(parents=True, exist_ok=True)
        
        # 1. Write raw sample
        raw_path = vendor_dir / spec["raw_file"]
        with open(raw_path, "w", encoding="utf-8") as f:
            f.write(spec["raw_content"])
            
        # 2. Parse and generate deterministic expected UCE
        framed = framer.frame_single(spec["raw_content"].strip())
        record = framed.records[0]
        parse_result = spec["parser"].parse(record)
        
        raw_bytes = record.raw_bytes
        uce_dict = builder.build_uce(
            parse_result=parse_result,
            raw_payload_bytes=raw_bytes,
            vendor=spec["vendor"],
            product=spec["product"]
        )
        
        # Make timestamp deterministic for expected fixture comparison
        uce_dict["processing"]["processed_at"] = "2026-09-16T14:00:00+00:00"
        uce_dict["event"]["metadata"]["ingest_timestamp"] = "2026-09-16T14:00:00+00:00"
        
        # 3. Write expected UCE JSON
        expected_json_path = vendor_dir / "expected_uce.json"
        with open(expected_json_path, "w", encoding="utf-8") as f:
            json.dump(uce_dict, f, indent=2)
            
        # 4. Write VERIFICATION contract
        verification_content = f"""# ULPF Expected Output Ground Truth Contract: {spec['vendor']} {spec['product']}

## Parser Specification
- **Parser ID:** `{parse_result.parser_id}`
- **Parser Version:** `{parse_result.parser_version}`
- **Vendor:** `{spec['vendor']}`
- **Product:** `{spec['product']}`
- **Format:** `{parse_result.format}`
- **Normalized Schema:** `contracts/jsonschema/normalized-event.v1.schema.json` (UCE v1.0.0)

## Verification Guarantees
1. **Deterministic Parsing:** Identical input bytes always produce 100% byte-for-byte identical extracted fields.
2. **Zero Loss (Residue Preservation):** Any fields not bound to core UCE canonical properties are preserved in `unmapped_fields`.
3. **Cryptographic Lineage:** Raw payload SHA-256 is tracked in `evidence.payload_sha256` and linked to `raw_event_id`.
4. **Field-Level Provenance:** Every normalized field has an immutable assertion origin (`observed`, `derived`, `inferred`, `enriched`).

## Verification Test
Run automated regression test suite:
```bash
python -m unittest tests/test_expected_output_fixtures.py -k test_fixture_{spec['id']}
```
"""
        with open(vendor_dir / "VERIFICATION.md", "w", encoding="utf-8") as f:
            f.write(verification_content)
            
        count += 1
        print(f"Generated ground truth fixture: {spec['id']} ({spec['vendor']})")

    print(f"\nAll {count} vendor expected output fixtures generated successfully in {OUTPUT_BASE}")

if __name__ == "__main__":
    generate_fixtures()
