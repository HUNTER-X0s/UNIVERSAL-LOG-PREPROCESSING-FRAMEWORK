import json
from fastapi.testclient import TestClient
from ulpf_api.app import app
from ulpf_parser_runtime.registry import create_default_registry
from ulpf_parser_runtime.framing import FramedRecord
from ulpf_parser_runtime.models import ParseStatus

def run_audit():
    reg = create_default_registry()
    client = TestClient(app)
    
    print(f"=== AUDITING ALL {len(reg._parsers)} CONCRETE PARSERS IN REGISTRY ===")
    
    sample_payloads = {
        "parser.generic.json": '{"src_ip": "10.0.0.1", "dst_port": 443, "action": "allow", "proto": "TCP"}',
        "parser.generic.ndjson": '{"event": "flow", "bytes": 512, "src": "192.168.1.10"}',
        "parser.generic.csv": 'src_ip,dst_port,action\n10.0.0.1,443,allow',
        "parser.generic.keyvalue": 'action=allow src=192.168.1.1 dst=8.8.8.8 dport=443',
        "parser.syslog.rfc3164": "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8",
        "parser.syslog.rfc5424": '<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - msg',
        "parser.generic.cef": 'CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232',
        "parser.generic.leef": 'LEEF:1.0|Microsoft|MSExchange|2013|AuthSuccess|src=192.168.1.1\tdst=10.0.0.2\tusr=admin',
        "parser.generic.w3c": '#Fields: date time c-ip cs-method cs-uri-stem sc-status\n2023-01-01 12:00:00 192.168.1.5 GET /index.html 200',
        "parser.generic.xml": '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4624</EventID><Channel>Security</Channel></System></Event>',
        "parser.cisco.asa_ios": 'Sep  5 14:00:02 fw %ASA-4-106023: Deny tcp src outside:203.0.113.88/61234 dst inside:10.0.0.1/445 by access-group "OUTSIDE-IN"',
        "parser.cloud.audit_flow": '{"eventVersion":"1.08","userIdentity":{"type":"IAMUser","userName":"alice"},"eventTime":"2026-09-05T14:00:00Z","eventSource":"s3.amazonaws.com","eventName":"GetObject","awsRegion":"us-east-1","sourceIPAddress":"198.51.100.1"}',
        "parser.fortinet.fortigate": 'date=2026-09-29 time=03:00:00 devname="FGT-CORP-01" devid="FGT60D12345" type="traffic" subtype="forward" level="warning" action="deny" srcip=10.10.10.25 dstip=198.51.100.40 srcport=54210 dstport=445 proto=6',
        "parser.linux.auditd": 'type=SYSCALL msg=audit(1620000000.123:456): arch=c000003e syscall=59 success=yes exit=0 a0=7ffd01 a1=7ffd02 a2=7ffd03 a3=7ffd04 items=2 ppid=1000 pid=1234 auid=1000 uid=0 gid=0 euid=0 comm="sudo" exe="/usr/bin/sudo" key="priv_esc"',
        "parser.opnsense.filterlog": 'filterlog: 4,16777216,,1000000103,vtnet0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,198.51.100.99,10.0.0.15,51234,445,0,S,12345678,,65535,,',
        "parser.paloalto.panos": '1,2026/09/10 14:40:00,001801000000,TRAFFIC,drop,1,2026/09/10 14:40:00,10.0.1.5,198.51.100.22,0.0.0.0,0.0.0.0,RULE-THREAT,test-user,,dns,vsys1,trust,untrust',
        "parser.snort.fast": '[**] [1:1000001:1] COMMUNITY WEB-ATTACK /etc/passwd access attempt [**] [Classification: Web Application Attack] [Priority: 1] 09/05-14:00:01.123456 198.51.100.15:49152 -> 10.0.0.10:80 TCP TTL:64 TOS:0x0 ID:12345 IpLen:20 DgmLen:450 [**]',
        "parser.suricata.eve": '{"timestamp":"2026-09-10T14:30:00Z","event_type":"alert","src_ip":"192.168.1.50","src_port":54321,"dest_ip":"10.0.0.1","dest_port":80,"proto":"TCP","alert":{"action":"blocked","gid":1,"signature_id":2010935,"signature":"ET MALWARE Suspicious Request"}}',
        "parser.web.access": '192.168.1.100 - admin [10/Oct/2026:13:55:36 +0000] "GET /api/v1/health HTTP/1.1" 200 1024 "https://example.com" "Mozilla/5.0"',
        "parser.zeek.telemetry": '1620000000.123\tC123456\t192.168.1.10\t49152\t10.0.0.1\t443\ttcp\tssl\t12.5\t1024\t8192\tSF\t-\t-\t0\tShADadfF\t10\t1500\t14\t8600\t-',
    }
    
    success_count = 0
    api_success_count = 0
    
    for pid in sorted(reg._parsers):
        parser = reg.get(pid)
        sample = sample_payloads.get(pid, "test payload")
        
        # Test 1: Direct Parser execution
        raw_b = sample.encode("utf-8")
        rec = FramedRecord(
            record_index=0,
            text=sample,
            raw_bytes=raw_b,
            start_byte_offset=0,
            end_byte_offset=len(raw_b),
            line_count=sample.count("\n") + 1,
        )
        res = parser.parse(rec)
        is_ok = res.status in (ParseStatus.PARSED, ParseStatus.PARTIAL)
        num_fields = len(res.extracted_fields)
        if is_ok:
            success_count += 1
            
        # Test 2: API REST endpoint /api/v1/parsers/test
        api_resp = client.post(
            "/api/v1/parsers/test",
            json={"raw_payload": sample, "parser_id": pid},
            headers={"X-Role": "operator"},
        )
        api_data = api_resp.json()
        api_ok = api_resp.status_code == 200 and api_data.get("parsed") is True
        if api_ok:
            api_success_count += 1
            
        print(f"[{'PASS' if is_ok else 'FAIL'}] {pid:30s} | Tier {parser.metadata.tier} | Direct: {num_fields:2d} fields | API: {'OK' if api_ok else 'ERR (' + str(api_data.get('error')) + ')'}")

    print(f"\nDirect Parse Success: {success_count}/{len(reg._parsers)}")
    print(f"API Parse Success:    {api_success_count}/{len(reg._parsers)}")

if __name__ == "__main__":
    run_audit()
