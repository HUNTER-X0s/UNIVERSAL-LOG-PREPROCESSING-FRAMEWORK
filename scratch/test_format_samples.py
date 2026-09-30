import json
from fastapi.testclient import TestClient
from ulpf_api.app import app
from ulpf_parser_runtime.registry import create_default_registry
from ulpf_parser_runtime.framing import FramedRecord
from ulpf_parser_runtime.models import ParseStatus

def test_samples():
    reg = create_default_registry()
    client = TestClient(app)
    
    # We will test generic CSV, KV, Syslog, CEF, LEEF, W3C, XML, FortiGate, etc.
    test_cases = [
        ("parser.generic.csv", "timestamp,src_ip,dst_ip,dst_port,protocol,action\n2026-09-29T03:00:00Z,192.168.1.100,10.0.0.1,443,TCP,ALLOW"),
        ("parser.generic.csv", "user\taction\tresult\tsrc_ip\tduration_ms\nadmin\tauth_token_grant\tsuccess\t198.51.100.22\t14.2"),
        ("parser.generic.keyvalue", 'time="2026-09-29T03:00:00Z" level=warn msg="Failed login attempt" user=sec-admin src_ip=198.51.100.42 reason="invalid_token"'),
        ("parser.generic.keyvalue", 'action=deny src=198.51.100.99 dst=10.0.1.10 sport=51234 dport=22 proto=tcp devname="EDGE-GW" policy_id=14'),
        ("parser.syslog.rfc3164", "<34>Oct 11 22:14:15 edge-router-01 su[4821]: 'su root' failed for sec-analyst on /dev/pts/8"),
        ("parser.syslog.rfc5424", '<165>1 2026-09-29T03:00:00.003Z sec-host.corp app 8710 ID47 [exampleSDID@32473 eventSource="SecurityEngine" eventID="1011" severity="HIGH"] Threat mitigation triggered'),
        ("parser.generic.cef", "CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232 dpt=443 act=block"),
        ("parser.generic.leef", "LEEF:1.0|Microsoft|MSExchange|2013|AuthSuccess|src=192.168.1.1\tdst=10.0.0.2\tusr=admin\tstatus=ALLOW"),
        ("parser.generic.w3c", "#Fields: date time c-ip cs-method cs-uri-stem sc-status\n2023-01-01 12:00:00 192.168.1.5 GET /index.html 200"),
        ("parser.generic.xml", '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4624</EventID><Channel>Security</Channel></System></Event>'),
        ("parser.fortinet.fortigate", 'date=2026-09-29 time=03:00:00 devname="FGT-CORP-01" devid="FGT60D12345" type="traffic" subtype="forward" level="warning" action="deny" srcip=10.10.10.25 dstip=198.51.100.40 srcport=54210 dstport=445 proto=6'),
        ("parser.opnsense.filterlog", "filterlog: 4,16777216,,1000000103,vtnet0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,198.51.100.99,10.0.0.15,51234,445,0,S,12345678,,65535,,"),
        ("parser.snort.fast", "[**] [1:1000001:1] COMMUNITY WEB-ATTACK /etc/passwd access attempt [**] [Classification: Web Application Attack] [Priority: 1] 09/05-14:00:01.123456 198.51.100.15:49152 -> 10.0.0.10:80 TCP TTL:64 TOS:0x0 ID:12345 IpLen:20 DgmLen:450 [**]"),
        ("parser.web.access", '192.168.1.100 - admin [10/Oct/2026:13:55:36 +0000] "GET /api/v1/health HTTP/1.1" 200 1024 "https://example.com" "Mozilla/5.0"'),
        ("parser.zeek.telemetry", "1620000000.123\tC123456\t192.168.1.10\t49152\t10.0.0.1\t443\ttcp\tssl\t12.5\t1024\t8192\tSF\t-\t-\t0\tShADadfF\t10\t1500\t14\t8600\t-"),
        ("parser.cloud.audit_flow", '{"eventVersion":"1.08","userIdentity":{"type":"IAMUser","userName":"alice"},"eventTime":"2026-09-05T14:00:00Z","eventSource":"s3.amazonaws.com","eventName":"GetObject","awsRegion":"us-east-1","sourceIPAddress":"198.51.100.1"}'),
        ("parser.cloud.audit_flow", "2 123456789010 eni-1235b8ca123456789 198.51.100.10 10.0.0.5 49152 443 6 20 8400 1620000000 1620000060 ACCEPT OK"),
        ("parser.linux.auditd", 'type=SYSCALL msg=audit(1620000000.123:456): arch=c000003e syscall=59 success=yes exit=0 a0=7ffd01 a1=7ffd02 a2=7ffd03 a3=7ffd04 items=2 ppid=1000 pid=1234 auid=1000 uid=0 gid=0 euid=0 comm="sudo" exe="/usr/bin/sudo" key="priv_esc"'),
    ]
    
    passed = 0
    for pid, sample in test_cases:
        resp = client.post("/api/v1/parsers/test", json={"raw_payload": sample, "parser_id": pid}, headers={"X-Role": "operator"})
        data = resp.json()
        ok = resp.status_code == 200 and data.get("parsed") is True
        if ok:
            passed += 1
        print(f"[{'PASS' if ok else 'FAIL'}] {pid:25s} | status={data.get('status')} | fields={len(data.get('fields', {}))}")
        
    print(f"\nAll Samples Test: {passed}/{len(test_cases)} Passed!")

if __name__ == "__main__":
    test_samples()
