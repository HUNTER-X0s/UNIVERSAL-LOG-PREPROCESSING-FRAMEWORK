import sys
sys.path.extend([
    'apps/api', 'apps/worker', 'packages/contracts', 'packages/domain', 'packages/ingestion',
    'packages/normalization', 'packages/parser-runtime', 'packages/platform', 'packages/semantic',
    'packages/mapping', 'packages/onboarding', 'packages/ai', 'packages/runtime', 'packages/streaming',
    'packages/storage', 'packages/search', 'packages/delivery', 'packages/observability', 'packages/security',
    'packages/intelligence', 'packages/advanced_intelligence', 'packages/mission', 'packages/blockchain'
])

from ulpf_parser_runtime.framing import FramedRecord
from ulpf_parser_runtime.registry import create_default_registry

reg = create_default_registry()

test_cases = [
    ("parser.paloalto.panos", "1,2026/09/16 10:15:30,001234567890,TRAFFIC,drop,1,2026/09/16 10:15:30,198.51.100.25,203.0.113.10,0.0.0.0,0.0.0.0,Perimeter-Drop,,,ssh,vsys1,trust,untrust,ethernet1/1,ethernet1/2,default,1,1001,1,49152,22,0,0,0x0,tcp,deny,128,64,64,2,2026/09/16 10:15:30,0,any"),
    ("parser.fortinet.fortigate", 'date=2026-09-16 time=11:20:00 devname="FGT-CORP-01" devid="FGT60D4614041234" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.10.10.25 srcport=54321 srcintf="port1" dstip=198.51.100.40 dstport=443 dstintf="port2" proto=6 action="close" policyid=1 service="HTTPS" trandisp="snat" duration=12 sentbyte=1200 rcvdbyte=4500'),
    ("parser.suricata.eve", '{"timestamp":"2026-09-16T12:00:01.000123+0000","flow_id":192837465,"event_type":"alert","src_ip":"198.51.100.105","src_port":41230,"dest_ip":"10.0.1.20","dest_port":80,"proto":"TCP","alert":{"action":"blocked","gid":1,"signature_id":2010935,"rev":3,"signature":"ET SCAN Potential SSH Brute Force","category":"Attempted Information Leak","severity":2}}'),
    ("parser.generic.xml", '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"/><EventID>1</EventID><Version>5</Version><Level>4</Level><TimeCreated SystemTime="2026-09-13T17:15:35.405112Z"/><Computer>WIN-DC01.ad.ntro.internal</Computer></System><EventData><Data Name="RuleName">mitre_attack=T1059.001</Data><Data Name="UtcTime">2026-09-13 17:15:35.405</Data><Data Name="ProcessId">4104</Data><Data Name="Image">C:\\Windows\\System32\\powershell.exe</Data><Data Name="CommandLine">powershell.exe -nop -w hidden</Data><Data Name="User">NT AUTHORITY\\SYSTEM</Data></EventData></Event>'),
    ("parser.web.access", '203.0.113.88 - - [13/Sep/2026:17:15:45 +0000] "POST /api/v1/auth/login HTTP/1.1" 401 128 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"'),
    ("parser.linux.auditd", 'type=USER_AUTH msg=audit(1789319751.300:4921): pid=1921 uid=0 auid=1000 ses=4 msg=\'op=PAM:authentication grantors=pam_unix acct="admin" exe="/usr/sbin/sshd" hostname=203.0.113.88 addr=203.0.113.88 terminal=ssh res=failed\'')
]

for pid, raw in test_cases:
    parser = reg.get(pid)
    if not parser:
        print(f"FAILED: Parser {pid} not found")
        continue
    raw_bytes = raw.encode('utf-8')
    rec = FramedRecord(
        record_index=0,
        text=raw,
        raw_bytes=raw_bytes,
        start_byte_offset=0,
        end_byte_offset=len(raw_bytes),
        line_count=1,
    )
    res = parser.parse(rec)
    print(f"[{pid}] -> Status: {res.status.value} - Fields: {len(res.extracted_fields)}")
