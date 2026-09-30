import re
import yaml
import json
from ulpf_parser_runtime.framing import FramedRecord
from ulpf_parser_runtime.registry import create_default_registry

reg = create_default_registry()

test_cases = {
    "snort_fast": "[**] [1:2001219:19] ET MALWARE Suspicious User-Agent [**] [Classification: A Network Trojan was detected] [Priority: 1] 09/30-00:25:14.123456 192.168.1.10:49200 -> 198.51.100.5:80 TCP TTL:64 TOS:0x0 ID:1420 IpLen:20 DgmLen:520",
    "zeek_conn": "1727655900.123456\tCuZ1234567\t192.168.1.100\t54321\t93.184.216.34\t443\ttcp\tssl\t1.452\t1520\t4820\tSF\tT\tF\t0\tShADadFf\t12\t2144\t15\t5620\t(empty)",
    "winevent_text": """Log Name: Security
Event ID: 4625
Computer: DC01.corp.local
Account Name: admin_corp
Logon Type: 3
Source Network Address: 10.0.4.15
Source Port: 52140""",
    "grok_app": "2026-09-30 00:25:14.892 [http-nio-8080-exec-4] WARN com.security.auth.AuthenticationProvider - Failed login attempt for user admin from IP 198.51.100.42 reason=INVALID_CREDENTIALS",
    "yaml_k8s": """apiVersion: audit.k8s.io/v1
kind: Event
level: Metadata
stage: ResponseComplete
verb: create
user: cluster-admin
sourceIP: 192.168.1.15
responseStatus: 201""",
    "netflow_text": "2026-09-30 00:15:02.102 1.240 TCP 192.168.1.100:51234 -> 10.0.0.5:443 14 8420 1",
}

print("Testing specialized parsers:")
snort_parser = reg.get("parser.snort.fast")
rec_snort = FramedRecord(record_index=0, text=test_cases["snort_fast"], raw_bytes=test_cases["snort_fast"].encode(), start_byte_offset=0, end_byte_offset=len(test_cases["snort_fast"]), line_count=1)
res_snort = snort_parser.parse(rec_snort)
print("Snort parsed fields:", len(res_snort.extracted_fields), {k: getattr(v, "value", v) for k, v in res_snort.extracted_fields.items()})

zeek_parser = reg.get("parser.zeek.telemetry")
rec_zeek = FramedRecord(record_index=0, text=test_cases["zeek_conn"], raw_bytes=test_cases["zeek_conn"].encode(), start_byte_offset=0, end_byte_offset=len(test_cases["zeek_conn"]), line_count=1)
res_zeek = zeek_parser.parse(rec_zeek)
print("Zeek parsed fields:", len(res_zeek.extracted_fields), {k: getattr(v, "value", v) for k, v in res_zeek.extracted_fields.items()})
