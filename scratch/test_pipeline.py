from ulpf_parser_runtime.detection.format_detector import FormatDetector
from ulpf_parser_runtime.framing import FramedRecord, RecordFramer
from ulpf_parser_runtime.parsers import (
    CefParser, LeefParser, SyslogRFC5424Parser, SyslogRFC3164Parser,
    GenericJsonParser, KeyValueParser, GenericCsvParser, XmlParser
)
from ulpf_normalization.canonical import CanonicalEventBuilder
from ulpf_semantic.service import SemanticService

samples = [
    ("CEF", "CEF:0|Palo Alto Networks|PAN-OS|10.2.0|THREAT|vulnerability|8|src=203.0.113.84 dst=10.0.1.20 spt=51294 dpt=80 proto=tcp act=block cs1Label=Rule cs1=Exploit-Shield-Deny msg=Apache Log4j RCE Attempt (CVE-2021-44228) cnt=1"),
    ("LEEF", "LEEF:2.0|Fortinet|FortiGate|7.2.4|IPS_ALERT|devTime=2026-09-29T02:00:00Z\tsrc=198.51.100.200\tdst=10.0.2.40\tsrcPort=41920\tdstPort=445\tproto=TCP\taction=Drop\tattack=MS17-010.EternalBlue.SMB\tseverity=5"),
    ("RFC5424", '<165>1 2026-09-29T02:00:00.000Z edge-gw01.corp security 1042 ID47 [meta@32473 session="84192" user="secadmin"] Security session terminated'),
    ("RFC3164", "<13>Sep 29 02:00:00 debian-srv01 sshd[14295]: Failed password for invalid user admin from 198.51.100.77 port 38412 ssh2"),
    ("JSON", '{"timestamp":"2026-09-29T02:00:00Z","src_ip":"192.168.1.50","dest_ip":"10.0.0.1","action":"allow","proto":"TCP"}'),
    ("KV", 'date=2026-09-29 time=02:00:00 devname="FGT" srcip=10.0.1.45 dstip=198.51.100.22 action="deny"'),
    ("XML", '<Event><System><EventID>4624</EventID><TimeCreated SystemTime="2026-09-29T02:00:00Z"/></System><EventData><Data Name="TargetUserName">secadmin</Data><Data Name="IpAddress">10.0.1.100</Data></EventData></Event>'),
    ("CSV", "1,2026/09/29 02:00:00,001801000001,TRAFFIC,drop,2304,2026/09/29 02:00:00,192.168.1.100,203.0.113.15,0.0.0.0,0.0.0.0,RULE-DENY-EXTERNAL,,,ping,vsys1,untrust,trust,ethernet1/1,ethernet1/2,Forward-All,2026/09/29 02:00:00,0,1,60,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0")
]

builder = CanonicalEventBuilder()
semantic_svc = SemanticService()
detector = FormatDetector()

for name, s in samples:
    payload_b = s.encode("utf-8")
    best, candidates, is_amb = detector.detect(s)
    fmt = best.format_name
    print(f"[{name}] Format detected: {fmt} (confidence: {best.confidence:.2f})")
    
    parser = None
    if fmt == "cef":
        parser = CefParser()
    elif fmt == "leef":
        parser = LeefParser()
    elif fmt == "syslog_rfc5424":
        parser = SyslogRFC5424Parser()
    elif fmt == "syslog_rfc3164":
        parser = SyslogRFC3164Parser()
    elif fmt == "json":
        parser = GenericJsonParser()
    elif fmt == "kv":
        parser = KeyValueParser()
    elif fmt == "xml":
        parser = XmlParser()
    elif fmt == "csv":
        parser = GenericCsvParser()

    if parser:
        record = FramedRecord(
            record_index=0,
            text=s,
            raw_bytes=payload_b,
            start_byte_offset=0,
            end_byte_offset=len(payload_b),
            line_count=1,
        )
        parse_res = parser.parse(record)
        print(f"  Parse status: {parse_res.status.value}, Extracted fields: {len(parse_res.extracted_fields)}")
        
        uce = builder.build_uce(parse_res, raw_payload_bytes=payload_b)
        print(f"  UCE event_id: {uce['event_id']}, category: {uce['event']['category']}, action: {uce['event']['action']}")
        
        sem = semantic_svc.process_uce(uce, project=True)
        print(f"  Semantic ID: {sem.semantic_event_id}, Projections: {list(sem.projections.keys())}")
    else:
        print(f"  No parser mapped for {fmt}")
    print()
