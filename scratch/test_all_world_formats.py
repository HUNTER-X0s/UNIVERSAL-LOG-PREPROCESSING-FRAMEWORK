import urllib.request
import json
import sys

samples = {
    "JSON (AWS CloudTrail)": {
        "format": "JSON",
        "raw": json.dumps({
            "eventVersion": "1.08",
            "userIdentity": {"type": "IAMUser", "userName": "alice_admin"},
            "eventTime": "2026-09-30T00:15:30Z",
            "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin",
            "sourceIPAddress": "198.51.100.25",
            "userAgent": "Mozilla/5.0",
            "responseElements": {"ConsoleLogin": "Success"}
        })
    },
    "JSON (Suricata EVE IDS)": {
        "format": "JSON",
        "raw": json.dumps({
            "timestamp": "2026-09-30T00:20:10.123456+0000",
            "flow_id": 987654321012,
            "event_type": "alert",
            "src_ip": "192.168.1.45",
            "src_port": 53210,
            "dest_ip": "198.51.100.99",
            "dest_port": 443,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "signature": "ET MALWARE C2 Traffic Observed",
                "category": "A Network Trojan was detected",
                "severity": 1
            }
        })
    },
    "CSV (Palo Alto PAN-OS)": {
        "format": "CSV",
        "raw": "1,2026/09/30 00:12:45,001201000456,TRAFFIC,drop,2304,2026/09/30 00:12:45,192.168.1.105,203.0.113.88,0.0.0.0,0.0.0.0,Block-Bad-Actors,,,ssl,vsys1,trust,untrust,ethernet1/2,ethernet1/1,logforwarder-prod,2026/09/30 00:12:45,987654,1,54321,443,0,0,0x0,tcp,deny,1520,0,0,14,2026/09/30 00:12:40,5,any,0,0,0x0,US,192.168.0.0-192.168.255.255,203.0.113.0-203.0.113.255,0,14,0,drop,0,0,0,0,,PA-5220,from-policy"
    },
    "Syslog RFC 5424": {
        "format": "Syslog",
        "raw": "<165>1 2026-09-30T00:12:45.123Z secure-gw01.corp.local audit-daemon 4120 ID47 [security@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] User authentication successful user=sarah_admin"
    },
    "Syslog RFC 3164 (BSD)": {
        "format": "Syslog",
        "raw": "<34>Sep 30 00:12:45 edge-router01 sshd[28451]: Failed password for invalid user admin from 198.51.100.77 port 48212 ssh2"
    },
    "Syslog (Cisco ASA)": {
        "format": "Syslog",
        "raw": "%ASA-6-302013: Built inbound TCP connection 987654321 for outside:198.51.100.80/443 (198.51.100.80/443) to inside:10.0.1.25/51234 (10.0.1.25/51234)"
    },
    "XML (Windows EVTX 4624)": {
        "format": "XML",
        "raw": """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>4624</EventID>
    <Level>0</Level>
    <TimeCreated SystemTime="2026-09-30T00:12:45.000Z" />
    <Computer>DC-PRIMARY.corp.local</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="TargetUserName">svc_backup</Data>
    <Data Name="IpAddress">10.0.2.14</Data>
    <Data Name="IpPort">5985</Data>
  </EventData>
</Event>"""
    },
    "Key-Value (Fortinet FortiGate)": {
        "format": "KV",
        "raw": 'date=2026-09-30 time=00:12:45 devname="FGT-60E" devid="FGT60E4Q16000000" eventtime=1727655165 type="traffic" subtype="forward" level="notice" vd="root" srcip=192.168.1.50 srcport=54210 srcintf="port1" dstip=198.51.100.20 dstport=443 dstintf="port2" proto=6 action="accept" policyid=4 service="HTTPS" app="Google.Search"'
    },
    "Key-Value (Linux Auditd)": {
        "format": "KV",
        "raw": 'type=USER_AUTH msg=audit(1727655165.789:4521): pid=1240 uid=0 auid=1000 ses=2 msg=\'op=PAM:authentication grantors=pam_unix acct="deploy" exe="/usr/bin/sudo" hostname=? addr=192.168.1.75 terminal=/dev/pts/1 res=success\''
    },
    "CEF (ArcSight / Check Point)": {
        "format": "CEF",
        "raw": "CEF:0|Check Point|VPN-1 & FireWall-1|CheckPoint|Drop|Drop|High|src=198.51.100.88 dst=10.0.1.10 spt=48200 dpt=22 proto=6 act=drop msg=Connection rejected by policy rule=14"
    },
    "LEEF (IBM QRadar LEEF 2.0)": {
        "format": "LEEF",
        "raw": "LEEF:2.0|IBM|SecurityAccessManager|10.0|AccessGranted|devTimeFormat=yyyy-MM-dd'T'HH:mm:ss.SSSZ\tdevTime=2026-09-30T00:12:45.123Z\tsrc=192.168.1.99\tdst=10.0.0.5\tsrcPort=52110\tdstPort=443\tproto=TCP\tusrName=robert_sec\tsev=5"
    },
    "W3C / Web Access (Nginx)": {
        "format": "W3C",
        "raw": '198.51.100.33 - admin [30/Sep/2026:00:12:45 +0000] "POST /api/v1/telemetry/ingest HTTP/1.1" 200 4820 "https://dashboard.corp.local" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
    },
    "Snort Fast Alert": {
        "format": "Snort",
        "raw": "[**] [1:2001219:19] ET MALWARE Suspicious User-Agent [**] [Classification: A Network Trojan was detected] [Priority: 1] 09/30-00:25:14.123456 192.168.1.10:49200 -> 198.51.100.5:80 TCP TTL:64 TOS:0x0 ID:1420 IpLen:20 DgmLen:520"
    },
    "Zeek TSV Connection Log": {
        "format": "Zeek",
        "raw": "1727655900.123456\tCuZ1234567\t192.168.1.100\t54321\t93.184.216.34\t443\ttcp\tssl\t1.452\t1520\t4820\tSF\tT\tF\t0\tShADadFf\t12\t2144\t15\t5620\t(empty)"
    },
    "WinEventLog Plain Text": {
        "format": "WinEventLog",
        "raw": """Log Name: Security
Event ID: 4625
Computer: DC01.corp.local
Account Name: admin_corp
Logon Type: 3
Source Network Address: 10.0.4.15
Source Port: 52140
Status: 0xC000006D"""
    },
    "Grok / Enterprise Application Log": {
        "format": "Grok",
        "raw": "2026-09-30 00:25:14.892 [http-nio-8080-exec-4] WARN com.security.auth.AuthenticationProvider - Failed login attempt for user admin from IP 198.51.100.42 reason=INVALID_CREDENTIALS duration_ms=45"
    },
    "YAML (Kubernetes Audit Event)": {
        "format": "YAML",
        "raw": """apiVersion: audit.k8s.io/v1
kind: Event
level: Metadata
stage: ResponseComplete
verb: create
user: cluster-admin
sourceIP: 192.168.1.15
responseStatus: 201"""
    },
    "NetFlow / IPFIX Flow Record": {
        "format": "NetFlow",
        "raw": "2026-09-30 00:15:02.102 1.240 TCP 192.168.1.100:51234 -> 10.0.0.5:443 14 8420 1"
    }
}

print(f"Total Test Formats: {len(samples)}")
success_count = 0

for name, payload in samples.items():
    body = json.dumps({"raw_payload": payload["raw"]}).encode("utf-8")
    req = urllib.request.Request("http://127.0.0.1:8000/api/v1/parsers/test", data=body, headers={"Content-Type": "application/json", "X-Role": "platform-admin"})
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            status = data.get("status")
            fcount = len(data.get("fields", {}))
            parser_id = data.get("parser_id")
            fmt = data.get("format")
            if status in ("parsed", "partial") and fcount > 0:
                print(f"[OK] {name:<35} -> fmt: {fmt:<15} fields: {fcount:<3} parser: {parser_id}")
                success_count += 1
            else:
                print(f"[FAIL] {name:<35} -> status: {status} fields: {fcount}")
    except Exception as exc:
        print(f"[ERROR] {name:<35} -> {exc}")

print(f"\nFinal Result: {success_count}/{len(samples)} formats parsed successfully!")
