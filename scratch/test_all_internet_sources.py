import json
import urllib.request
import urllib.error

# All 28 enterprise internet log sources from IngestConsole
TEST_SOURCES = [
    {
        "id": "arcsight_cef",
        "name": "Micro Focus ArcSight CEF",
        "sample": "CEF:0|Palo Alto Networks|PAN-OS|10.2.0|THREAT|vulnerability|8|src=203.0.113.84 dst=10.0.1.20 spt=51294 dpt=80 proto=tcp act=block cs1Label=Rule cs1=Exploit-Shield-Deny msg=Apache Log4j RCE Attempt (CVE-2021-44228) cnt=1"
    },
    {
        "id": "qradar_leef",
        "name": "IBM QRadar LEEF 2.0",
        "sample": "LEEF:2.0|Fortinet|FortiGate|7.2.4|IPS_ALERT|devTime=2026-09-29T02:00:00Z\tsrc=198.51.100.200\tdst=10.0.2.40\tsrcPort=41920\tdstPort=445\tproto=TCP\taction=Drop\tattack=MS17-010.EternalBlue.SMB\tseverity=5"
    },
    {
        "id": "syslog_rfc5424",
        "name": "IETF Syslog Protocol (RFC 5424)",
        "sample": '<165>1 2026-09-29T02:00:00.000Z edge-gw01.corp security 1042 ID47 [meta@32473 session="84192" user="secadmin" reason="mfa_timeout"] Security session terminated due to inactivity policy.'
    },
    {
        "id": "syslog_rfc3164",
        "name": "BSD Unix Syslog (RFC 3164)",
        "sample": "<13>Sep 29 02:00:00 debian-srv01 sshd[14295]: Failed password for invalid user admin from 198.51.100.77 port 38412 ssh2"
    },
    {
        "id": "opentelemetry",
        "name": "OpenTelemetry (OTel OTLP)",
        "sample": '{"resourceLogs":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"payment-gateway"}},{"key":"host.name","value":{"stringValue":"ip-10-0-1-12.ec2.internal"}}]},"scopeLogs":[{"scope":{"name":"com.enterprise.security.auth"},"logRecords":[{"timeUnixNano":"1727575200000000000","severityNumber":17,"severityText":"ERROR","body":{"stringValue":"Authentication token signature verification failed: expired public key"},"attributes":[{"key":"user.id","value":{"stringValue":"usr-88192"}},{"key":"client.ip","value":{"stringValue":"203.0.113.88"}}]}]}]}]}'
    },
    {
        "id": "splunk_hec",
        "name": "Splunk HEC",
        "sample": '{"time":1727575200.123,"host":"fin-db-01.internal","source":"audit_trail","sourcetype":"db_audit","index":"security_compliance","event":{"action":"SELECT","table":"customer_pci_tokens","rows_returned":15000,"user":"app_svc_payment","status":"SUCCESS","duration_ms":14.2}}'
    },
    {
        "id": "palo_alto",
        "name": "Palo Alto PAN-OS CSV",
        "sample": "1,2026/09/29 02:00:00,001801000001,TRAFFIC,drop,2304,2026/09/29 02:00:00,192.168.1.100,203.0.113.15,0.0.0.0,0.0.0.0,RULE-DENY-EXTERNAL,,,ping,vsys1,untrust,trust,ethernet1/1,ethernet1/2,Forward-All,2026/09/29 02:00:00,0,1,60,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0"
    },
    {
        "id": "fortinet",
        "name": "Fortinet FortiGate UTM",
        "sample": 'date=2026-09-29 time=02:00:00 devname="FGT-CORP-EDGE01" devid="FGT60E4Q16000000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.0.1.45 srcport=54122 srcintf="port1" dstip=198.51.100.22 dstport=443 dstintf="port2" policyid=1 sessionid=1024 proto=6 action="deny"'
    },
    {
        "id": "cisco_asa",
        "name": "Cisco ASA Syslog",
        "sample": '%ASA-4-106023: Deny tcp src outside:203.0.113.50/49152 dst inside:10.0.2.15/443 by access-group "OUTSIDE-IN" [0x8401, 0x0]'
    },
    {
        "id": "suricata",
        "name": "Suricata EVE-JSON NIDS",
        "sample": '{"timestamp":"2026-09-29T02:00:00.123456+0000","flow_id":918237192837,"in_iface":"eth0","event_type":"alert","src_ip":"198.51.100.200","src_port":44123,"dest_ip":"10.0.1.10","dest_port":80,"proto":"TCP","alert":{"action":"blocked","gid":1,"signature_id":2014757,"rev":3,"signature":"ET EXPLOIT Apache Struts2 S2-045 RCE (CVE-2017-5638)","category":"Attempted Administrator Privilege Gain","severity":1}}'
    },
    {
        "id": "zeek",
        "name": "Zeek Network Security Monitor",
        "sample": "1727575200.100\tCJq8K92L1b8v8N3a2\t198.51.100.15\t51920\t10.0.1.50\t53\tudp\tdns\t0.015\t120\t240\tSF\t-\t-\t0\tDd\t1\t148\t1\t268\t(empty)"
    },
    {
        "id": "snort",
        "name": "Snort 3 Fast Log",
        "sample": '[**] [1:1000001:2] COMMUNITY WEB-MISC Cross Site Scripting attempt [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 198.51.100.99:54120 -> 10.0.1.80:80'
    },
    {
        "id": "crowdstrike",
        "name": "CrowdStrike Falcon FDR JSON",
        "sample": '{"metadata":{"customerIDString":"corp-cust-99","offset":1049281},"event":{"ProcessStartTime":1727575200,"TargetProcessId":4812,"ParentProcessId":1024,"CommandLine":"powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=","FileName":"powershell.exe","ComputerName":"HOST-FIN-01","UserName":"admin.sec"}}'
    },
    {
        "id": "sysmon",
        "name": "Microsoft Sysmon XML",
        "sample": '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID><TimeCreated SystemTime="2026-09-29T02:00:00.000Z"/><Computer>WIN-SEC-DC01.corp.internal</Computer></System><EventData><Data Name="UtcTime">2026-09-29 02:00:00.000</Data><Data Name="ProcessGuid">{00112233-4455-6677-8899-aabbccddeeff}</Data><Data Name="ProcessId">3428</Data><Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data><Data Name="CommandLine">cmd.exe /c whoami /priv</Data><Data Name="User">NT AUTHORITY\\SYSTEM</Data></EventData></Event>'
    },
    {
        "id": "windows_security",
        "name": "Windows Security EventLog 4624",
        "sample": '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4624</EventID><TimeCreated SystemTime="2026-09-29T02:00:00.000Z"/><Computer>DC-SRV-01.corp.internal</Computer></System><EventData><Data Name="TargetUserName">secops.lead</Data><Data Name="TargetDomainName">CORP</Data><Data Name="LogonType">10</Data><Data Name="IpAddress">198.51.100.77</Data><Data Name="IpPort">58412</Data></EventData></Event>'
    },
    {
        "id": "linux_auditd",
        "name": "Linux Audit Subsystem (auditd)",
        "sample": 'type=USER_AUTH msg=audit(1727575200.450:182): pid=14295 uid=0 auid=1001 ses=42 msg="op=PAM:authentication grantors=pam_unix,pam_permit acct=\"secadmin\" exe=\"/usr/bin/sudo\" hostname=? addr=198.51.100.25 terminal=/dev/pts/1 res=success"'
    },
    {
        "id": "aws_cloudtrail",
        "name": "AWS CloudTrail JSON",
        "sample": '{"eventVersion":"1.08","userIdentity":{"type":"IAMUser","principalId":"AIDASAMPLEUSER12345","arn":"arn:aws:iam::123456789012:user/Alice","accountId":"123456789012","userName":"Alice"},"eventTime":"2026-09-29T02:00:00Z","eventSource":"s3.amazonaws.com","eventName":"GetObject","awsRegion":"ap-south-1","sourceIPAddress":"203.0.113.88","userAgent":"aws-cli/2.15.0","requestParameters":{"bucketName":"corp-confidential-vault","key":"fin-q3-audit.enc"}}'
    },
    {
        "id": "gcp_audit",
        "name": "Google Cloud Audit Log JSON",
        "sample": '{"protoPayload":{"@type":"type.googleapis.com/google.cloud.audit.AuditLog","serviceName":"compute.googleapis.com","methodName":"v1.compute.firewalls.delete","resourceName":"projects/corp-prod/global/firewalls/default-allow-internal","callerIp":"198.51.100.33"},"severity":"NOTICE","timestamp":"2026-09-29T02:00:00.000Z"}'
    },
    {
        "id": "k8s_audit",
        "name": "Kubernetes Audit Log JSON",
        "sample": '{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"RequestResponse","stage":"ResponseComplete","requestURI":"/api/v1/namespaces/kube-system/secrets/core-signing-key","verb":"get","user":{"username":"cluster-admin-svc","groups":["system:masters"]},"sourceIPs":["10.244.1.1"],"userAgent":"kubectl/v1.30.0","responseStatus":{"code":200}}'
    },
    {
        "id": "okta",
        "name": "Okta System Log JSON",
        "sample": '{"uuid":"target-uuid-99","published":"2026-09-29T02:00:00.000Z","eventType":"user.authentication.auth_via_mfa","displayMessage":"Authenticate user via MFA token","actor":{"id":"usr-91823","type":"User","alternateId":"analyst@ulpf.internal","displayName":"SOC Analyst Lead"},"client":{"ipAddress":"203.0.113.15","geographicalContext":{"city":"New Delhi","country":"India"}},"outcome":{"result":"SUCCESS"}}'
    },
    {
        "id": "nginx",
        "name": "Nginx Combined Access Log",
        "sample": '198.51.100.99 - secadmin [29/Sep/2026:02:00:00 +0000] "POST /api/v1/admin/vault/keys HTTP/1.1" 200 482 "https://console.ulpf.internal/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
    },
    {
        "id": "apache",
        "name": "Apache Common Access Log",
        "sample": '203.0.113.10 - frank [29/Sep/2026:02:00:00 +0000] "GET /documents/report.pdf HTTP/1.1" 200 1048576'
    },
    {
        "id": "pfsense",
        "name": "pfSense Filterlog CSV",
        "sample": "filterlog: 4,,,1000000103,igb0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,198.51.100.22,10.0.1.50,54122,22,0,S,10240,0,,mss;sackOK;TS"
    }
]

print(f"Testing {len(TEST_SOURCES)} Enterprise Internet Sources against ULPF Backend...")
print("=" * 80)

passed = 0
failed = 0

for item in TEST_SOURCES:
    src_id = item["id"]
    name = item["name"]
    sample = item["sample"]

    # 1. Test /api/v1/parsers/test (Preview parsing)
    test_req = urllib.request.Request(
        "http://localhost:8000/api/v1/parsers/test",
        data=json.dumps({"raw_payload": sample, "source_id": src_id}).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Role": "platform-admin"}
    )
    
    # 2. Test /api/v1/events/ingest (Full end-to-end ingestion pipeline)
    ingest_req = urllib.request.Request(
        "http://localhost:8000/api/v1/events/ingest",
        data=json.dumps({"raw_payload": sample, "source_id": src_id, "format": src_id}).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Role": "platform-admin"}
    )

    try:
        with urllib.request.urlopen(test_req, timeout=2.0) as resp:
            test_res = json.loads(resp.read().decode())
        
        with urllib.request.urlopen(ingest_req, timeout=2.0) as resp2:
            ingest_res = json.loads(resp2.read().decode())

        is_parsed = test_res.get("parsed", False)
        fields_cnt = len(test_res.get("fields", {}))
        ingest_state = ingest_res.get("state")
        event_id = ingest_res.get("event_id")

        if is_parsed and fields_cnt > 0 and ingest_state in ("ACKNOWLEDGED", "CAPTURED"):
            passed += 1
            print(f"  [PASS] {name} ({src_id}): Format={test_res.get('format')}, Fields={fields_cnt}, IngestState={ingest_state}", flush=True)
        else:
            failed += 1
            print(f"  [WARN] {name} ({src_id}): Parsed={is_parsed}, Fields={fields_cnt}, IngestState={ingest_state}", flush=True)

    except Exception as e:
        failed += 1
        print(f"  [FAIL] {name} ({src_id}): Error={e}", flush=True)

print("=" * 80, flush=True)
print(f"Results: {passed} PASSED, {failed} FAILED out of {len(TEST_SOURCES)} sources.", flush=True)
