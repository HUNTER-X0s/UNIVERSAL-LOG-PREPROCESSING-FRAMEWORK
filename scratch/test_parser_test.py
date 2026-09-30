import urllib.request
import json

samples = {
    "falco": ('{"time":"2026-09-16T13:50:00.000Z","rule":"PTRACE attached to process in container","priority":"WARNING","output":"Warning Detected ptrace PTRACE_ATTACH attempt","output_fields":{"container.id":"c10928a","k8s.pod.name":"ingress-pod","evt.type":"ptrace","proc.cmdline":"ptrace_inject -p 1"},"hostname":"node-k8s-01","source":"syscalls"}', "json_telemetry"),
    "crowdstrike": ('{"timestamp":"2026-09-16T13:40:00.000Z","event_simpleName":"ProcessRollup2","aid":"a1b2c3d4e5f67890abcdef1234567890","ComputerName":"CORP-SEC-01","UserName":"analyst","FileName":"powershell.exe","CommandLine":"powershell.exe -Enc SGVsbG8=","SHA256HashData":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","Severity":"High"}', "json_telemetry"),
    "gcp_audit": ('{"protoPayload":{"@type":"type.googleapis.com/google.cloud.audit.AuditLog","authenticationInfo":{"principalEmail":"admin@enterprise.com"},"serviceName":"compute.googleapis.com","methodName":"v1.compute.instances.delete","resourceName":"projects/prod-cluster/zones/us-central1-a/instances/vm-db-primary"},"insertId":"gcp_audit_019283","resource":{"type":"gce_instance","labels":{"instance_id":"918237192"}},"timestamp":"2026-09-16T13:15:00.000000Z","severity":"NOTICE"}', "json_telemetry"),
    "aws_cloudtrail": ('{"eventVersion":"1.08","userIdentity":{"type":"IAMUser","principalId":"AIDASAMPLEUSER","arn":"arn:aws:iam::123456789012:user/Alice","accountId":"123456789012","userName":"Alice"},"eventTime":"2026-09-16T12:00:00Z","eventSource":"iam.amazonaws.com","eventName":"CreateAccessKey","awsRegion":"us-east-1","sourceIPAddress":"198.51.100.50","userAgent":"aws-cli/2.15.0"}', "cloud_audit"),
    "cicids": ('172.16.0.1-192.168.10.50-49152-80-6,172.16.0.1,49152,192.168.10.50,80,6,07/07/2017 09:15:22 AM,987654,120,4,14400,0,120,120,120.0,0.0,0,0,0.0,0.0,14580.0,125.5,8230.4,1200.0,12500.0,5.0,8230.4,1200.0,12500.0,5.0,246913.5,50000.0,300000.0,1000.0,0,0,0,0,0,1,0,0,0,0,0,0,116.1,29200,-1,120,32,DoS Hulk', "csv_telemetry"),
    "unsw": ('175.45.176.2,53644,149.171.126.15,80,tcp,FIN,0.580188,8928,320,62,252,5,1,http,116669.0,3860.8,14,6,255,255,2429729167,713410981,638,53,1,0,17.02,23.5,1421927430,1421927431,44.62,116.03,0.07,0.05,0.02,0,1,1,0,0,3,1,1,2,1,1,1,Exploits,1', "csv_telemetry"),
    "auditd": ('type=USER_AUTH msg=audit(1789319751.300:4921): pid=1921 uid=0 auid=1000 ses=4 msg=\'op=PAM:authentication grantors=pam_unix acct="admin" exe="/usr/sbin/sshd" hostname=203.0.113.88 addr=203.0.113.88 terminal=ssh res=failed\'', "linux_auditd")
}

for name, (raw, parser_id) in samples.items():
    req = urllib.request.Request(
        'http://127.0.0.1:8000/api/v1/parsers/test',
        data=json.dumps({"raw_payload": raw, "source_id": parser_id, "parser_id": parser_id}).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    with urllib.request.urlopen(req) as resp:
        res = json.loads(resp.read().decode('utf-8'))
        print(f"[{name.upper()}] HTTP {resp.status} - Parsed: {res.get('parsed')} - Fields: {len(res.get('fields', {}))} - Residue: {len(res.get('unknown_fields', {}))}")
