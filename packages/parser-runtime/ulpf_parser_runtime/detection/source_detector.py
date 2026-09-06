"""Deterministic source, vendor, and product detection engine for ULPF Phase 3.

Adheres to:
- Spec §10: Source / Vendor / Product Detection (decoupled from format, explainable evidence)
- Spec §15: Phase-3 Initial Parser Coverage (Tier B & Tier C sources)
"""

import json
import re

from ulpf_parser_runtime.models import DetectedSource

# Precompiled regexes for source signatures
RE_CISCO_ASA = re.compile(r"%(?:ASA|FTD)-\d+-\d+:")
RE_CISCO_IOS = re.compile(r"%(?:LINK|LINEPROTO|SYS|OSPF|BGP)-\d+-[A-Z0-9_]+:")
RE_FORTINET = re.compile(r"\b(?:devname=[^\s]+|type=(?:traffic|utm|event|virus|webfilter))\b")
RE_PANOS_CSV = re.compile(
    r",\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2},[^,]+,(?:TRAFFIC|THREAT|SYSTEM|CONFIG),"
)
RE_JUNIPER_SRX = re.compile(r"\bRT_FLOW(?:_SESSION_CREATE|_SESSION_CLOSE)?\b")
RE_CHECKPOINT = re.compile(r"\b(?:fw1:|product=VPN-1|Check Point)\b")
RE_OPNSENSE = re.compile(r"\bfilterlog(?::\s*|,)")
RE_SNORT = re.compile(r"^\[\*\*\]\s+\[\d+:\d+:\d+\]")
RE_HAPROXY = re.compile(r"\bhaproxy\[\d+\]:\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+\s+\[")
RE_AUDITD = re.compile(r"\btype=[A-Z_]+\s+msg=audit\(\d+\.\d+:\d+\):")
RE_MYSQL_SLOW = re.compile(r"^#\s*Time:\s*\d{6}\s+|^#\s*User@Host:\s*")
RE_POSTGRES = re.compile(r"\b(?:LOG|ERROR|FATAL|PANIC):\s+(?:statement:|duration:)")
RE_REDIS = re.compile(r"^\d+:(?:M|S|C|X)\s+\d{2}\s+[A-Za-z]{3}\s+\d{4}\s+[\*\#\.\-]\s+")
RE_KAFKA = re.compile(r"\[(?:KafkaServer|KafkaApis|ReplicaManager|GroupCoordinator)\b")


class SourceDetector:
    """Scored source detector resolving vendor, product, and source taxonomy from telemetry."""

    def detect(
        self, text: str, format_name: str | None = None
    ) -> tuple[DetectedSource | None, tuple[DetectedSource, ...]]:
        """Detect source identity from raw payload text and optional format hint."""
        sample = text[:32768]
        if not sample.strip():
            return None, ()

        candidates: list[DetectedSource] = []

        # Check JSON-based signatures first if format is json/ndjson or starts with {
        if format_name in ("json", "ndjson") or sample.lstrip().startswith("{"):
            self._check_json_signatures(sample, candidates)

        # Check XML-based signatures
        if format_name == "xml" or "<Event" in sample:
            self._check_xml_signatures(sample, candidates)

        # Check Syslog/Text signatures
        self._check_syslog_and_text_signatures(sample, candidates)

        candidates.sort(key=lambda s: (-s.score, s.vendor, s.product))
        best = candidates[0] if candidates else None
        return best, tuple(candidates)

    def _check_json_signatures(self, sample: str, candidates: list[DetectedSource]) -> None:
        first_line = sample.splitlines()[0].strip()
        try:
            doc = json.loads(first_line)
            if not isinstance(doc, dict):
                return
        except Exception:
            return

        # Suricata EVE
        if "event_type" in doc and ("flow_id" in doc or "community_id" in doc or "src_ip" in doc):
            candidates.append(
                DetectedSource(
                    vendor="Suricata",
                    product="EVE",
                    source_type="ids_ips",
                    score=0.98,
                    confidence=0.98,
                    evidence=("suricata_event_type", f"type:{doc.get('event_type')}"),
                )
            )

        # AWS CloudTrail
        if "eventVersion" in doc and "eventSource" in doc and "awsRegion" in doc:
            candidates.append(
                DetectedSource(
                    vendor="AWS",
                    product="CloudTrail",
                    source_type="cloud_audit",
                    score=0.99,
                    confidence=0.99,
                    evidence=("aws_cloudtrail_keys", f"source:{doc.get('eventSource')}"),
                )
            )

        # GCP Cloud Audit
        if "protoPayload" in doc or (doc.get("resource", {}).get("type", "").startswith("gce_")):
            candidates.append(
                DetectedSource(
                    vendor="GCP",
                    product="CloudAudit",
                    source_type="cloud_audit",
                    score=0.96,
                    confidence=0.96,
                    evidence=("gcp_proto_payload",),
                )
            )

        # Azure Activity / Diagnostic
        if "operationName" in doc and ("resourceId" in doc or "category" in doc):
            candidates.append(
                DetectedSource(
                    vendor="Microsoft",
                    product="AzureActivity",
                    source_type="cloud_audit",
                    score=0.95,
                    confidence=0.95,
                    evidence=("azure_activity_keys",),
                )
            )

        # Kubernetes Audit
        if doc.get("kind") == "Event" or doc.get("apiVersion", "").startswith("audit.k8s.io"):
            candidates.append(
                DetectedSource(
                    vendor="Kubernetes",
                    product="KubeAudit",
                    source_type="container_audit",
                    score=0.97,
                    confidence=0.97,
                    evidence=("k8s_audit_api_version",),
                )
            )

        # OpenTelemetry Logs
        if "resourceLogs" in doc or "ResourceLogs" in doc or "scopeLogs" in doc:
            candidates.append(
                DetectedSource(
                    vendor="OpenTelemetry",
                    product="OTelLogs",
                    source_type="observability",
                    score=0.98,
                    confidence=0.98,
                    evidence=("otel_resource_logs_found",),
                )
            )

        # Zeek JSON
        if "ts" in doc and "uid" in doc and ("id.orig_h" in doc or "id_orig_h" in doc):
            candidates.append(
                DetectedSource(
                    vendor="Zeek",
                    product="ZeekNIDS",
                    source_type="network_flow",
                    score=0.97,
                    confidence=0.97,
                    evidence=("zeek_json_keys",),
                )
            )

    def _check_xml_signatures(self, sample: str, candidates: list[DetectedSource]) -> None:
        has_win_ns = 'xmlns="http://schemas.microsoft.com/win/2004/08/events/event"' in sample
        if has_win_ns or "<EventID>" in sample:
            candidates.append(
                DetectedSource(
                    vendor="Microsoft",
                    product="WindowsEventLog",
                    source_type="endpoint_os",
                    score=0.98,
                    confidence=0.98,
                    evidence=("windows_event_xml_namespace",),
                )
            )

    def _check_syslog_and_text_signatures(
        self, sample: str, candidates: list[DetectedSource]
    ) -> None:
        # Palo Alto PAN-OS
        if RE_PANOS_CSV.search(sample):
            candidates.append(
                DetectedSource(
                    vendor="Palo Alto Networks",
                    product="PAN-OS",
                    source_type="firewall",
                    score=0.96,
                    confidence=0.96,
                    evidence=("panos_csv_structure_matched",),
                )
            )

        # Fortinet FortiGate
        if RE_FORTINET.search(sample):
            candidates.append(
                DetectedSource(
                    vendor="Fortinet",
                    product="FortiGate",
                    source_type="firewall",
                    score=0.95,
                    confidence=0.95,
                    evidence=("fortigate_key_value_tokens",),
                )
            )

        # Cisco ASA / FTD
        if RE_CISCO_ASA.search(sample):
            candidates.append(
                DetectedSource(
                    vendor="Cisco",
                    product="ASA",
                    source_type="firewall",
                    score=0.98,
                    confidence=0.98,
                    evidence=("cisco_asa_message_id",),
                )
            )
        elif RE_CISCO_IOS.search(sample):
            candidates.append(
                DetectedSource(
                    vendor="Cisco",
                    product="IOS-XE",
                    source_type="network_device",
                    score=0.95,
                    confidence=0.95,
                    evidence=("cisco_ios_facility_mnemonic",),
                )
            )

        # Juniper SRX
        if RE_JUNIPER_SRX.search(sample):
            candidates.append(
                DetectedSource(
                    vendor="Juniper",
                    product="SRX",
                    source_type="firewall",
                    score=0.95,
                    confidence=0.95,
                    evidence=("juniper_rt_flow_token",),
                )
            )

        # Check Point
        if RE_CHECKPOINT.search(sample):
            candidates.append(
                DetectedSource(
                    vendor="Check Point",
                    product="SecurityGateway",
                    source_type="firewall",
                    score=0.93,
                    confidence=0.93,
                    evidence=("checkpoint_tokens",),
                )
            )

        # OPNsense / pfSense
        if RE_OPNSENSE.search(sample):
            candidates.append(
                DetectedSource(
                    vendor="OPNsense",
                    product="pfSense/OPNsense",
                    source_type="firewall",
                    score=0.95,
                    confidence=0.95,
                    evidence=("filterlog_matched",),
                )
            )

        # Snort Fast Alert
        if RE_SNORT.search(sample):
            candidates.append(
                DetectedSource(
                    vendor="Snort",
                    product="Snort",
                    source_type="ids_ips",
                    score=0.96,
                    confidence=0.96,
                    evidence=("snort_fast_bracket_pattern",),
                )
            )

        # Zeek TSV
        if sample.startswith("#separator") or sample.startswith("#fields\tts"):
            candidates.append(
                DetectedSource(
                    vendor="Zeek",
                    product="ZeekNIDS",
                    source_type="network_flow",
                    score=0.98,
                    confidence=0.98,
                    evidence=("zeek_tsv_header_matched",),
                )
            )

        # Linux Auditd
        if RE_AUDITD.search(sample):
            candidates.append(
                DetectedSource(
                    vendor="Linux",
                    product="Auditd",
                    source_type="endpoint_os",
                    score=0.97,
                    confidence=0.97,
                    evidence=("linux_auditd_type_msg",),
                )
            )

        # HAProxy
        if RE_HAPROXY.search(sample):
            candidates.append(
                DetectedSource(
                    vendor="HAProxy",
                    product="HAProxy",
                    source_type="load_balancer",
                    score=0.95,
                    confidence=0.95,
                    evidence=("haproxy_header_pattern",),
                )
            )

        # Microsoft IIS W3C
        has_iis_text = (
            "Microsoft Internet Information Services" in sample
            or "#Software: Microsoft IIS" in sample
        )
        if has_iis_text:
            candidates.append(
                DetectedSource(
                    vendor="Microsoft",
                    product="IIS",
                    source_type="web_server",
                    score=0.98,
                    confidence=0.98,
                    evidence=("iis_w3c_software_directive",),
                )
            )

        # Databases
        if RE_MYSQL_SLOW.search(sample):
            candidates.append(
                DetectedSource(
                    vendor="Oracle",
                    product="MySQL",
                    source_type="database",
                    score=0.95,
                    confidence=0.95,
                    evidence=("mysql_slow_header",),
                )
            )
        elif RE_POSTGRES.search(sample):
            candidates.append(
                DetectedSource(
                    vendor="PostgreSQL",
                    product="PostgreSQL",
                    source_type="database",
                    score=0.94,
                    confidence=0.94,
                    evidence=("postgres_log_prefix",),
                )
            )
        elif RE_REDIS.search(sample):
            candidates.append(
                DetectedSource(
                    vendor="Redis",
                    product="Redis",
                    source_type="database",
                    score=0.95,
                    confidence=0.95,
                    evidence=("redis_log_prefix",),
                )
            )
        elif RE_KAFKA.search(sample):
            candidates.append(
                DetectedSource(
                    vendor="Apache",
                    product="Kafka",
                    source_type="message_queue",
                    score=0.95,
                    confidence=0.95,
                    evidence=("kafka_server_token",),
                )
            )
