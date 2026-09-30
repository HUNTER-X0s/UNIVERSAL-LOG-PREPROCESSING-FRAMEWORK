export const SAMPLE_RAW_LOG = `%ASA-4-106023: Deny tcp src outside:198.51.100.44/51423 dst inside:10.0.1.20/443 by access-group "PROTECT-INTERNAL" [0x8401, 0x0]`;

export const SAMPLE_UCE = {
  "schema_version": "1.0.0",
  "event_id": "EVT-841920",
  "timestamp": "2026-09-11T14:30:00.123Z",
  "source": {
    "type": "cisco_asa",
    "vendor": "Cisco Systems",
    "parser": "cisco_asa_v1",
    "tier": "Tier A",
    "collector_id": "gw-perimeter-01"
  },
  "network": {
    "src_ip": "198.51.100.44",
    "src_port": 51423,
    "dst_ip": "10.0.1.20",
    "dst_port": 443,
    "protocol": "TCP",
    "action": "DENY",
    "interface_in": "outside",
    "interface_out": "inside"
  },
  "security": {
    "severity": "HIGH",
    "rule_name": "PROTECT-INTERNAL",
    "mitre_attack": {
      "tactic": "TA0001: Initial Access",
      "technique": "T1071.001: Application Layer Protocol"
    },
    "anomaly_z_score": 3.42
  },
  "entities": [
    { "type": "ip_address", "role": "source", "value": "198.51.100.44" },
    { "type": "ip_address", "role": "destination", "value": "10.0.1.20" }
  ],
  "unmapped_residue": {
    "cisco_msg_code": "106023",
    "cisco_threat_code": "0x8401",
    "extended_flags": "0x0",
    "capture_tag": "INGRESS_DENY"
  },
  "provenance": {
    "cas_digest": "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
    "capture_timestamp": "2026-09-11T14:30:00.102Z",
    "stages_applied": 13,
    "airgap_validated": true
  }
};

export const SAMPLE_OCSF = {
  "class_uid": 4001,
  "class_name": "Network Activity",
  "category_uid": 4,
  "category_name": "Network Activity",
  "severity_id": 4,
  "severity": "High",
  "activity_id": 2,
  "activity_name": "Deny",
  "time": 1726065000123,
  "metadata": {
    "version": "1.1.0",
    "product": {
      "vendor_name": "Cisco Systems",
      "name": "Cisco ASA",
      "version": "9.18.2"
    },
    "uid": "EVT-841920",
    "correlation_uid": "CORR-992140"
  },
  "src_endpoint": {
    "ip": "198.51.100.44",
    "port": 51423,
    "interface_name": "outside"
  },
  "dst_endpoint": {
    "ip": "10.0.1.20",
    "port": 443,
    "interface_name": "inside"
  },
  "connection_info": {
    "protocol_name": "TCP",
    "direction": "Inbound"
  },
  "unmapped": {
    "cisco_msg_code": "106023",
    "cisco_threat_code": "0x8401"
  }
};

export const SAMPLE_OTEL = {
  "resourceLogs": [
    {
      "resource": {
        "attributes": [
          { "key": "service.name", "value": { "stringValue": "ulpf-pipeline" } },
          { "key": "telemetry.source.type", "value": { "stringValue": "cisco_asa" } },
          { "key": "host.id", "value": { "stringValue": "gw-perimeter-01" } },
          { "key": "deployment.environment", "value": { "stringValue": "sovereign-airgap" } }
        ]
      },
      "scopeLogs": [
        {
          "scope": {
            "name": "ulpf.semantic.normalizer",
            "version": "1.0.0"
          },
          "logRecords": [
            {
              "timeUnixNano": "1726065000123000000",
              "severityNumber": 17,
              "severityText": "ERROR",
              "body": { "stringValue": "Network connection denied from 198.51.100.44:51423 to 10.0.1.20:443" },
              "attributes": [
                { "key": "network.transport", "value": { "stringValue": "tcp" } },
                { "key": "source.address", "value": { "stringValue": "198.51.100.44" } },
                { "key": "destination.address", "value": { "stringValue": "10.0.1.20" } },
                { "key": "destination.port", "value": { "intValue": 443 } },
                { "key": "ulpf.unmapped.cisco_threat_code", "value": { "stringValue": "0x8401" } }
              ]
            }
          ]
        }
      ]
    }
  ]
};
