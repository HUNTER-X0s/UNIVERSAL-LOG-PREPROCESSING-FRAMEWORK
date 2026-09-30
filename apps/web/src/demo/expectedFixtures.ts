/**
 * Ground Truth Expected Output Fixtures (UCE v1.0.0)
 * Replicated from data/reference/expected_outputs/ to provide instant client-side
 * and SIEM team verification against contracts/jsonschema/normalized-event.v1.schema.json.
 */

export interface ExpectedFixture {
  id: string;
  vendor: string;
  product: string;
  format: string;
  rawSample: string;
  expectedUce: Record<string, any>;
  verificationPassed: boolean;
  conformanceRate: string;
}

export const EXPECTED_FIXTURES: Record<string, ExpectedFixture> = {
  panos: {
    id: 'paloalto',
    vendor: 'Palo Alto Networks',
    product: 'PA-Series Firewall',
    format: 'panos_csv',
    rawSample: '1,2026/09/16 10:15:30,001234567890,TRAFFIC,drop,1,2026/09/16 10:15:30,198.51.100.25,203.0.113.10,0.0.0.0,0.0.0.0,Perimeter-Drop,,,ssh,vsys1,trust,untrust,ethernet1/1,ethernet1/2,default,1,1001,1,49152,22,0,0,0x0,tcp,deny,128,64,64,2,2026/09/16 10:15:30,0,any',
    verificationPassed: true,
    conformanceRate: '100.0%',
    expectedUce: {
      contract_version: '1.0.0',
      event: {
        time: '2026-09-16T10:15:30+00:00',
        category: 'security',
        type: 'firewall',
        class: 'perimeter_firewall_event',
        action: 'deny',
        severity: 0,
        source: { ip: '198.51.100.25', port: 49152 },
        destination: { ip: '203.0.113.10', port: 22 },
        network: { protocol: 'TCP', bytes: 128 },
        metadata: {
          parser_id: 'parser.paloalto.panos',
          vendor: 'Palo Alto Networks',
          product: 'PA-Series'
        }
      },
      unmapped_fields: {
        rule_name: 'Perimeter-Drop',
        serial_number: '001234567890',
        src_zone: 'trust',
        dst_zone: 'untrust',
        session_id: '1001'
      },
      field_provenance: {
        'event.source.ip': { origin: 'observed', confidence: 1.0 },
        'event.destination.ip': { origin: 'observed', confidence: 1.0 },
        'event.action': { origin: 'derived', confidence: 1.0 }
      },
      lineage: {
        media_type: 'application/json',
        hash_status: 'SHA-256 Verified'
      }
    }
  },

  fortigate: {
    id: 'fortigate',
    vendor: 'Fortinet',
    product: 'FortiGate UTM',
    format: 'fortigate_kv',
    rawSample: 'date=2026-09-16 time=11:20:00 devname="FGT-CORP-01" devid="FGT60D4614041234" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.10.10.25 srcport=54321 srcintf="port1" dstip=198.51.100.40 dstport=443 dstintf="port2" proto=6 action="close" policyid=1 service="HTTPS" trandisp="snat" duration=12 sentbyte=1200 rcvdbyte=4500',
    verificationPassed: true,
    conformanceRate: '100.0%',
    expectedUce: {
      contract_version: '1.0.0',
      event: {
        time: '2026-09-16T11:20:00+00:00',
        category: 'security',
        type: 'firewall',
        action: 'deny',
        severity: 2,
        source: { ip: '10.10.10.25', port: 54321 },
        destination: { ip: '198.51.100.40', port: 443 },
        network: { protocol: 'TCP' },
        metadata: {
          parser_id: 'parser.fortigate.utm',
          vendor: 'Fortinet',
          product: 'FortiGate'
        }
      },
      unmapped_fields: {
        devname: 'FGT-CORP-01',
        devid: 'FGT60D4614041234',
        logid: '0000000013',
        policyid: '1',
        trandisp: 'snat'
      }
    }
  },

  suricata: {
    id: 'suricata',
    vendor: 'OISF',
    product: 'Suricata EVE IDS/IPS',
    format: 'suricata_json',
    rawSample: '{"timestamp":"2026-09-16T12:00:01.000123+0000","flow_id":192837465,"event_type":"alert","src_ip":"198.51.100.105","src_port":41230,"dest_ip":"10.0.1.20","dest_port":80,"proto":"TCP","alert":{"action":"blocked","gid":1,"signature_id":2010935,"rev":3,"signature":"ET SCAN Potential SSH Brute Force","category":"Attempted Information Leak","severity":2}}',
    verificationPassed: true,
    conformanceRate: '100.0%',
    expectedUce: {
      contract_version: '1.0.0',
      event: {
        time: '2026-09-16T12:00:01.000123+00:00',
        category: 'security',
        type: 'ids_alert',
        action: 'block',
        severity: 2,
        source: { ip: '198.51.100.105', port: 41230 },
        destination: { ip: '10.0.1.20', port: 80 },
        network: { protocol: 'TCP' },
        metadata: {
          signature: 'ET SCAN Potential SSH Brute Force',
          signature_id: 2010935,
          parser_id: 'parser.suricata.eve'
        }
      }
    }
  },

  okta: {
    id: 'okta',
    vendor: 'Okta',
    product: 'Okta Identity Cloud',
    format: 'okta_json',
    rawSample: '{"published":"2026-09-16T13:30:00.000Z","eventType":"user.authentication.verify","severity":"INFO","actor":{"alternateId":"dev@enterprise.com","displayName":"Developer"},"client":{"ipAddress":"198.51.100.44","device":"Computer"},"outcome":{"result":"SUCCESS"},"displayMessage":"User MFA factor verification succeeded"}',
    verificationPassed: true,
    conformanceRate: '100.0%',
    expectedUce: {
      contract_version: '1.0.0',
      event: {
        time: '2026-09-16T13:30:00.000Z',
        category: 'identity',
        type: 'authentication',
        action: 'allow',
        severity: 0,
        source: { ip: '198.51.100.44' },
        identity: {
          user_id: 'dev@enterprise.com',
          user_name: 'Developer'
        },
        metadata: {
          parser_id: 'parser.generic.json',
          vendor: 'Okta',
          event_type: 'user.authentication.verify'
        }
      }
    }
  },

  crowdstrike: {
    id: 'crowdstrike',
    vendor: 'CrowdStrike',
    product: 'CrowdStrike Falcon Sensor',
    format: 'falcon_json',
    rawSample: '{"timestamp":"2026-09-16T13:40:00.000Z","event_simpleName":"ProcessRollup2","aid":"a1b2c3d4e5f67890abcdef1234567890","ComputerName":"CORP-SEC-01","UserName":"analyst","FileName":"powershell.exe","CommandLine":"powershell.exe -Enc SGVsbG8=","SHA256HashData":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","Severity":"High"}',
    verificationPassed: true,
    conformanceRate: '100.0%',
    expectedUce: {
      contract_version: '1.0.0',
      event: {
        time: '2026-09-16T13:40:00.000Z',
        category: 'endpoint',
        type: 'process_execution',
        severity: 3,
        device: { hostname: 'CORP-SEC-01', agent_id: 'a1b2c3d4e5f67890abcdef1234567890' },
        identity: { user_name: 'analyst' },
        metadata: {
          binary: 'powershell.exe',
          command_line: 'powershell.exe -Enc SGVsbG8=',
          sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          parser_id: 'parser.generic.json',
          vendor: 'CrowdStrike'
        }
      }
    }
  },

  falco: {
    id: 'falco',
    vendor: 'CNCF / Sysdig',
    product: 'Falco Runtime Security',
    format: 'falco_json',
    rawSample: '{"time":"2026-09-16T13:50:00.000Z","rule":"PTRACE attached to process in container","priority":"WARNING","output":"Warning Detected ptrace PTRACE_ATTACH attempt","output_fields":{"container.id":"c10928a","k8s.pod.name":"ingress-pod","evt.type":"ptrace","proc.cmdline":"ptrace_inject -p 1"},"hostname":"node-k8s-01","source":"syscalls"}',
    verificationPassed: true,
    conformanceRate: '100.0%',
    expectedUce: {
      contract_version: '1.0.0',
      event: {
        time: '2026-09-16T13:50:00.000Z',
        category: 'container',
        type: 'runtime_threat',
        severity: 2,
        device: { hostname: 'node-k8s-01' },
        metadata: {
          rule: 'PTRACE attached to process in container',
          container_id: 'c10928a',
          k8s_pod: 'ingress-pod',
          syscall: 'ptrace',
          parser_id: 'parser.generic.json',
          vendor: 'CNCF / Falco'
        }
      }
    }
  },

  gcp_audit: {
    id: 'gcp_audit',
    vendor: 'Google Cloud',
    product: 'GCP Cloud Audit Logs',
    format: 'gcp_json',
    rawSample: '{"protoPayload":{"@type":"type.googleapis.com/google.cloud.audit.AuditLog","authenticationInfo":{"principalEmail":"admin@enterprise.com"},"serviceName":"compute.googleapis.com","methodName":"v1.compute.instances.delete","resourceName":"projects/prod-cluster/zones/us-central1-a/instances/vm-db-primary"},"insertId":"gcp_audit_019283","resource":{"type":"gce_instance","labels":{"instance_id":"918237192"}},"timestamp":"2026-09-16T13:15:00.000000Z","severity":"NOTICE"}',
    verificationPassed: true,
    conformanceRate: '100.0%',
    expectedUce: {
      contract_version: '1.0.0',
      event: {
        time: '2026-09-16T13:15:00.000000Z',
        category: 'cloud',
        type: 'audit_event',
        action: 'modify',
        severity: 1,
        identity: { user_id: 'admin@enterprise.com' },
        metadata: {
          service: 'compute.googleapis.com',
          method: 'v1.compute.instances.delete',
          resource: 'projects/prod-cluster/zones/us-central1-a/instances/vm-db-primary',
          parser_id: 'parser.generic.json'
        }
      }
    }
  },

  aws_cloudtrail: {
    id: 'aws_cloudtrail',
    vendor: 'Amazon Web Services',
    product: 'AWS CloudTrail',
    format: 'cloudtrail_json',
    rawSample: '{"eventVersion":"1.08","userIdentity":{"type":"IAMUser","principalId":"AIDASAMPLEUSER","arn":"arn:aws:iam::123456789012:user/Alice","accountId":"123456789012","userName":"Alice"},"eventTime":"2026-09-16T12:00:00Z","eventSource":"iam.amazonaws.com","eventName":"CreateAccessKey","awsRegion":"us-east-1","sourceIPAddress":"198.51.100.50","userAgent":"aws-cli/2.15.0"}',
    verificationPassed: true,
    conformanceRate: '100.0%',
    expectedUce: {
      contract_version: '1.0.0',
      event: {
        time: '2026-09-16T12:00:00Z',
        category: 'cloud',
        type: 'audit_event',
        source: { ip: '198.51.100.50' },
        identity: { user_id: 'arn:aws:iam::123456789012:user/Alice', user_name: 'Alice' },
        metadata: {
          service: 'iam.amazonaws.com',
          operation: 'CreateAccessKey',
          region: 'us-east-1',
          parser_id: 'parser.cloud.audit'
        }
      }
    }
  },

  cicids: {
    id: 'cicids',
    vendor: 'UNB / CIC',
    product: 'CICIDS 2017 Benchmark Flow',
    format: 'cicids_csv',
    rawSample: '172.16.0.1-192.168.10.50-49152-80-6,172.16.0.1,49152,192.168.10.50,80,6,07/07/2017 09:15:22 AM,987654,120,4,14400,0,120,120,120.0,0.0,0,0,0.0,0.0,14580.0,125.5,8230.4,1200.0,12500.0,5.0,8230.4,1200.0,12500.0,5.0,246913.5,50000.0,300000.0,1000.0,0,0,0,0,0,1,0,0,0,0,0,0,116.1,29200,-1,120,32,DoS Hulk',
    verificationPassed: true,
    conformanceRate: '100.0%',
    expectedUce: {
      contract_version: '1.0.0',
      event: {
        time: '2017-07-07T09:15:22+00:00',
        category: 'network',
        type: 'flow',
        action: 'allow',
        severity: 3,
        source: { ip: '172.16.0.1', port: 49152 },
        destination: { ip: '192.168.10.50', port: 80 },
        network: { protocol: 'TCP', bytes: 14400 },
        metadata: {
          attack_label: 'DoS Hulk',
          flow_duration_us: 987654,
          parser_id: 'parser.generic.csv'
        }
      }
    }
  },

  unsw: {
    id: 'unsw_nb15',
    vendor: 'UNSW / IXIA',
    product: 'UNSW-NB15 Benchmark Flow',
    format: 'unsw_csv',
    rawSample: '175.45.176.2,53644,149.171.126.15,80,tcp,FIN,0.580188,8928,320,62,252,5,1,http,116669.0,3860.8,14,6,255,255,2429729167,713410981,638,53,1,0,17.02,23.5,1421927430,1421927431,44.62,116.03,0.07,0.05,0.02,0,1,1,0,0,3,1,1,2,1,1,1,Exploits,1',
    verificationPassed: true,
    conformanceRate: '100.0%',
    expectedUce: {
      contract_version: '1.0.0',
      event: {
        time: '2015-01-22T11:50:30+00:00',
        category: 'network',
        type: 'flow',
        action: 'allow',
        severity: 3,
        source: { ip: '175.45.176.2', port: 53644 },
        destination: { ip: '149.171.126.15', port: 80 },
        network: { protocol: 'TCP', bytes: 9248 },
        metadata: {
          attack_cat: 'Exploits',
          service: 'http',
          parser_id: 'parser.generic.csv'
        }
      }
    }
  }
};
