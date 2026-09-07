# Phase 10 — Mission Operations REST API Specification

**Prefix:** `/api/v1/mission`  
**Authentication & RBAC:** Enforced via `X-ULPF-Role` or `x-role` request headers.  
**Roles:** `platform-admin`, `mission:execute`, `mission:write`, `mission:read`, `viewer`.  

---

## Endpoint Reference

### 1. Unified Subsystem Health

#### `GET /api/v1/mission/health`
Retrieves operational health state, latency, and throughput across all 12 platform subsystems.
- **Required Roles:** `viewer`, `mission:read`, `platform-admin`
- **Response (200 OK):**
```json
{
  "status": "HEALTHY",
  "healthy_count": 12,
  "degraded_count": 0,
  "failed_count": 0,
  "subsystems": [
    {
      "subsystem": "posture",
      "state": "HEALTHY",
      "latency_ms": 0.05,
      "throughput_eps": 66000.0,
      "error_message": null,
      "last_checked": 1725740400.0
    }
  ]
}
```

---

### 2. Security Posture & Risk Analytics

#### `GET /api/v1/mission/posture`
Returns the current security posture state, composite risk score, and factor breakdown.
- **Required Roles:** `viewer`, `mission:read`, `platform-admin`
- **Response (200 OK):**
```json
{
  "level": "NORMAL",
  "risk_score": 19.5,
  "rationale": "critical_alerts=2 (f=0.20), campaigns=1 (f=0.20), anomaly_rate=1.50% (f=0.06), ti_matches=4 (f=0.20), source_health_penalty=0.00",
  "recommendations": [],
  "factors": {
    "critical_alert": 0.2,
    "campaign_volume": 0.2,
    "anomaly_rate": 0.06,
    "ti_match": 0.2,
    "source_health": 0.0
  },
  "is_urgent": false,
  "timestamp": 1725740400.0
}
```

#### `POST /api/v1/mission/posture/calculate`
Calculates custom security posture from explicit input counters.
- **Required Roles:** `viewer`, `mission:read`, `platform-admin`
- **Request Body:**
```json
{
  "critical_alert_count": 8,
  "active_campaign_count": 3,
  "anomaly_event_count": 45,
  "total_event_count": 1000,
  "ti_match_count": 12,
  "unhealthy_source_fraction": 0.15
}
```
- **Response (200 OK):** Calculated `SecurityPostureState` response.

---

### 3. Early Warning Threat Acceleration

#### `GET /api/v1/mission/early-warning`
Evaluates pre-incident threat acceleration velocity across authentication, diversity, and anomaly vectors.
- **Required Roles:** `viewer`, `mission:read`, `platform-admin`
- **Response (200 OK):**
```json
{
  "threat_acceleration_detected": true,
  "threat_level": "HIGH",
  "acceleration_factor": 2.85,
  "rationale": "High threat acceleration detected across 3 velocity indicators.",
  "signal_count": 5,
  "signals": [
    {
      "indicator_type": "AUTH_FAILURE_RATE",
      "observed_value": 0.18,
      "baseline_value": 0.04,
      "ratio": 4.5,
      "confidence": 0.95,
      "rationale": "Authentication failure rate surged 4.5x above baseline"
    }
  ]
}
```

---

### 4. Multi-Source Evidence Signal Fusion

#### `POST /api/v1/mission/fusion`
Fuses disparate detection signals into a unified entity risk score without losing attribution.
- **Required Roles:** `mission:execute`, `mission:write`, `platform-admin`
- **Request Body:**
```json
{
  "entity_id": "host-srv-prod-04",
  "entity_type": "host",
  "raw_signals": [
    {
      "source": "DETECTION_RULE",
      "risk_score": 85.0,
      "confidence": 0.9,
      "description": "Mimikatz LSASS memory dumping observed"
    },
    {
      "source": "THREAT_INTEL",
      "risk_score": 90.0,
      "confidence": 0.95,
      "description": "Known APT C2 communication"
    }
  ]
}
```
- **Response (200 OK):**
```json
{
  "entity_id": "host-srv-prod-04",
  "entity_type": "host",
  "fused_risk_score": 87.5,
  "confidence": 0.925,
  "is_high_risk": true,
  "rationale": "Fused 2 detection signals into high risk posture",
  "contributions": [
    {
      "source": "DETECTION_RULE",
      "weight": 0.35,
      "raw_risk": 85.0,
      "confidence": 0.9,
      "description": "Mimikatz LSASS memory dumping observed"
    }
  ]
}
```

---

### 5. Detection Coverage & Gap Advisory

#### `GET /api/v1/mission/coverage`
Generates the MITRE ATT&CK enterprise coverage matrix across ingested telemetry sources.
- **Required Roles:** `viewer`, `mission:read`, `platform-admin`
- **Response (200 OK):**
```json
{
  "overall_coverage_pct": 78.5,
  "total_cells": 70,
  "covered_cells": 55,
  "partially_covered_cells": 10,
  "uncovered_cells": 5,
  "sources": ["sysmon", "zeek", "auditd", "aws_cloudtrail", "auth_log"],
  "tactics": ["initial_access", "execution", "persistence", "privilege_escalation", "..."],
  "matrix": {}
}
```

#### `GET /api/v1/mission/coverage/gaps`
Produces detection gap analysis and prioritized remediation recommendations.
- **Required Roles:** `viewer`, `mission:read`, `platform-admin`

---

### 6. Purple-Team Scenario Validation & Differentials

#### `GET /api/v1/mission/scenarios`
Lists all standard pre-built purple-team attack scenarios.
- **Required Roles:** `viewer`, `mission:read`, `platform-admin`

#### `POST /api/v1/mission/scenarios/{scenario_id}/validate`
Injects synthetic attack scenario events into the validation harness.
- **Required Roles:** `mission:execute`, `mission:write`, `platform-admin`
- **Response (200 OK):**
```json
{
  "scenario_id": "SCENARIO_AUTH_BRUTE_FORCE",
  "scenario_name": "Authentication Brute Force Campaign",
  "status": "VALIDATED",
  "detection_rate": 1.0,
  "max_risk_score": 88.0,
  "duration_ms": 12.4,
  "failure_reasons": [],
  "step_results": [
    {
      "step_number": 1,
      "name": "Single Failure Probe",
      "fired": true,
      "matched_rules": ["RULE_BRUTE_FORCE_AUTH"],
      "risk_score": 45.0
    }
  ]
}
```

---

### 7. Response Playbooks (Safe Dry Run)

#### `POST /api/v1/mission/playbooks/{playbook_id}/dry-run`
Simulates automated response playbook actions without mutating system or network state.
- **Required Roles:** `mission:execute`, `mission:write`, `platform-admin`
- **Request Body:**
```json
{
  "parameters": {
    "host_ip": "10.0.4.15",
    "username": "jdoe_admin"
  },
  "user_permissions": ["edr:isolate", "firewall:write", "ad:write"]
}
```
- **Response (200 OK):**
```json
{
  "playbook_id": "PB-HOST-ISOLATION",
  "playbook_name": "Emergency Host Network Isolation",
  "status": "SIMULATION_SUCCESS",
  "steps_simulated": 3,
  "blocking_issues": [],
  "projected_impact": "Host 10.0.4.15 network connectivity severed with management port allowlist.",
  "dry_run_timestamp": 1725740400.0,
  "step_results": []
}
```

---

### 8. Air-Gapped AI Analyst Copilot

#### `POST /api/v1/mission/copilot/summary`
Generates explainable 5W case narratives and hunt queries with prompt injection defense.
- **Required Roles:** `viewer`, `mission:read`, `platform-admin`
- **Request Body:**
```json
{
  "case_id": "CASE-2026-0901",
  "severity": "HIGH",
  "description": "Suspicious PowerShell encoded command invoking external IP",
  "affected_assets": ["srv-app-02"],
  "involved_users": ["svc_web"],
  "detection_rule_ids": ["RULE_SUSPICIOUS_PS_EXEC"],
  "kill_chain_phases": ["Execution", "Command and Control"]
}
```
- **Response (200 OK):**
```json
{
  "case_id": "CASE-2026-0901",
  "severity": "HIGH",
  "what": "Execution of obfuscated command line via PowerShell with outbound network connection.",
  "when": "Incident initiated at timestamp 1725740300.0.",
  "where": "Asset srv-app-02 within primary application tier.",
  "who": "Service account svc_web.",
  "why": "Matched detection rule RULE_SUSPICIOUS_PS_EXEC mapped to MITRE T1059.001.",
  "recommended_actions": [
    "Quarantine host srv-app-02 pending forensic review",
    "Rotate credentials for svc_web service account"
  ],
  "hunt_queries": [
    "event_type:process_creation AND process_name:powershell.exe AND command_line:*-enc*"
  ],
  "confidence_note": "High confidence based on verified rule matching and offline heuristic alignment.",
  "data_limitations": "Zero external cloud dependencies used during synthesis."
}
```

---

### 9. Mission Pipeline Execution & Simulation

#### `POST /api/v1/mission/pipeline/run`
Executes end-to-end processing of a batch of raw telemetry events through all intelligence stages.
- **Required Roles:** `mission:execute`, `mission:write`, `platform-admin`

#### `POST /api/v1/mission/simulation/run`
Deterministically generates synthetic security attack streams mixed with realistic benign noise.
- **Required Roles:** `mission:execute`, `mission:write`, `platform-admin`
- **Request Body:**
```json
{
  "attack_type": "BRUTE_FORCE",
  "event_count": 50,
  "noise_ratio": 0.7,
  "seed": 42
}
```

#### `GET /api/v1/mission/metrics`
Returns measured SLA performance metrics (MTTD/MTTA/MTTR and latency percentiles).
- **Required Roles:** `viewer`, `mission:read`, `platform-admin`
