# Phase 9 — Advanced Security Analytics REST API Specification

**Prefix:** `/api/v1/advanced-intelligence`  
**Authentication & RBAC:** Enforced via `X-ULPF-Role` or `x-role` request headers.  
**Roles:** `platform-admin`, `intelligence:write`, `intelligence:read`, `viewer`.  

---

## Endpoints

### 1. Threat Intelligence Subsystem

#### `POST /api/v1/advanced-intelligence/ti/indicators`
Registers a new threat intelligence indicator from a local feed.
- **Required Roles:** `intelligence:write`, `platform-admin`
- **Request Body:**
```json
{
  "type": "IPV4",
  "normalized_value": "198.51.100.5",
  "source": "cert-in-feed",
  "source_version": "1.0.0",
  "status": "MALICIOUS",
  "lifecycle_state": "ACTIVE",
  "risk_contribution": 30.0,
  "tags": ["apt", "c2"]
}
```
- **Response (200 OK):**
```json
{
  "indicator_id": "ind-7a4c9f120e31",
  "integrity_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "status": "REGISTERED"
}
```

#### `GET /api/v1/advanced-intelligence/ti/indicators/{indicator_id}`
Retrieves details and metadata for a specific threat intelligence indicator.
- **Required Roles:** `intelligence:read`, `intelligence:write`, `platform-admin`
- **Response (200 OK):** Serialized `ThreatIntelIndicator` dictionary.
- **Response (404 Not Found):** If indicator does not exist.

#### `POST /api/v1/advanced-intelligence/ti/indicators/{indicator_id}/activate`
Promotes a registered indicator to `ACTIVE` state, instantly loading it into in-memory fast matching indices.
- **Required Roles:** `intelligence:write`, `platform-admin`

#### `POST /api/v1/advanced-intelligence/ti/indicators/{indicator_id}/revoke`
Revokes an active indicator immediately, purging it from live matching indices.
- **Required Roles:** `intelligence:write`, `platform-admin`

#### `GET /api/v1/advanced-intelligence/ti/stats`
Returns active indicator count and index telemetry.
- **Required Roles:** `intelligence:read`, `intelligence:write`, `platform-admin`

#### `POST /api/v1/advanced-intelligence/ti/match`
Scans an incoming log or event record against all active threat intelligence indicators.
- **Required Roles:** `intelligence:read`, `intelligence:write`, `platform-admin`
- **Request Body:**
```json
{
  "event": {
    "event_id": "evt-001",
    "src_ip": "198.51.100.5"
  }
}
```
- **Response (200 OK):**
```json
{
  "event_id": "evt-001",
  "match_count": 1,
  "matches": [
    {
      "indicator_id": "ind-7a4c9f120e31",
      "match_type": "EXACT",
      "matched_value": "198.51.100.5",
      "confidence": 0.8,
      "risk_contribution": 30.0
    }
  ],
  "highest_status": "MALICIOUS"
}
```

---

### 2. Alert Triage & Flood Control

#### `POST /api/v1/advanced-intelligence/alerts/triage/classify`
Executes deterministic alert triage classification.
- **Required Roles:** `intelligence:read`, `intelligence:write`, `platform-admin`
- **Request Body:**
```json
{
  "risk_score": 85.0,
  "has_critical_ti": true,
  "asset_criticality": "CRITICAL",
  "is_external_facing": true,
  "is_multi_stage": true
}
```
- **Response (200 OK):**
```json
{
  "severity": "CRITICAL",
  "action": "ESCALATE_TO_SOC_TIER2"
}
```

#### `GET /api/v1/advanced-intelligence/alerts/flood-control/stats`
Returns sliding-window flood control stats (1-minute sliding rate, total suppressed, burst limits).

#### `GET /api/v1/advanced-intelligence/alerts/dedup/stats`
Returns deduplication metrics (total unique groups, active suppression count).

---

### 3. SOC Overview

#### `GET /api/v1/advanced-intelligence/soc/overview`
Live operational dashboard feed. Returns live engine counts with zero synthetic data.
- **Required Roles:** Any authenticated role.
- **Response (200 OK):**
```json
{
  "active_indicators": 1420,
  "alert_dedup_groups": 38,
  "flood_control_rate_1m": 12,
  "flood_control_total_suppressed": 0,
  "last_updated": "2026-09-07T12:15:00Z",
  "tenant_id": null
}
```
