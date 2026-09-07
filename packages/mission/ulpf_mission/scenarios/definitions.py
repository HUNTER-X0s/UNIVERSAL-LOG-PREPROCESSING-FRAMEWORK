"""Standard purple-team attack scenario definitions for Phase 10."""

from __future__ import annotations

from ulpf_mission.models.scenarios import AttackScenario, ScenarioStep

# ---------------------------------------------------------------------------
# SCENARIO_AUTH_BRUTE_FORCE
# ---------------------------------------------------------------------------
SCENARIO_AUTH_BRUTE_FORCE = AttackScenario(
    scenario_id="S-001",
    name="Authentication Brute Force",
    description=(
        "Adversary repeatedly attempts authentication against a target account "
        "until credentials are compromised."
    ),
    steps=[
        ScenarioStep(
            step_id="S-001-01",
            description="Burst of failed authentication attempts from single source IP",
            mitre_tactic="TA0006_CREDENTIAL_ACCESS",
            mitre_technique="T1110.001",
            expected_detection_rule_ids=["RULE_AUTH_BRUTE_FORCE"],
            expected_anomaly_types=["failure_rate_spike"],
            synthetic_event_template={
                "event_type": "auth_failure",
                "source_ip": "10.0.0.55",
                "target_user": "admin",
                "count": 50,
            },
        ),
        ScenarioStep(
            step_id="S-001-02",
            description="Successful authentication following credential compromise",
            mitre_tactic="TA0001_INITIAL_ACCESS",
            mitre_technique="T1078",
            expected_detection_rule_ids=["RULE_IMPOSSIBLE_TRAVEL", "RULE_AUTH_AFTER_BRUTE"],
            synthetic_event_template={
                "event_type": "auth_success",
                "source_ip": "10.0.0.55",
                "target_user": "admin",
            },
        ),
    ],
    tags=["credential_access", "initial_access", "brute_force"],
)

# ---------------------------------------------------------------------------
# SCENARIO_PORT_SCAN
# ---------------------------------------------------------------------------
SCENARIO_PORT_SCAN = AttackScenario(
    scenario_id="S-002",
    name="Network Port Scan",
    description="Adversary scans multiple destination ports to enumerate open services.",
    steps=[
        ScenarioStep(
            step_id="S-002-01",
            description="High-rate connection attempts across many destination ports",
            mitre_tactic="TA0007_DISCOVERY",
            mitre_technique="T1046",
            expected_detection_rule_ids=["RULE_PORT_SCAN"],
            expected_anomaly_types=["destination_port_diversity"],
            synthetic_event_template={
                "event_type": "network_connection",
                "source_ip": "192.168.1.10",
                "dest_port_range": [1, 65535],
                "count": 1000,
            },
        ),
    ],
    expected_campaign_detected=False,
    tags=["discovery", "reconnaissance"],
)

# ---------------------------------------------------------------------------
# SCENARIO_REMOTE_ACCESS_ABUSE
# ---------------------------------------------------------------------------
SCENARIO_REMOTE_ACCESS_ABUSE = AttackScenario(
    scenario_id="S-003",
    name="Remote Access Tool Abuse",
    description="Adversary installs and uses a remote access tool (RAT) for persistent access.",
    steps=[
        ScenarioStep(
            step_id="S-003-01",
            description="RAT binary execution on endpoint",
            mitre_tactic="TA0002_EXECUTION",
            mitre_technique="T1059",
            expected_detection_rule_ids=["RULE_SUSPICIOUS_PROCESS"],
            synthetic_event_template={
                "event_type": "process_exec",
                "process_name": "rat.exe",
                "host": "WORKSTATION-001",
            },
        ),
        ScenarioStep(
            step_id="S-003-02",
            description="Outbound C2 beacon to external IP",
            mitre_tactic="TA0011_COMMAND_AND_CONTROL",
            mitre_technique="T1071.001",
            expected_detection_rule_ids=["RULE_C2_BEACON"],
            expected_anomaly_types=["c2_beacon_pattern"],
            synthetic_event_template={
                "event_type": "network_connection",
                "dest_ip": "203.0.113.99",
                "dest_port": 4444,
                "beacon_interval_s": 30,
            },
        ),
        ScenarioStep(
            step_id="S-003-03",
            description="Persistence via scheduled task creation",
            mitre_tactic="TA0003_PERSISTENCE",
            mitre_technique="T1053.005",
            expected_detection_rule_ids=["RULE_SCHEDULED_TASK"],
            synthetic_event_template={
                "event_type": "scheduled_task_create",
                "task_name": "SystemUpdate",
                "host": "WORKSTATION-001",
            },
        ),
    ],
    tags=["persistence", "c2", "execution"],
)

# ---------------------------------------------------------------------------
# SCENARIO_SUSPICIOUS_LATERAL_CONNECTION
# ---------------------------------------------------------------------------
SCENARIO_SUSPICIOUS_LATERAL_CONNECTION = AttackScenario(
    scenario_id="S-004",
    name="Suspicious Lateral Connection",
    description="Adversary moves laterally using compromised credentials or pass-the-hash.",
    steps=[
        ScenarioStep(
            step_id="S-004-01",
            description="SMB connection from workstation to domain controller",
            mitre_tactic="TA0008_LATERAL_MOVEMENT",
            mitre_technique="T1021.002",
            expected_detection_rule_ids=["RULE_LATERAL_MOVEMENT_SMB"],
            expected_anomaly_types=["unusual_lateral_path"],
            synthetic_event_template={
                "event_type": "network_connection",
                "source_host": "WORKSTATION-001",
                "dest_host": "DC-001",
                "protocol": "SMB",
            },
        ),
        ScenarioStep(
            step_id="S-004-02",
            description="Admin share access with service account credentials",
            mitre_tactic="TA0008_LATERAL_MOVEMENT",
            mitre_technique="T1021.002",
            expected_detection_rule_ids=["RULE_ADMIN_SHARE_ACCESS"],
            synthetic_event_template={
                "event_type": "share_access",
                "share_path": "\\\\DC-001\\ADMIN$",
                "user": "svc_account",
            },
        ),
    ],
    tags=["lateral_movement"],
)

# ---------------------------------------------------------------------------
# SCENARIO_DNS_ANOMALY
# ---------------------------------------------------------------------------
SCENARIO_DNS_ANOMALY = AttackScenario(
    scenario_id="S-005",
    name="DNS Exfiltration Anomaly",
    description="Adversary uses DNS tunnelling to exfiltrate data or communicate with C2.",
    steps=[
        ScenarioStep(
            step_id="S-005-01",
            description="High query rate to unusual subdomain with long labels",
            mitre_tactic="TA0011_COMMAND_AND_CONTROL",
            mitre_technique="T1071.004",
            expected_detection_rule_ids=["RULE_DNS_TUNNELLING"],
            expected_anomaly_types=["dns_query_volume_spike", "dns_label_length"],
            synthetic_event_template={
                "event_type": "dns_query",
                "query": "base64encodeddata.attacker.com",
                "query_count": 500,
            },
        ),
    ],
    expected_campaign_detected=False,
    tags=["c2", "exfiltration", "dns"],
)

# ---------------------------------------------------------------------------
# SCENARIO_MULTI_STAGE_ATTACK
# ---------------------------------------------------------------------------
SCENARIO_MULTI_STAGE_ATTACK = AttackScenario(
    scenario_id="S-006",
    name="Multi-Stage Attack Chain",
    description=(
        "Full kill-chain: initial access via phishing → execution → privilege "
        "escalation → lateral movement → data exfiltration."
    ),
    steps=[
        ScenarioStep(
            step_id="S-006-01",
            description="Phishing email with malicious attachment opened",
            mitre_tactic="TA0001_INITIAL_ACCESS",
            mitre_technique="T1566.001",
            expected_detection_rule_ids=["RULE_PHISHING_ATTACHMENT"],
            synthetic_event_template={
                "event_type": "email_attachment_open",
                "attachment": "invoice.doc",
            },
        ),
        ScenarioStep(
            step_id="S-006-02",
            description="Macro execution drops payload",
            mitre_tactic="TA0002_EXECUTION",
            mitre_technique="T1059.005",
            expected_detection_rule_ids=["RULE_MACRO_EXECUTION"],
            synthetic_event_template={"event_type": "macro_exec", "host": "VICTIM-PC"},
        ),
        ScenarioStep(
            step_id="S-006-03",
            description="Token impersonation for privilege escalation",
            mitre_tactic="TA0004_PRIVILEGE_ESCALATION",
            mitre_technique="T1134",
            expected_detection_rule_ids=["RULE_TOKEN_IMPERSONATION"],
            expected_anomaly_types=["privilege_spike"],
            synthetic_event_template={"event_type": "token_impersonation", "user": "SYSTEM"},
        ),
        ScenarioStep(
            step_id="S-006-04",
            description="Lateral movement via RDP to server",
            mitre_tactic="TA0008_LATERAL_MOVEMENT",
            mitre_technique="T1021.001",
            expected_detection_rule_ids=["RULE_LATERAL_MOVEMENT_RDP"],
            synthetic_event_template={"event_type": "rdp_session", "dest_host": "FILE-SERVER"},
        ),
        ScenarioStep(
            step_id="S-006-05",
            description="Large file transfer to external IP",
            mitre_tactic="TA0010_EXFILTRATION",
            mitre_technique="T1041",
            expected_detection_rule_ids=["RULE_DATA_EXFILTRATION"],
            expected_anomaly_types=["volume_exfiltration"],
            synthetic_event_template={
                "event_type": "file_transfer",
                "dest_ip": "198.51.100.77",
                "bytes": 50_000_000,
            },
        ),
    ],
    expected_campaign_detected=True,
    expected_attack_path_detected=True,
    tags=["multi_stage", "full_kill_chain", "apt"],
)

# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
ALL_SCENARIOS: list[AttackScenario] = [
    SCENARIO_AUTH_BRUTE_FORCE,
    SCENARIO_PORT_SCAN,
    SCENARIO_REMOTE_ACCESS_ABUSE,
    SCENARIO_SUSPICIOUS_LATERAL_CONNECTION,
    SCENARIO_DNS_ANOMALY,
    SCENARIO_MULTI_STAGE_ATTACK,
]
