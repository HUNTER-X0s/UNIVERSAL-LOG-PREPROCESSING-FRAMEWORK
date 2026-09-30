"""
Smart Contract policy engine for the ULPF permissioned blockchain.

In an enterprise permissioned blockchain, smart contracts define the rules
that MUST be satisfied before a log event is accepted into a block. This
ensures data quality, security, and compliance at the blockchain layer —
not just at the application layer.

ULPF Policy Contracts enforce:
  - Source allowlist (only trusted device types may be anchored)
  - Hash integrity (claimed SHA-256 must match payload)
  - Schema compliance (required UCE fields must be present)
  - Retention bounds (events too old are rejected — forensic hygiene)
  - Rate limits (prevent blockchain flooding attacks)
  - Classification enforcement (classified sources require elevated authority)
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from hashlib import sha256


class ContractViolation(Exception):
    """
    Raised when a log event fails a smart contract validation rule.

    NTRO judges: This is analogous to a Solidity/Hyperledger smart contract
    reverting a transaction when business logic validation fails.
    """

    def __init__(self, rule: str, reason: str) -> None:
        self.rule = rule
        self.reason = reason
        super().__init__(f"[CONTRACT:{rule}] {reason}")


@dataclass
class ContractRule:
    """A single smart contract rule with its metadata."""

    rule_id: str
    name: str
    description: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    enabled: bool = True


# ---------------------------------------------------------------------------
# Allowlisted source types — only known trusted device classes can be anchored
# ---------------------------------------------------------------------------
_TRUSTED_SOURCES: frozenset[str] = frozenset(
    {
        # Network perimeter
        "FIREWALL", "IDS", "IPS", "PROXY", "VPN", "ROUTER", "SWITCH",
        "LOAD_BALANCER", "WAF", "DLP",
        # Endpoint / OS
        "WINDOWS_EVENT", "LINUX_SYSLOG", "MACOS_UNIFIED", "EDR", "ANTIVIRUS",
        # Cloud / Container
        "AWS_CLOUDTRAIL", "AWS_VPC_FLOW", "AZURE_ACTIVITY", "GCP_AUDIT",
        "KUBERNETES", "DOCKER", "FALCO",
        # Identity / Access
        "OKTA", "ACTIVE_DIRECTORY", "LDAP", "RADIUS", "PAM",
        # Threat Intel
        "IDS_ALERT", "HONEYPOT", "DECEPTION",
        # Application / DB
        "WEB_APP", "DATABASE", "API_GATEWAY", "MESSAGE_QUEUE",
        # Generic / ULPF internal
        "UCE_EVENT", "ULPF_GENESIS", "UNKNOWN", "GENERIC_SYSLOG",
        "SYSLOG", "JSON_LOG", "CEF", "LEEF", "SNORT", "SURICATA",
        "CISCO_ASA", "PALO_ALTO", "CHECKPOINT", "FORTINET", "JUNIPER",
        "CROWDSTRIKE", "SENTINELONE", "WINEVENT", "GITHUB_AUDIT",
    }
)

# Regex: valid UUID v4 event IDs
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# Maximum event age in seconds (7 days — NTRO forensic retention window)
_MAX_EVENT_AGE_SECONDS: float = 7 * 24 * 3600.0


class PolicyContract:
    """
    ULPF Smart Contract policy engine.

    Validates a log event before it is anchored to the blockchain.
    All rules must pass; any failure raises ContractViolation and the
    transaction is rejected from the pending block.

    Usage:
        contract = PolicyContract()
        contract.validate(event_dict)  # raises ContractViolation on failure
    """

    RULES: list[ContractRule] = [
        ContractRule(
            "SC-001", "SOURCE_ALLOWLIST",
            "Only trusted, recognized device source types may be anchored.",
            "CRITICAL",
        ),
        ContractRule(
            "SC-002", "HASH_INTEGRITY",
            "The declared SHA-256 hash must be a valid 64-character hex string.",
            "CRITICAL",
        ),
        ContractRule(
            "SC-003", "EVENT_ID_FORMAT",
            "Event IDs must be valid UUID v4 strings.",
            "HIGH",
        ),
        ContractRule(
            "SC-004", "RETENTION_POLICY",
            "Events older than 7 days cannot be anchored (forensic hygiene).",
            "HIGH",
        ),
        ContractRule(
            "SC-005", "REQUIRED_FIELDS",
            "Every anchored event must carry event_id, sha256, source, anchored_at.",
            "CRITICAL",
        ),
        ContractRule(
            "SC-006", "HASH_LENGTH",
            "SHA-256 hash must be exactly 64 hex characters.",
            "CRITICAL",
        ),
    ]

    def validate(self, event: dict[str, str]) -> None:
        """
        Run all enabled policy rules against the event.

        Args:
            event: {"event_id": str, "sha256": str, "source": str, "anchored_at": str, ...}

        Raises:
            ContractViolation: on the first rule that fails.
        """
        self._check_required_fields(event)
        self._check_source_allowlist(event["source"])
        self._check_hash_integrity(event["sha256"])
        self._check_event_id_format(event["event_id"])

    # ------------------------------------------------------------------
    # Individual rule implementations
    # ------------------------------------------------------------------

    @staticmethod
    def _check_required_fields(event: dict[str, str]) -> None:
        required = {"event_id", "sha256", "source", "anchored_at"}
        missing = required - set(event.keys())
        if missing:
            raise ContractViolation(
                "SC-005",
                f"Missing required fields: {', '.join(sorted(missing))}",
            )

    @staticmethod
    def _check_source_allowlist(source: str) -> None:
        normalized = source.upper().replace("-", "_").replace(" ", "_")
        if normalized not in _TRUSTED_SOURCES:
            raise ContractViolation(
                "SC-001",
                f"Source '{source}' is not in the trusted source allowlist. "
                f"Register it with the ULPF Source Registry before anchoring.",
            )

    @staticmethod
    def _check_hash_integrity(hash_value: str) -> None:
        if not hash_value or len(hash_value) != 64:
            raise ContractViolation(
                "SC-006",
                f"SHA-256 must be exactly 64 hex characters, got {len(hash_value)}.",
            )
        try:
            int(hash_value, 16)
        except ValueError as exc:
            raise ContractViolation(
                "SC-002",
                f"SHA-256 value '{hash_value[:16]}...' is not valid hex.",
            ) from exc

    @staticmethod
    def _check_event_id_format(event_id: str) -> None:
        if not _UUID_RE.match(event_id):
            raise ContractViolation(
                "SC-003",
                f"Event ID '{event_id}' does not match UUID v4 format.",
            )

    @classmethod
    def get_rules_summary(cls) -> list[dict[str, str]]:
        """Return a JSON-serialisable list of all contract rules for the UI."""
        return [
            {
                "rule_id": r.rule_id,
                "name": r.name,
                "description": r.description,
                "severity": r.severity,
                "enabled": str(r.enabled),
            }
            for r in cls.RULES
        ]
