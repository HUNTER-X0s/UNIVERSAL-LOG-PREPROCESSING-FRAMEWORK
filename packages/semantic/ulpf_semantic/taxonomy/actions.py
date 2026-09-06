"""Controlled Semantic Action Taxonomy for ULPF Phase 4.

Preserves original, normalized, and mapped semantic actions without loss
of vendor distinctions.
"""

from enum import Enum

from ulpf_semantic.models import SemanticAction


class ActionTaxonomy(str, Enum):
    """Controlled semantic action vocabulary."""

    ALLOW = "allow"
    DENY = "deny"
    DROP = "drop"
    REJECT = "reject"
    ACCEPT = "accept"
    ALERT = "alert"
    BLOCK = "block"
    QUARANTINE = "quarantine"
    LOGIN = "login"
    LOGOUT = "logout"
    CREATE = "create"
    DELETE = "delete"
    MODIFY = "modify"
    EXECUTE = "execute"
    READ = "read"
    WRITE = "write"
    CONNECT = "connect"
    DISCONNECT = "disconnect"
    START = "start"
    STOP = "stop"
    AUTHENTICATE = "authenticate"
    AUTHORIZE = "authorize"
    FAIL = "fail"
    UNKNOWN = "unknown"


# Mapping from vendor/normalized action tokens to controlled semantic actions
ACTION_MAPPING: dict[str, ActionTaxonomy] = {
    # Permissive
    "allow": ActionTaxonomy.ALLOW,
    "allowed": ActionTaxonomy.ALLOW,
    "permit": ActionTaxonomy.ALLOW,
    "permitted": ActionTaxonomy.ALLOW,
    "accept": ActionTaxonomy.ALLOW,
    "accepted": ActionTaxonomy.ALLOW,
    "pass": ActionTaxonomy.ALLOW,
    "passed": ActionTaxonomy.ALLOW,
    "forward": ActionTaxonomy.ALLOW,
    "ok": ActionTaxonomy.ALLOW,
    "success": ActionTaxonomy.ALLOW,
    # Restrictive / Drops
    "drop": ActionTaxonomy.DROP,
    "dropped": ActionTaxonomy.DROP,
    "discard": ActionTaxonomy.DROP,
    "discarded": ActionTaxonomy.DROP,
    "deny": ActionTaxonomy.DENY,
    "denied": ActionTaxonomy.DENY,
    "reject": ActionTaxonomy.REJECT,
    "rejected": ActionTaxonomy.REJECT,
    "block": ActionTaxonomy.BLOCK,
    "blocked": ActionTaxonomy.BLOCK,
    "prevent": ActionTaxonomy.BLOCK,
    "prevented": ActionTaxonomy.BLOCK,
    "quarantine": ActionTaxonomy.QUARANTINE,
    "quarantined": ActionTaxonomy.QUARANTINE,
    "isolate": ActionTaxonomy.QUARANTINE,
    # Alerts / Detection
    "alert": ActionTaxonomy.ALERT,
    "alerted": ActionTaxonomy.ALERT,
    "notice": ActionTaxonomy.ALERT,
    "warning": ActionTaxonomy.ALERT,
    "threat": ActionTaxonomy.ALERT,
    # Authentication & Access
    "login": ActionTaxonomy.LOGIN,
    "logon": ActionTaxonomy.LOGIN,
    "signin": ActionTaxonomy.LOGIN,
    "logout": ActionTaxonomy.LOGOUT,
    "logoff": ActionTaxonomy.LOGOUT,
    "signout": ActionTaxonomy.LOGOUT,
    "auth": ActionTaxonomy.AUTHENTICATE,
    "authenticate": ActionTaxonomy.AUTHENTICATE,
    # CRUD / Lifecycle
    "create": ActionTaxonomy.CREATE,
    "created": ActionTaxonomy.CREATE,
    "add": ActionTaxonomy.CREATE,
    "delete": ActionTaxonomy.DELETE,
    "deleted": ActionTaxonomy.DELETE,
    "remove": ActionTaxonomy.DELETE,
    "destroy": ActionTaxonomy.DELETE,
    "modify": ActionTaxonomy.MODIFY,
    "modified": ActionTaxonomy.MODIFY,
    "update": ActionTaxonomy.MODIFY,
    "change": ActionTaxonomy.MODIFY,
    "start": ActionTaxonomy.START,
    "started": ActionTaxonomy.START,
    "stop": ActionTaxonomy.STOP,
    "stopped": ActionTaxonomy.STOP,
    "terminate": ActionTaxonomy.STOP,
    "connect": ActionTaxonomy.CONNECT,
    "connected": ActionTaxonomy.CONNECT,
    "disconnect": ActionTaxonomy.DISCONNECT,
    "disconnected": ActionTaxonomy.DISCONNECT,
    "execute": ActionTaxonomy.EXECUTE,
    "executed": ActionTaxonomy.EXECUTE,
    "read": ActionTaxonomy.READ,
    "write": ActionTaxonomy.WRITE,
}


def map_action(original: str | None, normalized: str | None) -> SemanticAction:
    """Map source and normalized action strings to a SemanticAction model."""
    token = (normalized or original or "").strip().lower()
    if not token:
        return SemanticAction(
            semantic=ActionTaxonomy.UNKNOWN.value,
            original=original,
            normalized=normalized,
            mapping_rule="default.action.unknown",
        )

    matched = ACTION_MAPPING.get(token)
    if matched:
        return SemanticAction(
            semantic=matched.value,
            original=original,
            normalized=normalized,
            mapping_rule=f"taxonomy.action.{matched.value}",
        )

    # Substring heuristic checks for compound phrases (e.g., 'teardown TCP connection')
    for prefix, act in ACTION_MAPPING.items():
        if prefix in token:
            return SemanticAction(
                semantic=act.value,
                original=original,
                normalized=normalized,
                mapping_rule=f"heuristic.action.{act.value}",
            )

    return SemanticAction(
        semantic=token[:32],
        original=original,
        normalized=normalized,
        mapping_rule="passthrough.action.unmapped",
    )
