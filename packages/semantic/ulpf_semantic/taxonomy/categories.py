"""Controlled Semantic Taxonomy for ULPF Phase 4.

Defines versioned enums for Category, Class, and Type forming
the explainable (Category, Class, Type) semantic triple.
"""

from enum import Enum


class EventCategory(str, Enum):
    """Controlled versioned taxonomy of event categories."""

    NETWORK = "NETWORK"
    SECURITY = "SECURITY"
    IDENTITY = "IDENTITY"
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION = "AUTHORIZATION"
    SYSTEM = "SYSTEM"
    PROCESS = "PROCESS"
    FILE = "FILE"
    APPLICATION = "APPLICATION"
    WEB = "WEB"
    DATABASE = "DATABASE"
    CLOUD = "CLOUD"
    CONTAINER = "CONTAINER"
    KUBERNETES = "KUBERNETES"
    VPN = "VPN"
    DNS = "DNS"
    DHCP = "DHCP"
    HTTP = "HTTP"
    TLS = "TLS"
    IDS = "IDS"
    IPS = "IPS"
    FIREWALL = "FIREWALL"
    PROXY = "PROXY"
    AUDIT = "AUDIT"
    CONFIGURATION = "CONFIGURATION"
    OBSERVABILITY = "OBSERVABILITY"
    MESSAGE_BROKER = "MESSAGE_BROKER"
    INFRASTRUCTURE = "INFRASTRUCTURE"
    OTHER = "OTHER"


class EventClass(str, Enum):
    """Controlled classes describing functional domain within a category."""

    NETWORK_ACTIVITY = "Network Activity"
    SECURITY_FINDING = "Security Finding"
    DETECTION_FINDING = "Detection Finding"
    FIREWALL = "Firewall"
    IDS_IPS = "IDS/IPS"
    AUTHENTICATION = "Authentication"
    ACCOUNT_CHANGE = "Account Change"
    AUTHORIZATION = "Authorization"
    PROCESS_ACTIVITY = "Process Activity"
    FILE_ACTIVITY = "File Activity"
    HTTP_ACTIVITY = "HTTP Activity"
    DNS_ACTIVITY = "DNS Activity"
    CLOUD_API = "Cloud API"
    CONTAINER_LIFECYCLE = "Container Lifecycle"
    DATABASE_ACTIVITY = "Database Activity"
    APPLICATION_LIFECYCLE = "Application Lifecycle"
    SYSTEM_ACTIVITY = "System Activity"
    AUDIT_LOG = "Audit Log"
    UNKNOWN = "Unknown"


class EventType(str, Enum):
    """Granular semantic event types describing specific occurrences."""

    # Firewall / Network Security
    FIREWALL_DENY = "firewall.deny"
    FIREWALL_ALLOW = "firewall.allow"
    FIREWALL_DROP = "firewall.drop"
    FIREWALL_RESET = "firewall.reset"

    # IDS / IPS / Threat Detection
    IDS_ALERT = "ids.alert"
    MALWARE_DETECTED = "malware.detected"
    POLICY_VIOLATION = "security.policy_violation"

    # Network Flow / Connection
    NETWORK_CONNECTION = "network.connection"
    NETWORK_FLOW = "network.flow"
    DNS_QUERY = "dns.query"
    DNS_RESPONSE = "dns.response"
    HTTP_REQUEST = "http.request"
    HTTP_RESPONSE = "http.response"
    VPN_SESSION = "vpn.session"

    # Identity / Access
    USER_AUTHENTICATION = "user.authentication"
    USER_AUTHORIZATION = "user.authorization"
    ACCOUNT_CREATED = "account.created"
    ACCOUNT_MODIFIED = "account.modified"
    ACCOUNT_DELETED = "account.deleted"

    # System & Host
    PROCESS_STARTED = "process.started"
    PROCESS_TERMINATED = "process.terminated"
    FILE_CREATED = "file.created"
    FILE_MODIFIED = "file.modified"
    FILE_DELETED = "file.deleted"
    SYSTEM_REBOOT = "system.reboot"

    # Cloud & Container
    CLOUD_API_CALL = "cloud.api_call"
    CONTAINER_STARTED = "container.started"
    CONTAINER_STOPPED = "container.stopped"
    KUBERNETES_AUDIT = "kubernetes.audit"

    # Database & Application
    DATABASE_QUERY = "database.query"
    DATABASE_ERROR = "database.error"
    APPLICATION_LOG = "application.log"
    APPLICATION_EXCEPTION = "application.exception"
    WEB_ACCESS = "web.access"
    WEB_ERROR = "web.error"

    # Generic / Unknown
    GENERIC_TELEMETRY = "generic.telemetry"
    UNKNOWN = "unknown"
