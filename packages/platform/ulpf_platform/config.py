"""Typed, environment-derived configuration with no embedded secrets."""

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    field_validator,
    model_validator,
)

Environment = Literal["development", "test", "demo", "production", "air-gapped"]


class AppSettings(BaseModel):
    """Non-secret configuration required by the Phase 1 process shells."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    environment: Environment = "development"
    service_name: str = Field(default="ulpf-api", min_length=1, max_length=64)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    request_max_bytes: int = Field(default=1_048_576, ge=1_024, le=16_777_216)
    intake_max_event_bytes: int = Field(default=1_048_576, ge=1, le=16_777_216)
    intake_max_http_header_bytes: int = Field(default=16_384, ge=1_024, le=65_536)
    intake_http_requests_per_minute: int = Field(default=600, ge=1, le=100_000)
    intake_tcp_enabled: bool = False
    intake_tcp_host: str = Field(default="127.0.0.1", min_length=1, max_length=255)
    intake_tcp_port: int = Field(default=5514, ge=1, le=65_535)
    intake_udp_enabled: bool = False
    intake_udp_host: str = Field(default="127.0.0.1", min_length=1, max_length=255)
    intake_udp_port: int = Field(default=5514, ge=1, le=65_535)
    intake_max_connections: int = Field(default=64, ge=1, le=1_024)
    intake_read_timeout_seconds: float = Field(default=5.0, gt=0, le=60.0)
    intake_evidence_directory: Path = Path("data/evidence")
    intake_evidence_max_events: int = Field(default=10_000, ge=1, le=1_000_000)
    intake_evidence_max_bytes: int = Field(default=1_073_741_824, ge=1_024, le=1_073_741_824_000)
    intake_auth_token: SecretStr | None = None
    intake_development_retrieval_enabled: bool = False
    api_prefix: str = "/api/v1"
    api_documentation_enabled: bool = True

    @field_validator("api_prefix")
    @classmethod
    def validate_api_prefix(cls, value: str) -> str:
        if not value.startswith("/") or value.endswith("/"):
            raise ValueError("api_prefix must start with one slash and not end with a slash")
        return value

    @field_validator("intake_evidence_directory")
    @classmethod
    def validate_evidence_directory(cls, value: Path) -> Path:
        """Reject empty paths while leaving environment-specific placement configurable."""
        if not str(value).strip():
            raise ValueError("intake_evidence_directory must not be empty")
        return value

    @model_validator(mode="after")
    def validate_intake_limits(self) -> "AppSettings":
        """Ensure one configured boundary cannot accept a partial event."""
        if self.intake_max_event_bytes > self.request_max_bytes:
            raise ValueError("intake_max_event_bytes must not exceed request_max_bytes")
        if self.intake_evidence_max_bytes < self.intake_max_event_bytes:
            raise ValueError("intake_evidence_max_bytes must fit one complete event")
        if self.environment == "production" and self.intake_auth_token is None:
            raise ValueError("production intake requires an authentication token")
        return self

    @classmethod
    def from_environment(cls) -> "AppSettings":
        """Load the explicit allowed environment variables and reject invalid values."""
        values = {
            "environment": os.getenv("ULPF_ENVIRONMENT", "development"),
            "service_name": os.getenv("ULPF_SERVICE_NAME", "ulpf-api"),
            "log_level": os.getenv("ULPF_LOG_LEVEL", "INFO").upper(),
            "request_max_bytes": os.getenv("ULPF_REQUEST_MAX_BYTES", "1048576"),
            "intake_max_event_bytes": os.getenv("ULPF_INTAKE_MAX_EVENT_BYTES", "1048576"),
            "intake_max_http_header_bytes": os.getenv("ULPF_INTAKE_MAX_HTTP_HEADER_BYTES", "16384"),
            "intake_http_requests_per_minute": os.getenv(
                "ULPF_INTAKE_HTTP_REQUESTS_PER_MINUTE", "600"
            ),
            "intake_tcp_enabled": os.getenv("ULPF_INTAKE_TCP_ENABLED", "false"),
            "intake_tcp_host": os.getenv("ULPF_INTAKE_TCP_HOST", "127.0.0.1"),
            "intake_tcp_port": os.getenv("ULPF_INTAKE_TCP_PORT", "5514"),
            "intake_udp_enabled": os.getenv("ULPF_INTAKE_UDP_ENABLED", "false"),
            "intake_udp_host": os.getenv("ULPF_INTAKE_UDP_HOST", "127.0.0.1"),
            "intake_udp_port": os.getenv("ULPF_INTAKE_UDP_PORT", "5514"),
            "intake_max_connections": os.getenv("ULPF_INTAKE_MAX_CONNECTIONS", "64"),
            "intake_read_timeout_seconds": os.getenv("ULPF_INTAKE_READ_TIMEOUT_SECONDS", "5.0"),
            "intake_evidence_directory": os.getenv(
                "ULPF_INTAKE_EVIDENCE_DIRECTORY", "data/evidence"
            ),
            "intake_evidence_max_events": os.getenv("ULPF_INTAKE_EVIDENCE_MAX_EVENTS", "10000"),
            "intake_evidence_max_bytes": os.getenv("ULPF_INTAKE_EVIDENCE_MAX_BYTES", "1073741824"),
            "intake_auth_token": os.getenv("ULPF_INTAKE_AUTH_TOKEN"),
            "intake_development_retrieval_enabled": os.getenv(
                "ULPF_INTAKE_DEVELOPMENT_RETRIEVAL_ENABLED", "false"
            ),
            "api_prefix": os.getenv("ULPF_API_PREFIX", "/api/v1"),
            "api_documentation_enabled": os.getenv("ULPF_API_DOCUMENTATION_ENABLED", "true"),
        }
        try:
            return cls.model_validate(values)
        except ValidationError as exc:
            raise ConfigurationError("ULPF foundation configuration is invalid") from exc


class ConfigurationError(RuntimeError):
    """Safe startup failure without exposing raw environment values."""


@lru_cache(maxsize=1)
def get_settings() -> AppSettings:
    """Return cached validated settings for one process lifetime."""
    return AppSettings.from_environment()
