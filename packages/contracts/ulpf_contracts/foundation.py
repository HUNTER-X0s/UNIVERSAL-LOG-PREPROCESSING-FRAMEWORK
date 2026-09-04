"""Typed models for Phase 1 foundation endpoints, not ULPF business contracts."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ErrorEnvelope(BaseModel):
    """Stable, safe HTTP error response model."""

    model_config = ConfigDict(extra="forbid")

    code: str
    message: str
    request_id: str
    correlation_id: str
    trace_id: str
    retryable: bool = False
    timestamp: datetime
    details: dict[str, str] | None = None


class HealthResponse(BaseModel):
    """Health/readiness/liveness response model."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["healthy", "ready", "alive"]
    service: str
    environment: str
    timestamp: datetime
    request_id: str
    correlation_id: str
    trace_id: str


class MetadataResponse(BaseModel):
    """Accurate API shell metadata."""

    model_config = ConfigDict(extra="forbid")

    service: str
    environment: str
    api_version: str
    phase: str
    capabilities: list[str] = Field(default_factory=list)
    deferred_capabilities: list[str] = Field(default_factory=list)
