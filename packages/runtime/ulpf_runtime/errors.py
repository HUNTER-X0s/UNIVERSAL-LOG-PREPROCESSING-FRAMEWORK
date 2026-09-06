"""Typed operational and infrastructure error taxonomy for ULPF Phase 6."""

from typing import Any


class UlpfOperationalError(Exception):
    """Base exception for all operational and runtime infrastructure errors."""

    def __init__(
        self, message: str, *, error_code: str, details: dict[str, Any] | None = None
    ) -> None:
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}


class TransportError(UlpfOperationalError):
    """Raised when transport/network ingestion fails."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message, error_code="TRANSPORT_ERROR", details=details)


class BufferFullError(UlpfOperationalError):
    """Raised when stream buffer or queue capacity is exhausted (backpressure rejection)."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message, error_code="BUFFER_FULL", details=details)


class PersistenceError(UlpfOperationalError):
    """Raised when storage write or retrieval fails."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message, error_code="PERSISTENCE_ERROR", details=details)


class StorageIntegrityError(UlpfOperationalError):
    """Raised when stored data fails cryptographic integrity verification."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message, error_code="STORAGE_INTEGRITY_ERROR", details=details)


class DeliveryError(UlpfOperationalError):
    """Raised when downstream projection or SIEM delivery fails."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message, error_code="DELIVERY_ERROR", details=details)


class RetryExhaustedError(UlpfOperationalError):
    """Raised when a processing or delivery attempt exhausts maximum retries."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message, error_code="RETRY_EXHAUSTED", details=details)


class ReplayError(UlpfOperationalError):
    """Raised when historical replay violates safety or pinning requirements."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message, error_code="REPLAY_ERROR", details=details)


class ConfigurationError(UlpfOperationalError):
    """Raised when runtime configuration fails validation or security constraints."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message, error_code="CONFIGURATION_ERROR", details=details)


class AuthorizationError(UlpfOperationalError):
    """Raised when an administrative or API operation lacks required privileges."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message, error_code="AUTHORIZATION_ERROR", details=details)


class QueryValidationError(UlpfOperationalError):
    """Raised when an external query violates safety, limits, or structure constraints."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message, error_code="QUERY_VALIDATION_ERROR", details=details)


class DependencyUnavailableError(UlpfOperationalError):
    """Raised when an external operational dependency is unavailable."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message, error_code="DEPENDENCY_UNAVAILABLE", details=details)
