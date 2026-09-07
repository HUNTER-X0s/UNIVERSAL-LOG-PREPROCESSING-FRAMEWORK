"""Secret management and key rotation abstractions for ULPF Phase 7.

Enforces:
- Rule 14: No hardcoded credentials
- Rule 15: No secrets committed to source
- Rule 13: Graceful cryptographic key rotation
"""

import os
from abc import ABC, abstractmethod
from pathlib import Path

from ulpf_security.errors import SecretNotFoundError, SecurityConfigurationError


class SecretManager(ABC):
    """Abstract interface for secure secret retrieval and lifecycle management."""

    @abstractmethod
    def get_secret(self, key_name: str) -> str:
        """Retrieve the secret string corresponding to key_name."""

    @abstractmethod
    def has_secret(self, key_name: str) -> bool:
        """Check if key_name exists in the store."""


class EnvironmentSecretManager(SecretManager):
    """Retrieves secrets from system environment variables."""

    def __init__(self, prefix: str = "ULPF_SECRET_") -> None:
        self.prefix = prefix

    def get_secret(self, key_name: str) -> str:
        full_key = f"{self.prefix}{key_name.upper()}"
        val = os.environ.get(full_key) or os.environ.get(key_name)
        if not val:
            raise SecretNotFoundError(
                f"Secret '{key_name}' not found in environment (checked {full_key})"
            )
        return val

    def has_secret(self, key_name: str) -> bool:
        full_key = f"{self.prefix}{key_name.upper()}"
        return bool(os.environ.get(full_key) or os.environ.get(key_name))


class FileSecretManager(SecretManager):
    """Retrieves secrets mounted from filesystem files (e.g. Docker/Kubernetes secrets)."""

    def __init__(self, secrets_dir: str | Path) -> None:
        self.secrets_dir = Path(secrets_dir).resolve()

    def get_secret(self, key_name: str) -> str:
        secret_path = (self.secrets_dir / key_name).resolve()
        if not str(secret_path).startswith(str(self.secrets_dir)):
            raise SecurityConfigurationError(
                f"Directory traversal attempt in secret key: {key_name}"
            )
        if not secret_path.is_file():
            raise SecretNotFoundError(f"Secret file not found: {secret_path}")
        return secret_path.read_text(encoding="utf-8").strip()

    def has_secret(self, key_name: str) -> bool:
        secret_path = (self.secrets_dir / key_name).resolve()
        return str(secret_path).startswith(str(self.secrets_dir)) and secret_path.is_file()


class KeyRotationManager:
    """Manages active and previous keys for graceful verification during key rotation windows."""

    def __init__(self, active_key_id: str, keys: dict[str, str]) -> None:
        if active_key_id not in keys:
            raise SecurityConfigurationError(f"Active key id '{active_key_id}' must be in keys map")
        self._active_key_id = active_key_id
        self._keys: dict[str, str] = dict(keys)

    @property
    def active_key_id(self) -> str:
        return self._active_key_id

    def get_active_key(self) -> tuple[str, str]:
        """Returns (key_id, key_value) for signing/encryption."""
        return self._active_key_id, self._keys[self._active_key_id]

    def get_verification_key(self, key_id: str) -> str:
        """Retrieves key by id for signature/decrypt verification."""
        if key_id not in self._keys:
            raise SecretNotFoundError(f"Key id '{key_id}' not found in active/previous keyring")
        return self._keys[key_id]

    def rotate_to_new_key(
        self, new_key_id: str, new_key_value: str, keep_previous: bool = True
    ) -> None:
        """Sets a new active key while preserving previous keys for seamless verification."""
        if not keep_previous:
            self._keys.clear()
        self._keys[new_key_id] = new_key_value
        self._active_key_id = new_key_id

    def list_key_ids(self) -> list[str]:
        return list(self._keys.keys())
