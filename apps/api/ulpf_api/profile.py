"""Production profile validator and security self-check for ULPF Phase 7.

Enforces:
- Rule 149: Security baseline
- Rule 150: Development vs production profile separation
- Rule 151: Production config validation (rejects debug, default keys, plaintext, in-memory DB)
- Rule 152: Startup security self-check
"""

from dataclasses import dataclass

from ulpf_security.errors import SecurityConfigurationError


@dataclass(frozen=True)
class RuntimeConfiguration:
    """Consolidated runtime and deployment configuration."""

    profile: str = "development"  # production, development, test, airgap
    debug: bool = False
    jwt_secret: str = "ulpf-phase7-hardened-key-32bytes-min"  # noqa: S105
    database_url: str = "sqlite:///data/ulpf_operational.db"
    enable_auth: bool = True
    enable_rate_limiting: bool = True
    require_tls: bool = False
    allowed_hosts: tuple[str, ...] = ("localhost", "127.0.0.1")


class ProductionConfigValidator:
    """Validates configuration at process startup, preventing insecure deployment."""

    INSECURE_SECRETS: frozenset[str] = frozenset({
        "secret",
        "changeme",
        "admin",
        "123456",
        "default",
        "ulpf-phase7-hardened-key-32bytes-min",
    })

    @classmethod
    def validate(cls, config: RuntimeConfiguration) -> None:
        profile = config.profile.lower().strip()

        if profile == "production":
            # 1. Debug mode strictly forbidden in production
            if config.debug:
                raise SecurityConfigurationError(
                    "Startup rejected: 'debug=True' is strictly forbidden in production profile"
                )

            # 2. Insecure or default JWT secret strictly forbidden
            if not config.jwt_secret or config.jwt_secret in cls.INSECURE_SECRETS:
                raise SecurityConfigurationError(
                    "Startup rejected: Default or weak JWT secret detected in production profile. "
                    "Must set a high-entropy secret via ULPF_JWT_SECRET"
                )

            if len(config.jwt_secret) < 32:
                raise SecurityConfigurationError(
                    "Startup rejected: JWT secret must be at least 32 characters long "
                    "in production profile"
                )

            # 3. Authentication must be enabled
            if not config.enable_auth:
                raise SecurityConfigurationError(
                    "Startup rejected: Authentication cannot be disabled in production profile"
                )

            # 4. Volatile in-memory databases strictly forbidden for production persistence
            if ":memory:" in config.database_url or config.database_url.startswith("memory://"):
                raise SecurityConfigurationError(
                    "Startup rejected: In-memory database is forbidden in production profile. "
                    "Must configure persistent relational storage (PostgreSQL or durable "
                    "SQLite file)"
                )
