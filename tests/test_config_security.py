"""Phase 7 Test: Configuration Security.

Verifies:
- Rule 151: Production profile rejects debug=True
- Rule 151: Production profile rejects default/weak JWT secret
- Rule 151: Production profile rejects in-memory database
- Rule 151: Auth disabled in production is rejected
- Rule 150: Development profile is more permissive
"""

import pytest
from ulpf_api.profile import ProductionConfigValidator, RuntimeConfiguration
from ulpf_security.errors import SecurityConfigurationError


def test_valid_production_config_passes() -> None:
    config = RuntimeConfiguration(
        profile="production",
        debug=False,
        jwt_secret="a-valid-high-entropy-production-key-256bits",
        database_url="postgresql://user:pass@host:5432/ulpf_prod",
        enable_auth=True,
    )
    ProductionConfigValidator.validate(config)  # Should not raise


def test_production_debug_true_rejected() -> None:
    config = RuntimeConfiguration(
        profile="production",
        debug=True,
        jwt_secret="a-valid-high-entropy-production-key-256bits",
        database_url="postgresql://user:pass@host/ulpf",
        enable_auth=True,
    )
    with pytest.raises(SecurityConfigurationError, match="debug"):
        ProductionConfigValidator.validate(config)


def test_production_default_jwt_secret_rejected() -> None:
    config = RuntimeConfiguration(
        profile="production",
        debug=False,
        jwt_secret="changeme",
        database_url="sqlite:///data/prod.db",
        enable_auth=True,
    )
    with pytest.raises(SecurityConfigurationError, match="[Jj][Ww][Tt]|secret|key"):
        ProductionConfigValidator.validate(config)


def test_production_short_jwt_secret_rejected() -> None:
    config = RuntimeConfiguration(
        profile="production",
        debug=False,
        jwt_secret="short",  # Less than 32 chars
        database_url="sqlite:///data/prod.db",
        enable_auth=True,
    )
    with pytest.raises(SecurityConfigurationError):
        ProductionConfigValidator.validate(config)


def test_production_in_memory_db_rejected() -> None:
    config = RuntimeConfiguration(
        profile="production",
        debug=False,
        jwt_secret="a-valid-high-entropy-production-key-256bits",
        database_url="sqlite:///:memory:",
        enable_auth=True,
    )
    with pytest.raises(SecurityConfigurationError, match="[Mm]emory|memory"):
        ProductionConfigValidator.validate(config)


def test_production_auth_disabled_rejected() -> None:
    config = RuntimeConfiguration(
        profile="production",
        debug=False,
        jwt_secret="a-valid-high-entropy-production-key-256bits",
        database_url="sqlite:///data/prod.db",
        enable_auth=False,
    )
    with pytest.raises(SecurityConfigurationError, match="[Aa]uth"):
        ProductionConfigValidator.validate(config)


def test_development_profile_allows_debug() -> None:
    """Development profile does not validate production security rules."""
    config = RuntimeConfiguration(
        profile="development",
        debug=True,
        jwt_secret="weak",
        database_url="sqlite:///:memory:",
        enable_auth=False,
    )
    # Should not raise for development profile
    ProductionConfigValidator.validate(config)
