"""Phase 7 Test: Production Defaults Validation.

Verifies:
- Rule 150/151: Production defaults enforce security baseline
- Default RuntimeConfiguration is safe for development
- Production profile explicitly requires secure configuration
- Insecure secret list is complete and effective
"""

import pytest
from ulpf_api.profile import ProductionConfigValidator, RuntimeConfiguration
from ulpf_security.errors import SecurityConfigurationError


def test_default_config_is_development_profile() -> None:
    """Default profile must be 'development', not 'production'."""
    config = RuntimeConfiguration()
    assert config.profile == "development"


def test_default_config_has_auth_enabled() -> None:
    config = RuntimeConfiguration()
    assert config.enable_auth is True


def test_known_insecure_secrets_rejected_in_production() -> None:
    insecure_secrets = [
        "secret",
        "changeme",
        "admin",
        "123456",
        "default",
        "ulpf-phase7-hardened-key-32bytes-min",
    ]
    for secret in insecure_secrets:
        config = RuntimeConfiguration(
            profile="production",
            debug=False,
            jwt_secret=secret,
            database_url="sqlite:///prod.db",
            enable_auth=True,
        )
        with pytest.raises(SecurityConfigurationError):
            ProductionConfigValidator.validate(config)


def test_high_entropy_secret_accepted_in_production() -> None:
    config = RuntimeConfiguration(
        profile="production",
        debug=False,
        jwt_secret="x9Km3vPqL7hRwYnJbFdTsQeAuCzOiGlN",  # 32+ chars, high entropy
        database_url="sqlite:///data/prod.db",
        enable_auth=True,
    )
    ProductionConfigValidator.validate(config)  # Must not raise


def test_test_profile_not_blocked() -> None:
    """Test profile must not block startup (used in CI)."""
    config = RuntimeConfiguration(
        profile="test",
        debug=True,
        jwt_secret="test-only-key",
        database_url="sqlite:///:memory:",
        enable_auth=False,
    )
    ProductionConfigValidator.validate(config)


def test_airgap_profile_not_blocked() -> None:
    """Air-gap profile must not block startup."""
    config = RuntimeConfiguration(
        profile="airgap",
        debug=False,
        jwt_secret="airgap-local-key",
        database_url="sqlite:///data/airgap.db",
        enable_auth=True,
    )
    ProductionConfigValidator.validate(config)


def test_production_requires_at_least_32_char_secret() -> None:
    # Exactly 31 chars: rejected
    config31 = RuntimeConfiguration(
        profile="production",
        debug=False,
        jwt_secret="a" * 31,
        database_url="sqlite:///prod.db",
        enable_auth=True,
    )
    with pytest.raises(SecurityConfigurationError):
        ProductionConfigValidator.validate(config31)

    # Exactly 32 chars: accepted
    config32 = RuntimeConfiguration(
        profile="production",
        debug=False,
        jwt_secret="a" * 32,
        database_url="sqlite:///prod.db",
        enable_auth=True,
    )
    ProductionConfigValidator.validate(config32)
