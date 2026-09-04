"""Configuration validation tests for the foundation shell."""

import os
import unittest
from unittest.mock import patch

from ulpf_platform.config import AppSettings, ConfigurationError


class ConfigurationTests(unittest.TestCase):
    """Prove malformed environment values fail safely."""

    def test_defaults_are_development_safe(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            settings = AppSettings.from_environment()
        self.assertEqual(settings.environment, "development")
        self.assertEqual(settings.request_max_bytes, 1_048_576)

    def test_invalid_limit_is_rejected_without_echoing_value(self) -> None:
        with patch.dict(os.environ, {"ULPF_REQUEST_MAX_BYTES": "unbounded"}, clear=True):
            with self.assertRaises(ConfigurationError) as captured:
                AppSettings.from_environment()
        self.assertNotIn("unbounded", str(captured.exception))

    def test_invalid_environment_is_rejected(self) -> None:
        with patch.dict(os.environ, {"ULPF_ENVIRONMENT": "cloud"}, clear=True):
            with self.assertRaises(ConfigurationError):
                AppSettings.from_environment()
