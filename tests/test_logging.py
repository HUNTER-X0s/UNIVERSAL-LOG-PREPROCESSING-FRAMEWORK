"""Structured logging tests."""

import json
import logging
import unittest

from ulpf_platform.correlation import build_context, reset_request_context, set_request_context
from ulpf_platform.logging import JsonFormatter


class LoggingTests(unittest.TestCase):
    """Ensure foundation logs retain operational IDs in JSON form."""

    def test_json_formatter_includes_correlation_fields(self) -> None:
        token = set_request_context(build_context(None, None, None))
        try:
            record = logging.LogRecord(
                "ulpf.test", logging.INFO, "", 0, "foundation event", (), None
            )
            record.component = "test"
            payload = json.loads(JsonFormatter().format(record))
        finally:
            reset_request_context(token)
        self.assertEqual(payload["message"], "foundation event")
        self.assertEqual(payload["component"], "test")
        self.assertTrue(payload["request_id"])
        self.assertTrue(payload["trace_id"])
