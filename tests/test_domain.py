"""Framework-independent domain primitive tests."""

import unittest
from datetime import UTC, datetime

from ulpf_domain.primitives import UtcTimestamp


class DomainPrimitiveTests(unittest.TestCase):
    """Prove time primitives reject ambiguous local timestamps."""

    def test_timestamp_normalizes_aware_input_to_utc(self) -> None:
        timestamp = UtcTimestamp(datetime(2026, 1, 1, tzinfo=UTC))
        self.assertEqual(timestamp.value.tzinfo, UTC)

    def test_timestamp_rejects_naive_input(self) -> None:
        with self.assertRaises(ValueError):
            UtcTimestamp(datetime(2026, 1, 1))
