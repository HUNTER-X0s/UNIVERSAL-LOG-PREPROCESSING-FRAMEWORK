"""Tests for ULPF Phase 6 downstream delivery sinks and failure isolation."""

import tempfile
import unittest

from ulpf_delivery.interfaces import DeliveryBatch
from ulpf_delivery.sinks import FileExportSink, OCSFJsonSink, OTelBatchSink, SiemMockSink


class TestDeliverySinks(unittest.TestCase):
    def test_fanout_and_failure_isolation(self) -> None:
        ocsf_sink = OCSFJsonSink()
        otel_sink = OTelBatchSink()
        siem_sink = SiemMockSink()

        # Simulate SIEM downstream failure
        siem_sink.set_healthy(False)

        records = [{"class_uid": 4001, "activity_id": 1, "status": "Success"}]
        batch = DeliveryBatch(sink_name="test", records=records, batch_id="b-1")

        # OCSF succeeds
        res_ocsf = ocsf_sink.deliver(batch)
        self.assertTrue(res_ocsf.success)
        self.assertEqual(res_ocsf.delivered_count, 1)

        # OTel succeeds
        res_otel = otel_sink.deliver(batch)
        self.assertTrue(res_otel.success)
        self.assertEqual(res_otel.delivered_count, 1)

        # SIEM fails isolated
        res_siem = siem_sink.deliver(batch)
        self.assertFalse(res_siem.success)
        self.assertEqual(res_siem.failed_count, 1)

        # OCSF and OTel buffers remain intact despite SIEM failure
        self.assertEqual(len(ocsf_sink.get_delivered()), 1)
        self.assertEqual(len(otel_sink.get_delivered()), 1)
        self.assertEqual(len(siem_sink.get_delivered()), 0)

    def test_file_data_lake_sink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            file_sink = FileExportSink(output_dir=tmp_dir)
            batch = DeliveryBatch(
                sink_name="telemetry",
                records=[{"id": 1, "msg": "test"}],
                batch_id="b-file-1",
            )
            res = file_sink.deliver(batch)
            self.assertTrue(res.success)
            self.assertEqual(res.delivered_count, 1)


if __name__ == "__main__":
    unittest.main()
