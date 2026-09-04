"""Deterministic local tests for Phase 2 TCP, UDP, and fixture adapters."""

import asyncio
import tempfile
import unittest
from pathlib import Path

from ulpf_ingestion.adapters import FileFixtureIntakeAdapter
from ulpf_ingestion.evidence import InMemoryRawEventSink
from ulpf_ingestion.listeners import TcpRawIntakeServer, UdpRawIntakeListener
from ulpf_ingestion.metrics import IntakeMetrics
from ulpf_ingestion.service import RawCaptureService


class IntakeTransportTests(unittest.IsolatedAsyncioTestCase):
    """Exercise transport framing without interpreting any payload semantics."""

    def setUp(self) -> None:
        self.sink = InMemoryRawEventSink()
        self.service = RawCaptureService(self.sink, IntakeMetrics(), maximum_event_bytes=1_024)

    async def _wait_for_event(self) -> str:
        for _ in range(100):
            if self.sink.event_ids:
                return self.sink.event_ids[0]
            await asyncio.sleep(0.01)
        self.fail("Timed out waiting for local raw capture.")

    async def test_tcp_retains_lf_delimited_frame_bytes(self) -> None:
        server = TcpRawIntakeServer(
            self.service,
            host="127.0.0.1",
            port=0,
            maximum_frame_bytes=1_024,
            maximum_connections=2,
            read_timeout_seconds=1,
        )
        await server.start()
        try:
            port = server.bound_port
            if port is None:
                self.fail("TCP listener did not bind a port.")
            _, writer = await asyncio.open_connection("127.0.0.1", port)
            payload = b"opaque tcp message\r\n"
            writer.write(payload)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

            event_id = await self._wait_for_event()
            self.assertEqual(self.sink.retrieve(event_id).payload, payload)
        finally:
            await server.stop()

    async def test_udp_captures_one_complete_datagram(self) -> None:
        listener = UdpRawIntakeListener(
            self.service,
            host="127.0.0.1",
            port=0,
            maximum_datagram_bytes=1_024,
            maximum_concurrent_captures=2,
        )
        await listener.start()
        try:
            port = listener.bound_port
            if port is None:
                self.fail("UDP listener did not bind a port.")
            loop = asyncio.get_running_loop()
            transport, _ = await loop.create_datagram_endpoint(
                asyncio.DatagramProtocol,
                remote_addr=("127.0.0.1", port),
            )
            payload = b"opaque udp datagram\x00"
            transport.sendto(payload)
            event_id = await self._wait_for_event()
            self.assertEqual(self.sink.retrieve(event_id).payload, payload)
            transport.close()
        finally:
            await listener.stop()


class FileFixtureIntakeTests(unittest.TestCase):
    """Prove file framing is explicit and preserves delimiters in each frame."""

    def test_line_framing_preserves_original_line_endings(self) -> None:
        sink = InMemoryRawEventSink()
        service = RawCaptureService(sink, IntakeMetrics(), maximum_event_bytes=1_024)
        adapter = FileFixtureIntakeAdapter(service, maximum_event_bytes=1_024)
        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture = Path(temporary_directory) / "opaque.log"
            fixture.write_bytes(b"first\r\nsecond\n")
            acknowledgements = adapter.capture_file(
                fixture,
                request_id="00000000-0000-0000-0000-000000000001",
                correlation_id="00000000-0000-0000-0000-000000000002",
                trace_id="0" * 32,
                framing="line",
            )

        self.assertEqual(len(acknowledgements), 2)
        self.assertEqual(sink.retrieve(acknowledgements[0].event_id).payload, b"first\r\n")
        self.assertEqual(sink.retrieve(acknowledgements[1].event_id).payload, b"second\n")
