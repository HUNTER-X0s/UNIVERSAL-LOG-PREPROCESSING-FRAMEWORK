"""Bounded raw TCP and UDP listeners with transport-only framing behavior."""

import asyncio
from collections.abc import Awaitable, Callable

from ulpf_platform.correlation import build_context
from ulpf_platform.logging import get_logger

from ulpf_ingestion.models import RawCaptureInput, TransportMetadata, TransportProtocol
from ulpf_ingestion.service import PayloadTooLargeError, RawCaptureService


def _socket_address(address: object) -> str | None:
    """Render an address for receipt context without payload-derived identity."""
    if not isinstance(address, tuple) or len(address) < 2:
        return None
    host, port = address[0], address[1]
    return f"{host}:{port}"


class TcpRawIntakeServer:
    """LF-delimited TCP listener that retains each delimiter as received evidence."""

    def __init__(
        self,
        capture_service: RawCaptureService,
        host: str,
        port: int,
        maximum_frame_bytes: int,
        maximum_connections: int,
        read_timeout_seconds: float,
    ) -> None:
        self._capture_service = capture_service
        self._host = host
        self._port = port
        self._maximum_frame_bytes = maximum_frame_bytes
        self._read_timeout_seconds = read_timeout_seconds
        self._connections = asyncio.Semaphore(maximum_connections)
        self._server: asyncio.AbstractServer | None = None
        self._logger = get_logger("ingestion.tcp")

    @property
    def bound_port(self) -> int | None:
        """Return the actual port, including an ephemeral test port after startup."""
        if self._server is None or not self._server.sockets:  # type: ignore[attr-defined]
            return None
        return int(self._server.sockets[0].getsockname()[1])  # type: ignore[attr-defined]

    async def start(self) -> None:
        """Start the listener with an input buffer that cannot grow beyond one frame."""
        self._server = await asyncio.start_server(
            self._handle_client,
            host=self._host,
            port=self._port,
            limit=self._maximum_frame_bytes + 1,
            backlog=128,
        )

    async def stop(self) -> None:
        """Stop accepting connections and wait for the server socket to close."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        if self._connections.locked():
            writer.close()
            await writer.wait_closed()
            return
        async with self._connections:
            connection_context = build_context(None, None, None)
            peer_address = _socket_address(writer.get_extra_info("peername"))
            listener_address = _socket_address(writer.get_extra_info("sockname"))
            try:
                while True:
                    try:
                        payload = await asyncio.wait_for(
                            reader.readuntil(b"\n"), timeout=self._read_timeout_seconds
                        )
                    except asyncio.IncompleteReadError as exc:
                        if exc.partial:
                            self._log_refusal("intake_invalid_request")
                        return
                    except asyncio.LimitOverrunError:
                        self._log_refusal("intake_frame_too_large")
                        return
                    except TimeoutError:
                        self._log_refusal("intake_timeout")
                        return
                    if len(payload) > self._maximum_frame_bytes:
                        self._log_refusal("intake_frame_too_large")
                        return
                    context = build_context(None, connection_context.correlation_id, None)
                    await asyncio.to_thread(
                        self._capture,
                        payload,
                        peer_address,
                        listener_address,
                        context.request_id,
                        context.correlation_id,
                        context.trace_id,
                    )
            finally:
                writer.close()
                await writer.wait_closed()

    def _capture(
        self,
        payload: bytes,
        peer_address: str | None,
        listener_address: str | None,
        request_id: str,
        correlation_id: str,
        trace_id: str,
    ) -> None:
        try:
            self._capture_service.capture(
                RawCaptureInput(
                    payload=payload,
                    transport=TransportMetadata(
                        protocol=TransportProtocol.TCP,
                        intake_id="syslog-tcp",
                        peer_address=peer_address,
                        listener_address=listener_address,
                        details={"framing": "lf-retained"},
                    ),
                    request_id=request_id,
                    correlation_id=correlation_id,
                    trace_id=trace_id,
                )
            )
        except PayloadTooLargeError:
            self._log_refusal("intake_frame_too_large")
        except Exception:
            self._logger.exception(
                "tcp_capture_failed",
                extra={"component": "ingestion.tcp", "error_code": "intake_capture_failure"},
            )

    def _log_refusal(self, error_code: str) -> None:
        self._logger.warning(
            "tcp_frame_refused", extra={"component": "ingestion.tcp", "error_code": error_code}
        )


class _UdpProtocol(asyncio.DatagramProtocol):
    """Delegate datagrams to a bounded listener without decoding payload bytes."""

    def __init__(self, receiver: Callable[[bytes, object], Awaitable[None]]) -> None:
        self._receiver = receiver

    def datagram_received(self, data: bytes, address: object) -> None:
        """Schedule bounded capture; UDP provides no acknowledgement channel."""
        asyncio.create_task(self._receiver(data, address))  # type: ignore[arg-type]


class UdpRawIntakeListener:
    """Datagram listener that captures complete datagrams or records a refusal."""

    def __init__(
        self,
        capture_service: RawCaptureService,
        host: str,
        port: int,
        maximum_datagram_bytes: int,
        maximum_concurrent_captures: int,
    ) -> None:
        self._capture_service = capture_service
        self._host = host
        self._port = port
        self._maximum_datagram_bytes = maximum_datagram_bytes
        self._captures = asyncio.Semaphore(maximum_concurrent_captures)
        self._transport: asyncio.DatagramTransport | None = None
        self._tasks: set[asyncio.Task[None]] = set()
        self._logger = get_logger("ingestion.udp")

    @property
    def bound_port(self) -> int | None:
        """Return the actual port, including an ephemeral test port after startup."""
        if self._transport is None:
            return None
        socket_name = self._transport.get_extra_info("sockname")
        return int(socket_name[1]) if isinstance(socket_name, tuple) else None

    async def start(self) -> None:
        """Bind the configured local UDP socket."""
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _UdpProtocol(self._schedule_capture), local_addr=(self._host, self._port)
        )
        self._transport = transport

    async def stop(self) -> None:
        """Close the socket and allow in-flight bounded captures to finish."""
        if self._transport is not None:
            self._transport.close()
            self._transport = None
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

    async def _schedule_capture(self, payload: bytes, address: object) -> None:
        if len(payload) > self._maximum_datagram_bytes:
            self._log_refusal("intake_frame_too_large")
            return
        if self._captures.locked():
            self._log_refusal("intake_rate_limited")
            return
        task = asyncio.current_task()
        if task is not None:
            self._tasks.add(task)
        try:
            async with self._captures:
                context = build_context(None, None, None)
                await asyncio.to_thread(
                    self._capture,
                    payload,
                    _socket_address(address),
                    context.request_id,
                    context.correlation_id,
                    context.trace_id,
                )
        finally:
            if task is not None:
                self._tasks.discard(task)

    def _capture(
        self,
        payload: bytes,
        peer_address: str | None,
        request_id: str,
        correlation_id: str,
        trace_id: str,
    ) -> None:
        try:
            self._capture_service.capture(
                RawCaptureInput(
                    payload=payload,
                    transport=TransportMetadata(
                        protocol=TransportProtocol.UDP,
                        intake_id="syslog-udp",
                        peer_address=peer_address,
                    ),
                    request_id=request_id,
                    correlation_id=correlation_id,
                    trace_id=trace_id,
                )
            )
        except PayloadTooLargeError:
            self._log_refusal("intake_frame_too_large")
        except Exception:
            self._logger.exception(
                "udp_capture_failed",
                extra={"component": "ingestion.udp", "error_code": "intake_capture_failure"},
            )

    def _log_refusal(self, error_code: str) -> None:
        self._logger.warning(
            "udp_datagram_refused", extra={"component": "ingestion.udp", "error_code": error_code}
        )
