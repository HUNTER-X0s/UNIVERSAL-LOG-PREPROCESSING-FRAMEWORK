"""Composition root for Phase 2 raw capture without a parser or message broker."""

from ulpf_platform.config import AppSettings

from ulpf_ingestion.adapters import (
    FileFixtureIntakeAdapter,
    FixedWindowRateLimiter,
    HttpRawIntakeAdapter,
    IntakeTokenAuthorizer,
)
from ulpf_ingestion.evidence import LocalFileRawEventSink
from ulpf_ingestion.listeners import TcpRawIntakeServer, UdpRawIntakeListener
from ulpf_ingestion.metrics import IntakeMetrics
from ulpf_ingestion.service import RawCaptureService


class IntakeRuntime:
    """Own the bounded local evidence sink, adapters, and optional listeners."""

    def __init__(self, settings: AppSettings) -> None:
        self.metrics = IntakeMetrics()
        self.evidence_sink = LocalFileRawEventSink(
            root=settings.intake_evidence_directory,
            maximum_events=settings.intake_evidence_max_events,
            maximum_bytes=settings.intake_evidence_max_bytes,
        )
        self.capture_service = RawCaptureService(
            sink=self.evidence_sink,
            metrics=self.metrics,
            maximum_event_bytes=settings.intake_max_event_bytes,
        )
        self.http = HttpRawIntakeAdapter(self.capture_service)
        self.fixture = FileFixtureIntakeAdapter(
            self.capture_service, maximum_event_bytes=settings.intake_max_event_bytes
        )
        self.authorizer = IntakeTokenAuthorizer(
            settings.intake_auth_token.get_secret_value()
            if settings.intake_auth_token is not None
            else None
        )
        self.rate_limiter = FixedWindowRateLimiter(settings.intake_http_requests_per_minute)
        self.tcp = (
            TcpRawIntakeServer(
                capture_service=self.capture_service,
                host=settings.intake_tcp_host,
                port=settings.intake_tcp_port,
                maximum_frame_bytes=settings.intake_max_event_bytes,
                maximum_connections=settings.intake_max_connections,
                read_timeout_seconds=settings.intake_read_timeout_seconds,
            )
            if settings.intake_tcp_enabled
            else None
        )
        self.udp = (
            UdpRawIntakeListener(
                capture_service=self.capture_service,
                host=settings.intake_udp_host,
                port=settings.intake_udp_port,
                maximum_datagram_bytes=settings.intake_max_event_bytes,
                maximum_concurrent_captures=settings.intake_max_connections,
            )
            if settings.intake_udp_enabled
            else None
        )

    async def start(self) -> None:
        """Start only explicitly enabled local network listeners."""
        if self.tcp is not None:
            await self.tcp.start()
        if self.udp is not None:
            await self.udp.start()

    async def stop(self) -> None:
        """Stop listeners; local evidence remains available for verified retrieval."""
        if self.udp is not None:
            await self.udp.stop()
        if self.tcp is not None:
            await self.tcp.stop()
