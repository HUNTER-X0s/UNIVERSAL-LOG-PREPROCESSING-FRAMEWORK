"""HTTP- and fixture-boundary helpers that pass opaque bytes to raw capture."""

import hmac
from collections.abc import AsyncIterable
from pathlib import Path
from threading import Lock
from time import monotonic

from ulpf_ingestion.models import (
    CaptureAcknowledgement,
    RawCaptureInput,
    TransportMetadata,
    TransportProtocol,
)
from ulpf_ingestion.service import PayloadTooLargeError, RawCaptureService


class IntakeAuthorizationError(RuntimeError):
    """A configured source credential was absent or did not match."""


class RateLimitedError(RuntimeError):
    """The fixed local request boundary refuses another request in its window."""


class FixedWindowRateLimiter:
    """Global bounded request limiter; it stores no source identifiers."""

    def __init__(self, maximum_requests_per_minute: int) -> None:
        self._maximum_requests = maximum_requests_per_minute
        self._window_started_at = monotonic()
        self._count = 0
        self._lock = Lock()

    def check(self) -> None:
        """Consume one available request slot or safely reject the request."""
        with self._lock:
            now = monotonic()
            if now - self._window_started_at >= 60:
                self._window_started_at = now
                self._count = 0
            if self._count >= self._maximum_requests:
                raise RateLimitedError("The local intake request limit was reached.")
            self._count += 1


class IntakeTokenAuthorizer:
    """Optional static-token boundary for a single local intake deployment."""

    def __init__(self, configured_token: str | None) -> None:
        self._configured_token = configured_token

    def authorize(self, authorization_header: str | None) -> None:
        """Check a bearer token when one was explicitly configured."""
        if self._configured_token is None:
            return
        prefix = "Bearer "
        if authorization_header is None or not authorization_header.startswith(prefix):
            raise IntakeAuthorizationError("A valid intake credential is required.")
        supplied_token = authorization_header.removeprefix(prefix)
        if not hmac.compare_digest(supplied_token, self._configured_token):
            raise IntakeAuthorizationError("A valid intake credential is required.")


async def read_bounded_body(chunks: AsyncIterable[bytes], maximum_bytes: int) -> bytes:
    """Read a request stream without representing a partial body as an event."""
    captured = bytearray()
    async for chunk in chunks:
        if len(captured) + len(chunk) > maximum_bytes:
            raise PayloadTooLargeError("Payload exceeds the configured event limit.")
        captured.extend(chunk)
    return bytes(captured)


class HttpRawIntakeAdapter:
    """Converge opaque HTTP request bytes into the raw-capture service."""

    def __init__(self, capture_service: RawCaptureService) -> None:
        self._capture_service = capture_service

    def capture(
        self,
        payload: bytes,
        peer_address: str | None,
        content_type: str | None,
        request_id: str,
        correlation_id: str,
        trace_id: str,
    ) -> CaptureAcknowledgement:
        """Use HTTP request framing only; bytes and content are never decoded."""
        return self._capture_service.capture(
            RawCaptureInput(
                payload=payload,
                transport=TransportMetadata(
                    protocol=TransportProtocol.HTTP,
                    intake_id="http-api",
                    peer_address=peer_address,
                    content_type=content_type,
                ),
                request_id=request_id,
                correlation_id=correlation_id,
                trace_id=trace_id,
            )
        )


class FileFixtureIntakeAdapter:
    """Deterministic development/test adapter; it is not a file-tail service."""

    def __init__(self, capture_service: RawCaptureService, maximum_event_bytes: int) -> None:
        self._capture_service = capture_service
        self._maximum_event_bytes = maximum_event_bytes

    def capture_file(
        self,
        fixture_path: Path,
        request_id: str,
        correlation_id: str,
        trace_id: str,
        framing: str = "whole-file",
    ) -> tuple[CaptureAcknowledgement, ...]:
        """Capture exact whole-file or line-framed bytes with explicit EOF semantics."""
        if framing == "whole-file":
            if fixture_path.stat().st_size > self._maximum_event_bytes:
                raise PayloadTooLargeError("Fixture exceeds the configured event limit.")
            return (
                self._capture(
                    fixture_path.read_bytes(), fixture_path, request_id, correlation_id, trace_id
                ),
            )
        if framing != "line":
            raise ValueError("fixture framing must be whole-file or line")

        acknowledgements: list[CaptureAcknowledgement] = []
        with fixture_path.open("rb") as fixture:
            while payload := fixture.readline(self._maximum_event_bytes + 1):
                if len(payload) > self._maximum_event_bytes:
                    raise PayloadTooLargeError("Fixture frame exceeds the configured event limit.")
                acknowledgements.append(
                    self._capture(payload, fixture_path, request_id, correlation_id, trace_id)
                )
        return tuple(acknowledgements)

    def _capture(
        self,
        payload: bytes,
        fixture_path: Path,
        request_id: str,
        correlation_id: str,
        trace_id: str,
    ) -> CaptureAcknowledgement:
        return self._capture_service.capture(
            RawCaptureInput(
                payload=payload,
                transport=TransportMetadata(
                    protocol=TransportProtocol.FILE,
                    intake_id="fixture-file",
                    details={"fixture_name": fixture_path.name},
                ),
                request_id=request_id,
                correlation_id=correlation_id,
                trace_id=trace_id,
            )
        )
