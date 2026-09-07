"""Sliding window rate limiting middleware for ULPF Phase 7.

Enforces:
- Rule 72: API rate limiting across ingest, search, replay, and admin endpoints
- Rule 73: Bounded memory and DoS defense
"""

import threading
import time
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


class RateLimiterMiddleware(BaseHTTPMiddleware):
    """In-memory sliding window rate limiter bounded by client IP and path prefix."""

    def __init__(
        self,
        app: Any,
        default_limit_per_minute: int = 1000,
        route_limits: dict[str, int] | None = None,
        max_tracked_clients: int = 10000,
    ) -> None:
        super().__init__(app)
        self.default_limit = default_limit_per_minute
        self.route_limits = route_limits or {
            "/api/v1/search": 120,
            "/api/v1/replay": 30,
            "/api/v1/dlq": 60,
        }
        self.max_clients = max_tracked_clients
        self._lock = threading.Lock()
        # client_ip:list of timestamps
        self._clients: dict[str, list[float]] = {}

    def _get_limit_for_path(self, path: str) -> int:
        for prefix, limit in self.route_limits.items():
            if path.startswith(prefix):
                return limit
        return self.default_limit

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        # Public health endpoints bypass rate limiting
        if request.url.path.startswith("/health"):
            return await call_next(request)

        client_ip = request.client.host if request.client else "127.0.0.1"
        key = f"{client_ip}:{request.url.path}"
        limit = self._get_limit_for_path(request.url.path)
        now = time.time()
        window_start = now - 60.0

        with self._lock:
            # Memory safety: LRU eviction if client cache overflows
            if len(self._clients) > self.max_clients and key not in self._clients:
                self._clients.pop(next(iter(self._clients)))

            timestamps = self._clients.setdefault(key, [])
            # Prune timestamps older than 60s
            self._clients[key] = [t for t in timestamps if t > window_start]

            if len(self._clients[key]) >= limit:
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={
                        "error": "Too Many Requests",
                        "detail": f"Rate limit exceeded: maximum {limit} requests per minute",
                        "retry_after": 60,
                    },
                    headers={"Retry-After": "60"},
                )

            self._clients[key].append(now)

        return await call_next(request)
