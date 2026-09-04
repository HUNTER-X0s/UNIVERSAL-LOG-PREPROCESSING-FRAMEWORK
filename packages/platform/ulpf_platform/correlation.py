"""Request/correlation/trace identifiers that can cross future service boundaries."""

from contextvars import ContextVar, Token
from dataclasses import dataclass
from uuid import UUID, uuid4

_context: ContextVar["RequestContext"] = ContextVar("ulpf_request_context")


@dataclass(frozen=True, slots=True)
class RequestContext:
    """Safe identifiers for structured logs and response envelopes."""

    request_id: str
    correlation_id: str
    trace_id: str


def _safe_uuid(value: str | None) -> str:
    if value:
        try:
            return str(UUID(value))
        except ValueError:
            pass
    return str(uuid4())


def build_context(
    request_id: str | None, correlation_id: str | None, trace_id: str | None
) -> RequestContext:
    """Accept only UUID-like user identifiers; generate replacements otherwise."""
    normalized_trace = (
        trace_id.lower()
        if trace_id
        and len(trace_id) == 32
        and all(c in "0123456789abcdef" for c in trace_id.lower())
        else uuid4().hex
    )
    return RequestContext(
        request_id=_safe_uuid(request_id),
        correlation_id=_safe_uuid(correlation_id),
        trace_id=normalized_trace,
    )


def set_request_context(context: RequestContext) -> Token[RequestContext]:
    """Set request context and return the token for reliable reset."""
    return _context.set(context)


def reset_request_context(token: Token[RequestContext]) -> None:
    """Remove request-scoped identifiers at the end of a request."""
    _context.reset(token)


def request_context() -> RequestContext:
    """Get current context or a safe standalone context for non-HTTP code."""
    try:
        return _context.get()
    except LookupError:
        return build_context(None, None, None)
