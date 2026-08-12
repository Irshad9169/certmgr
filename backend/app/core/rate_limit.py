"""Rate limiting via slowapi with pluggable storage (Redis in production)."""

from __future__ import annotations

from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.core.config import settings
from app.core.exceptions import RateLimitError


def _get_storage_uri() -> str | None:
    if not settings.rate_limit_enabled:
        return None
    if settings.redis_url and not settings.redis_url.startswith("redis://"):
        return None
    # slowapi uses limits-storage; use redis if available
    return settings.redis_url if settings.redis_url.startswith("redis") else None


limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=_get_storage_uri(),
    enabled=settings.rate_limit_enabled,
    default_limits=[settings.rate_limit_api],
    headers_enabled=True,
)


def rate_limit_handler(request, exc: RateLimitExceeded):
    """Convert slowapi's 429 into our standard error envelope."""
    return RateLimitError(
        "Rate limit exceeded — slow down",
        code="RATE_LIMITED",
        details={"limit": str(exc.detail)},
    )
