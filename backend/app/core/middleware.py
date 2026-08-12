"""HTTP middleware: request context, security headers, CSRF, metrics, logging."""

from __future__ import annotations

import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.core.config import settings
from app.core.logging import (
    clear_request_context,
    get_logger,
    set_request_context,
)
from app.core.security import verify_csrf_token

logger = get_logger("app.http")

# State-changing methods that require CSRF validation when using cookie auth.
_CSRF_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Attach request_id + client metadata to logs for the current request."""

    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex[:16]
        set_request_context(
            request_id=request_id,
            client_ip=request.client.host if request.client else "unknown",
        )
        start = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            response = Response(status_code=500)
        duration_ms = int((time.perf_counter() - start) * 1000)
        logger.info(
            f"{request.method} {request.url.path} -> {response.status_code} ({duration_ms}ms)",
            extra={"event": "http_request", "duration_ms": duration_ms, "status": response.status_code},
        )
        response.headers["X-Request-ID"] = request_id
        clear_request_context()
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Hardening headers: CSP, X-Frame-Options, HSTS, nosniff, referrer policy."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["X-XSS-Protection"] = "0"  # modern browsers: use CSP instead
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; form-action 'self'",
        )
        if settings.is_production and request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if settings.cookie_secure:
            response.headers["Cache-Control"] = "no-store" if request.url.path.startswith("/api") else response.headers.get("Cache-Control", "")
        return response


class CSRFMiddleware(BaseHTTPMiddleware):
    """Double-submit cookie CSRF for state-changing requests.

    Design notes:
    - This app authenticates with JWT in the `Authorization`/`X-CertMgr-Token`
      header; such requests are NOT CSRF-able and are exempted below.
    - The `/api/v1/auth/*` endpoints (login, refresh) are public and never
      carry a Bearer token, so the middleware historically applied only to
      them. Login CSRF is a low-severity nuisance attack, already mitigated by
      SameSite=Lax cookies (the CSRF cookie is not sent on cross-site POSTs).
      To avoid a class of brittle failure (stale cookie vs. token mismatches
      that lock users out of login), auth endpoints are exempted.
    - The middleware remains active for any non-auth, non-Bearer
      state-changing request under /api (defense in depth).
    """

    COOKIE_NAME = "certmgr_csrf"
    _EXEMPT_PREFIXES = ("/api/v1/auth/",)

    async def dispatch(self, request: Request, call_next):
        # Header-token-authenticated requests are not CSRF-able; exempt them.
        auth = request.headers.get("Authorization", "")
        token_auth = auth.startswith("Bearer ") or bool(request.headers.get("X-CertMgr-Token"))
        is_auth_endpoint = any(
            request.url.path.startswith(prefix) for prefix in self._EXEMPT_PREFIXES
        )
        if (
            settings.csrf_enabled
            and request.method in _CSRF_METHODS
            and request.url.path.startswith("/api")
            and not token_auth
            and not is_auth_endpoint
        ):
            header_token = request.headers.get("X-CSRF-Token", "")
            cookie_token = request.cookies.get(self.COOKIE_NAME, "")
            if not verify_csrf_token(header_token, cookie_token):
                return Response(
                    status_code=403,
                    content=b'{"error":{"code":"CSRF_FAILED","message":"CSRF token missing or invalid"}}',
                    media_type="application/json",
                )
        return await call_next(request)


class MetricsMiddleware(BaseHTTPMiddleware):
    """Prometheus counters for HTTP requests (used by /metrics endpoint)."""

    async def dispatch(self, request: Request, call_next):
        start = time.perf_counter()
        response = await call_next(request)
        duration = time.perf_counter() - start
        try:
            from app.core.metrics import HTTP_REQUEST_DURATION, HTTP_REQUESTS

            HTTP_REQUESTS.labels(method=request.method, path=request.url.path, status=response.status_code).inc()
            HTTP_REQUEST_DURATION.labels(method=request.method, path=request.url.path).observe(duration)
        except Exception:  # pragma: no cover  # noqa: S110 — metrics must never break requests
            pass
        return response
