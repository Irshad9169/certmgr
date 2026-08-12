"""Domain exception hierarchy + FastAPI exception handlers.

Every error surfaced to clients is normalized to a stable JSON envelope:
    {"error": {"code": "...", "message": "...", "details": {...}}}
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.logging import get_logger

logger = get_logger(__name__)


class AppError(Exception):
    """Base application error."""

    status_code = 500
    code = "INTERNAL_ERROR"

    def __init__(self, message: str, *, code: str | None = None, details: Any = None) -> None:
        super().__init__(message)
        self.message = message
        if code:
            self.code = code
        self.details = details


class NotFoundError(AppError):
    status_code = 404
    code = "NOT_FOUND"


class ConflictError(AppError):
    status_code = 409
    code = "CONFLICT"


class ValidationAppError(AppError):
    status_code = 422
    code = "VALIDATION_ERROR"


class PermissionDeniedError(AppError):
    status_code = 403
    code = "FORBIDDEN"


class AuthError(AppError):
    status_code = 401
    code = "UNAUTHORIZED"


class SecurityError(AppError):
    status_code = 403
    code = "SECURITY_ERROR"


class ProviderError(AppError):
    status_code = 502
    code = "PROVIDER_ERROR"


class RateLimitError(AppError):
    status_code = 429
    code = "RATE_LIMITED"


class DeploymentError(AppError):
    status_code = 502
    code = "DEPLOYMENT_ERROR"


class MaintenanceModeError(AppError):
    status_code = 503
    code = "MAINTENANCE_MODE"


class ConflictResourceError(ConflictError):
    code = "RESOURCE_EXISTS"


class CommandError(AppError):
    """Raised when a locally executed (safe, shell=False) command fails."""

    status_code = 500
    code = "COMMAND_FAILED"

    def __init__(self, message: str, exit_code: int | None = None, stderr: str = "") -> None:
        super().__init__(message)
        self.exit_code = exit_code
        self.stderr = stderr


def _error_body(exc: AppError) -> dict[str, Any]:
    body: dict[str, Any] = {"code": exc.code, "message": exc.message}
    if exc.details is not None:
        body["details"] = exc.details
    return body


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def app_error_handler(request: Request, exc: AppError) -> JSONResponse:
        if exc.status_code >= 500:
            logger.exception("App error", extra={"action": request.url.path})
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": _error_body(exc)},
        )

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        errors = []
        for err in exc.errors():
            errors.append(
                {
                    "loc": ".".join(str(x) for x in err.get("loc", [])),
                    "msg": err.get("msg", "invalid"),
                    "type": err.get("type", "value_error"),
                }
            )
        return JSONResponse(
            status_code=422,
            content={"error": {"code": "VALIDATION_ERROR", "message": "Invalid request", "details": errors}},
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"code": "HTTP_ERROR", "message": str(exc.detail)}},
        )

    @app.exception_handler(Exception)
    async def unhandled_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled exception", extra={"action": request.url.path})
        return JSONResponse(
            status_code=500,
            content={"error": {"code": "INTERNAL_ERROR", "message": "Internal server error"}},
        )
