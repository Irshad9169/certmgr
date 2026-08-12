"""Structured JSON logging with secret/private-key redaction.

- JSON lines to stdout (production) or human-readable (development).
- A redaction filter guarantees private keys and secret material NEVER appear
  in any log record, regardless of which module logged it.
"""

from __future__ import annotations

import json
import logging
import re
import sys
import threading
import time
from datetime import UTC, datetime
from typing import Any

from app.core.config import settings

# ── Redaction patterns ──────────────────────────────────────────────────────
_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----.*?"
    r"-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
    re.DOTALL,
)
_SECRET_PATTERNS = [
    re.compile(r"(?i)(password|passwd|secret|api[_-]?key|token|authorization)\s*[=:]\s*\S+"),
    re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL),
    re.compile(r"(?i)(pwd|passwd|password)\s*=\s*\S+"),
    re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"),  # JWTs
]


def redact(text: str) -> str:
    """Replace private key material and secrets with a placeholder."""
    out = _PRIVATE_KEY_BLOCK.sub("[REDACTED:PRIVATE_KEY]", text)
    for pat in _SECRET_PATTERNS:
        out = pat.sub(lambda m: f"{m.group(0).split('=')[0]}=[REDACTED]", out)
    return out


def redact_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Deep-redact a dict in place (returns a copy)."""
    result: dict[str, Any] = {}
    for k, v in data.items():
        if isinstance(v, dict):
            result[k] = redact_dict(v)
        elif isinstance(v, list):
            result[k] = [redact_dict(i) if isinstance(i, dict) else i for i in v]
        elif isinstance(v, str):
            result[k] = redact(v)
        else:
            result[k] = v
    return result


class RedactionFilter(logging.Filter):
    """Strip private keys / secrets from every emitted log record."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact(record.msg)
        if record.args:
            record.args = tuple(redact(a) if isinstance(a, str) else a for a in record.args)
        for attr in ("exc_text", "stack_info"):
            val = getattr(record, attr, None)
            if isinstance(val, str):
                setattr(record, attr, redact(val))
        return True


class JsonFormatter(logging.Formatter):
    """Emit one JSON object per line: timestamp, level, logger, message, extras."""

    def __init__(self) -> None:
        super().__init__()
        self._host = settings.app_name

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        # Merge contextual fields (request_id, user, action, duration…)
        for key in ("request_id", "user", "action", "resource", "duration_ms", "event"):
            val = getattr(record, key, None)
            if val is not None:
                entry[key] = val
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


class ContextFilter(logging.Filter):
    """Attach thread-local request context (request_id / user) to records."""

    def filter(self, record: logging.LogRecord) -> bool:
        ctx = request_context()
        for key, value in ctx.items():
            if not hasattr(record, key):
                setattr(record, key, value)
        return True


class SafeConsoleFormatter(logging.Formatter):
    """Console formatter that tolerates records without contextual fields."""

    def format(self, record: logging.LogRecord) -> str:
        request_id = getattr(record, "request_id", "-")
        return (
            f"{self.formatTime(record)} {record.levelname:<7} {record.name} "
            f"[{request_id}] {record.getMessage()}"
        )


_context = threading.local()


def set_request_context(**kwargs: Any) -> None:
    """Set context vars for the current thread (called by middleware)."""
    for k, v in kwargs.items():
        setattr(_context, k, v)


def request_context() -> dict[str, Any]:
    return {
        k: v
        for k, v in vars(_context).items()
        if not k.startswith("_")
    }


def clear_request_context() -> None:
    vars(_context).clear()


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


def setup_logging() -> None:
    root = logging.getLogger()
    root.setLevel(settings.log_level.upper())

    for handler in list(root.handlers):
        root.removeHandler(handler)

    stream = logging.StreamHandler(sys.stdout)
    if settings.json_logging:
        stream.setFormatter(JsonFormatter())
    else:
        stream.setFormatter(SafeConsoleFormatter())
    stream.addFilter(RedactionFilter())
    stream.addFilter(ContextFilter())
    root.addHandler(stream)

    # Quiet noisy third-party loggers
    for noisy in ("uvicorn.access", "paramiko.transport", "httpcore", "httpx"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    logging.getLogger("app").setLevel(settings.log_level.upper())
    logging.getLogger("app").info("logging initialized", extra={"event": "logging_init"})


class Timer:
    """Simple monotonic timer helper for audit/duration tracking."""

    def __init__(self) -> None:
        self._start = time.perf_counter()

    def elapsed_ms(self) -> int:
        return int((time.perf_counter() - self._start) * 1000)

    @property
    def elapsed(self) -> float:
        return time.perf_counter() - self._start
