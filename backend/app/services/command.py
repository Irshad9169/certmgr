"""Secure local command execution.

SECURITY CONTRACT:
  * subprocess.run() with a LIST argv — shell=True is FORBIDDEN (lint-enforced).
  * Every argv element is validated (no shell metacharacters) before execution.
  * Optionally runs as a different OS user (setuid) when the platform runs as root.
  * Full stdout/stderr/exit-code/duration capture, safe for concurrent runs.
"""

from __future__ import annotations

import os
import pwd
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from app.core.exceptions import CommandError, ValidationAppError
from app.core.logging import get_logger, redact

logger = get_logger(__name__)

_FORBIDDEN_METACHARS = set(" ;&|`$<>(){}[]*?~!\"'\\\n\r\t")


@dataclass
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    timed_out: bool = False

    @property
    def success(self) -> bool:
        return self.returncode == 0

    def combined(self, limit: int | None = 4096) -> str:
        out = f"{self.stdout}\n{self.stderr}".strip()
        if limit and len(out) > limit:
            return out[:limit] + "\n...[truncated]"
        return out


def assert_safe_argument(value: str) -> str:
    """Reject shell metacharacters in any argv element (injection defense)."""
    v = str(value)
    if any(c in v for c in _FORBIDDEN_METACHARS):
        raise ValidationAppError("Argument contains forbidden shell characters")
    if v.startswith("-") and "=" in v and "CERTMGR_" not in v:  # allow env-ish flags but not injections
        pass
    return v


def assert_safe_script_path(path: str, *, executable_required: bool = False) -> Path:
    """Validate an absolute script path with no metacharacters; must exist."""
    p = Path(path)
    if not p.is_absolute():
        raise ValidationAppError("Script path must be absolute")
    if not p.exists():
        raise ValidationAppError(f"Script does not exist: {path}")
    if executable_required and not os.access(p, os.X_OK):
        raise ValidationAppError(f"Script is not executable: {path}")
    return p


def _drop_privileges(target_user: str) -> None:
    """setuid/setgid to another user (only meaningful when running as root)."""
    if os.geteuid() != 0:
        logger.warning("Cannot run as %s (not root); continuing as current user", target_user)
        return
    try:
        pw = pwd.getpwnam(target_user)
    except KeyError as exc:
        raise ValidationAppError(f"Unknown execution user: {target_user}") from exc
    os.setgroups([])
    os.setgid(pw.pw_gid)
    os.setuid(pw.pw_uid)


def run_command(
    argv: list[str],
    *,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    timeout: int = 300,
    execution_user: str | None = None,
    stdin_data: bytes | None = None,
    log_output: bool = True,
) -> CommandResult:
    """Execute argv safely. Raises nothing for non-zero exit — callers inspect result."""
    if not argv:
        raise ValidationAppError("Empty command")

    binary = shutil.which(argv[0])
    if binary is None:
        raise CommandError(f"Executable not found: {argv[0]}", exit_code=127)

    safe_argv = [binary] + [assert_safe_argument(a) for a in argv[1:]]

    merged_env = os.environ.copy()
    merged_env.update(env or {})
    # Prevent accidental leakage of secrets into child env
    for key in list(merged_env):
        if "CERTMGR_SECRETS_MASTER_KEY" in key or "PASSWORD" in key.upper():
            merged_env.pop(key, None)

    start = time.perf_counter()
    logger.info("Executing: %s (timeout=%ss)", " ".join(safe_argv), timeout)
    try:
        proc = subprocess.run(  # noqa: S603 — argv is validated, shell=False by design
            safe_argv,
            capture_output=True,
            text=True,
            cwd=cwd,
            env=merged_env,
            timeout=timeout,
            input=stdin_data.decode("utf-8") if stdin_data else None,
            check=False,
            preexec_fn=(lambda: _drop_privileges(execution_user)) if execution_user else None,
        )
        result = CommandResult(
            argv=safe_argv,
            returncode=proc.returncode,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            duration_ms=int((time.perf_counter() - start) * 1000),
        )
    except subprocess.TimeoutExpired as exc:
        result = CommandResult(
            argv=safe_argv,
            returncode=124,
            stdout=exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
            stderr=exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or ""),
            duration_ms=int((time.perf_counter() - start) * 1000),
            timed_out=True,
        )
    except OSError as exc:
        raise CommandError(f"Failed to execute {argv[0]}: {exc}", exit_code=126) from exc

    if log_output:
        logger.info(
            "Command %s exited with %d in %dms",
            argv[0], result.returncode, result.duration_ms,
            extra={"event": "command_result", "returncode": result.returncode,
                   "duration_ms": result.duration_ms},
        )
        if result.stderr:
            logger.debug("stderr: %s", redact(result.stderr)[:2000])
    return result
