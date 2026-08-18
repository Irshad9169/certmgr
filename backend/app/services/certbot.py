"""Certbot command construction and execution.

Every certbot invocation is built as a strict argument LIST (never a shell
string), validated element-by-element, and executed via subprocess.run with
shell=False. Hooks (auth/cleanup) are passed as validated absolute paths and
their environment variables are injected as a controlled env dict.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from app.core.config import settings
from app.core.domain_utils import validate_domain_list
from app.core.logging import get_logger
from app.models.enums import KeyType, ValidationMethod
from app.services.command import (
    CommandResult,
    assert_safe_script_path,
    run_command,
)

logger = get_logger(__name__)


class CertbotError(Exception):
    def __init__(self, message: str, result: CommandResult | None = None) -> None:
        super().__init__(message)
        self.result = result


@dataclass
class CertbotRequest:
    domains: list[str]
    email: str
    key_type: str = KeyType.RSA_2048.value
    validation_method: str = ValidationMethod.HTTP_01.value
    cert_name: str | None = None
    staging: bool = False
    dry_run: bool = False
    webroot_path: str | None = None
    standalone_port: int | None = None
    auth_hook: str | None = None
    cleanup_hook: str | None = None
    hook_env: dict[str, str] = field(default_factory=dict)
    hook_execution_user: str | None = None
    hook_working_directory: str | None = None
    hook_timeout: int = 300
    extra_args: list[str] = field(default_factory=list)
    workdir: str | None = None  # --config-dir/--work-dir/--logs-dir override
    rsa_key_size: int | None = None
    elliptic_curve: str | None = None
    prefer_chain: str | None = None


@dataclass
class CertbotOutcome:
    success: bool
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    result: CommandResult


def _key_type_args(req: CertbotRequest) -> list[str]:
    if req.key_type in (KeyType.ECDSA_P256.value, KeyType.ECDSA_P384.value):
        curve = req.elliptic_curve or (
            "secp256r1" if req.key_type == KeyType.ECDSA_P256.value else "secp384r1"
        )
        return ["--key-type", "ecdsa", "--elliptic-curve", curve]
    size = req.rsa_key_size or (4096 if req.key_type == KeyType.RSA_4096.value else 2048)
    return ["--key-type", "rsa", "--rsa-key-size", str(size)]


def _validation_args(req: CertbotRequest) -> list[str]:
    method = req.validation_method
    if method == ValidationMethod.HTTP_01.value:
        return ["--preferred-challenges", "http"]
    if method == ValidationMethod.DNS_01.value:
        return ["--preferred-challenges", "dns"]
    if method == ValidationMethod.STANDALONE.value:
        port = req.standalone_port or 80
        return ["--standalone", "--http-01-port", str(port)]
    if method == ValidationMethod.WEBROOT.value:
        if not req.webroot_path:
            raise CertbotError("webroot_path is required for webroot validation")
        Path(req.webroot_path)  # existence checked by certbot
        return ["--webroot", "-w", req.webroot_path]
    if method == ValidationMethod.MANUAL_HTTP.value:
        return ["--manual", "--preferred-challenges", "http"]
    if method == ValidationMethod.MANUAL_DNS.value:
        return ["--manual", "--preferred-challenges", "dns"]
    if method == ValidationMethod.CUSTOM.value:
        if not req.auth_hook:
            raise CertbotError("Custom validation requires an auth hook")
        # Select certbot's "manual" authenticator plugin — without this,
        # certbot has no authenticator to run --manual-auth-hook/-cleanup-hook
        # under and will fail to find a suitable plugin in non-interactive
        # mode. The actual hook flags are added once, by _hook_args() below
        # (previously duplicated here too).
        return ["--manual"]
    raise CertbotError(f"Unsupported validation method: {method}")


def _hook_args(req: CertbotRequest) -> list[str]:
    args: list[str] = []
    if req.auth_hook:
        assert_safe_script_path(req.auth_hook, executable_required=True)
        args += ["--manual-auth-hook", req.auth_hook]
    if req.cleanup_hook:
        assert_safe_script_path(req.cleanup_hook, executable_required=True)
        args += ["--manual-cleanup-hook", req.cleanup_hook]
    return args


def build_certbot_env(req: CertbotRequest) -> dict[str, str]:
    """Controlled env for hook scripts — no secrets from process env leak in."""
    env: dict[str, str] = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
    for k, v in (req.hook_env or {}).items():
        env[str(k)] = str(v)
    return env


def _workdir_args(workdir: str | None) -> list[str]:
    """config-dir/work-dir/logs-dir override — without it certbot falls back
    to its system defaults (/etc/letsencrypt, /var/lib/letsencrypt,
    /var/log/letsencrypt), which a non-root service account generally can't
    write to."""
    if not workdir:
        return []
    return ["--config-dir", str(workdir), "--work-dir", str(workdir),
            "--logs-dir", str(Path(settings.log_root_path) / "certbot")]


def build_issue_command(req: CertbotRequest) -> list[str]:
    domains = validate_domain_list(req.domains, allow_wildcard=True)
    argv: list[str] = [
        settings.certbot_binary,
        "certonly",
        "--non-interactive",
        "--agree-tos",
        "--no-self-upgrade",
        "-m", req.email,
        "--domains", ",".join(domains),
    ]
    if req.cert_name:
        argv += ["--cert-name", req.cert_name]
    argv += _key_type_args(req)
    argv += _validation_args(req)
    argv += _hook_args(req)
    argv += _workdir_args(req.workdir)
    if req.prefer_chain:
        argv += ["--preferred-chain", req.prefer_chain]
    if req.staging:
        argv += ["--staging"]
    if req.dry_run:
        argv += ["--dry-run"]
    argv += ["--verbose"]
    argv += req.extra_args
    return argv


def build_renew_command(cert_name: str, *, force: bool = False, staging: bool = False,
                        dry_run: bool = False, workdir: str | None = None) -> list[str]:
    argv: list[str] = [settings.certbot_binary, "renew", "--non-interactive", "--no-self-upgrade"]
    if cert_name:
        argv += ["--cert-name", cert_name]
    if force:
        argv += ["--force-renewal"]
    if dry_run:
        argv += ["--dry-run"]
    if staging:
        argv += ["--staging"]
    argv += _workdir_args(workdir)
    return argv


def build_revoke_command(cert_path: str, *, reason: str = "unspecified",
                         delete_after: bool = False, workdir: str | None = None) -> list[str]:
    argv: list[str] = [settings.certbot_binary, "revoke", "--cert-path", cert_path]
    valid_reasons = {"unspecified", "keycompromise", "affiliationchanged", "superseded",
                     "cessationofoperation"}
    if reason not in valid_reasons:
        raise CertbotError(f"Invalid revocation reason: {reason}")
    argv += ["--reason", reason]
    if delete_after:
        argv += ["--delete-after"]
    argv += _workdir_args(workdir)
    return argv


class CertbotExecutor:
    """Runs certbot commands and records execution metadata."""

    def __init__(self, timeout: int | None = None) -> None:
        self.timeout = timeout or settings.certbot_timeout_seconds

    def execute(self, argv: list[str], *, env: dict[str, str] | None = None,
                execution_user: str | None = None, cwd: str | None = None,
                timeout: int | None = None) -> CertbotOutcome:
        from app.core.metrics import CERTBOT_EXECUTIONS

        result = run_command(
            argv,
            env=env,
            execution_user=execution_user,
            cwd=cwd,
            timeout=timeout or self.timeout,
        )
        CERTBOT_EXECUTIONS.labels(result="success" if result.success else "failure").inc()
        return CertbotOutcome(
            success=result.success,
            exit_code=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            duration_ms=result.duration_ms,
            result=result,
        )

    def issue(self, req: CertbotRequest) -> CertbotOutcome:
        argv = build_issue_command(req)
        return self.execute(argv, env=build_certbot_env(req),
                            execution_user=req.hook_execution_user,
                            cwd=req.hook_working_directory,
                            timeout=req.hook_timeout)

    def renew(self, cert_name: str, *, force: bool = False, staging: bool = False,
              dry_run: bool = False, workdir: str | None = None) -> CertbotOutcome:
        return self.execute(build_renew_command(cert_name, force=force, staging=staging,
                                                 dry_run=dry_run, workdir=workdir))

    def revoke(self, cert_path: str, *, reason: str = "unspecified",
              workdir: str | None = None) -> CertbotOutcome:
        return self.execute(build_revoke_command(cert_path, reason=reason, workdir=workdir))

    @staticmethod
    def default_cert_directory() -> Path:
        return Path(settings.certbot_workdir) / "live"

    @staticmethod
    def cert_files(cert_name: str) -> dict[str, Path]:
        live = CertbotExecutor.default_cert_directory() / cert_name
        return {
            "cert": live / "cert.pem",
            "key": live / "privkey.pem",
            "chain": live / "chain.pem",
            "fullchain": live / "fullchain.pem",
        }
