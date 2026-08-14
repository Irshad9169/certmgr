"""Let's Encrypt provider — ACME v2 via the Certbot CLI."""

from __future__ import annotations

import re

from app.core.config import settings
from app.core.exceptions import SecurityError, ValidationAppError
from app.core.logging import get_logger
from app.models.enums import KeyType, ValidationMethod
from app.services.certbot import CertbotError, CertbotExecutor, CertbotRequest
from app.services.providers.base import (
    CertificateProvider,
    IssueRequest,
    IssueResult,
    ProviderCapabilities,
    RenewResult,
    RevokeResult,
)

logger = get_logger(__name__)

_VALIDATION_METHODS = [
    ValidationMethod.HTTP_01.value,
    ValidationMethod.DNS_01.value,
    ValidationMethod.MANUAL_DNS.value,
    ValidationMethod.MANUAL_HTTP.value,
    ValidationMethod.STANDALONE.value,
    ValidationMethod.WEBROOT.value,
    ValidationMethod.CUSTOM.value,
]
_KEY_TYPES = [KeyType.RSA_2048.value, KeyType.RSA_4096.value,
              KeyType.ECDSA_P256.value, KeyType.ECDSA_P384.value]
_RENEW_SKIPPED = re.compile(r"No renewals were attempted|not yet due for renewal", re.IGNORECASE)


class LetsEncryptProvider(CertificateProvider):
    provider_key = "letsencrypt"
    display_name = "Let's Encrypt (Certbot / ACME v2)"

    def __init__(self, config: dict | None = None) -> None:
        super().__init__(config)
        self.executor = CertbotExecutor(timeout=self.config.get("timeout_seconds"))

    # ── Capabilities ────────────────────────────────────────────────────────
    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            validation_methods=_VALIDATION_METHODS,
            key_types=_KEY_TYPES,
            cert_types=["single", "multi", "wildcard"],
            supports_revoke=True,
            supports_import=False,
            supports_auto_renew=True,
        )

    def validate_config(self, config: dict) -> list[str]:
        problems: list[str] = []
        email = config.get("email") or settings.default_letsencrypt_email
        if not email or "@" not in email:
            problems.append("A valid Let's Encrypt contact email is required")
        return problems

    # ── Issue ───────────────────────────────────────────────────────────────
    def issue(self, request: IssueRequest) -> IssueResult:
        email = request.email or settings.default_letsencrypt_email
        req = CertbotRequest(
            domains=request.domains,
            email=email,
            key_type=request.key_type,
            validation_method=request.validation_method,
            cert_name=request.cert_name,
            staging=request.staging or (not request.dry_run and settings.default_staging),
            dry_run=request.dry_run,
            webroot_path=request.webroot_path,
            standalone_port=request.standalone_port,
            auth_hook=request.auth_hook,
            cleanup_hook=request.cleanup_hook,
            hook_env=request.hook_env,
            hook_execution_user=request.hook_execution_user,
            hook_working_directory=request.hook_working_directory,
            hook_timeout=request.hook_timeout,
            # Falls back to the admin-configured CERTMGR_CERTBOT_WORKDIR so
            # certbot actually writes into a location the service account can
            # use (config-dir/work-dir/logs-dir) instead of silently trying
            # its own system defaults (/etc/letsencrypt, /var/lib/letsencrypt,
            # /var/log/letsencrypt) — which a non-root service user generally
            # can't write to. `extra.workdir` still overrides per-request.
            workdir=request.extra.get("workdir") or settings.certbot_workdir,
            prefer_chain=request.extra.get("prefer_chain"),
        )
        try:
            if request.ssh_private_key_encrypted:
                from app.core.security import decrypt_secret
                from app.services.ssh_credentials import TemporarySSHIdentity

                private_key = decrypt_secret(request.ssh_private_key_encrypted)
                with TemporarySSHIdentity(private_key, request.ssh_target_host):
                    outcome = self.executor.issue(req)
            else:
                outcome = self.executor.issue(req)
        except (CertbotError, OSError, ValidationAppError, SecurityError) as exc:
            return IssueResult(success=False, error=str(exc))

        if outcome.success and not request.dry_run:
            cert_name = request.cert_name or _derive_cert_name(request.domains)
            files = CertbotExecutor.cert_files(cert_name)
            missing = [p for p in files.values() if not p.exists()]
            if missing:
                return IssueResult(
                    success=False,
                    stdout=outcome.stdout, stderr=outcome.stderr,
                    exit_code=outcome.exit_code, duration_ms=outcome.duration_ms,
                    error=f"Certbot succeeded but files missing: {[str(m) for m in missing]}",
                )
            return IssueResult(
                success=True,
                cert_path=str(files["cert"]), key_path=str(files["key"]),
                chain_path=str(files["chain"]), fullchain_path=str(files["fullchain"]),
                cert_name=cert_name, exit_code=outcome.exit_code,
                stdout=outcome.stdout, stderr=outcome.stderr, duration_ms=outcome.duration_ms,
            )
        return IssueResult(
            success=False, exit_code=outcome.exit_code,
            stdout=outcome.stdout, stderr=outcome.stderr, duration_ms=outcome.duration_ms,
            error=outcome.stderr.strip()[-2000:] or "Certbot exited non-zero",
        )

    # ── Renew ───────────────────────────────────────────────────────────────
    def renew(self, cert_name: str, *, force: bool = False, staging: bool = False,
              dry_run: bool = False) -> RenewResult:
        try:
            outcome = self.executor.renew(cert_name, force=force, staging=staging, dry_run=dry_run,
                                          workdir=settings.certbot_workdir)
        except (CertbotError, OSError) as exc:
            return RenewResult(success=False, error=str(exc))

        renewed = outcome.success and not _RENEW_SKIPPED.search(outcome.stdout + outcome.stderr)
        files = CertbotExecutor.cert_files(cert_name)
        return RenewResult(
            success=outcome.success,
            renewed=renewed and not dry_run,
            cert_path=str(files["cert"]) if files["cert"].exists() else None,
            key_path=str(files["key"]) if files["key"].exists() else None,
            chain_path=str(files["chain"]) if files["chain"].exists() else None,
            fullchain_path=str(files["fullchain"]) if files["fullchain"].exists() else None,
            exit_code=outcome.exit_code, stdout=outcome.stdout, stderr=outcome.stderr,
            duration_ms=outcome.duration_ms,
            error=None if outcome.success else outcome.stderr.strip()[-2000:],
        )

    # ── Revoke ──────────────────────────────────────────────────────────────
    def revoke(self, cert_path: str, *, reason: str = "unspecified") -> RevokeResult:
        try:
            outcome = self.executor.revoke(cert_path, reason=reason, workdir=settings.certbot_workdir)
        except (CertbotError, OSError) as exc:
            return RevokeResult(success=False, error=str(exc))
        return RevokeResult(
            success=outcome.success, stdout=outcome.stdout, stderr=outcome.stderr,
            exit_code=outcome.exit_code,
            error=None if outcome.success else outcome.stderr.strip()[-2000:],
        )

    # ── Verify ──────────────────────────────────────────────────────────────
    def verify(self, cert_path: str, domains: list[str]) -> tuple[bool, str]:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        try:
            with open(cert_path, "rb") as fh:
                cert = x509.load_pem_x509_certificate(fh.read(), default_backend())
        except Exception as exc:  # noqa: BLE001
            return False, f"Cannot parse certificate: {exc}"

        sans: set[str] = set()
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = {str(name.value) for name in ext.value}
        except x509.ExtensionNotFound:
            pass
        missing = [d for d in domains if d.lstrip("*.") not in sans]
        if missing:
            return False, f"Certificate does not cover: {missing}"
        return True, "Certificate covers all requested domains"


def _derive_cert_name(domains: list[str]) -> str:
    primary = domains[0].replace("*", "wildcard")
    return re.sub(r"[^A-Za-z0-9_.-]", "-", primary)[:120]
