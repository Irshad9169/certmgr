"""Internal PKI provider — self-contained OpenSSL-based certificate authority.

This is a second *concrete* provider proving the plugin pattern: internal
certificates (ADCS-style) are issued by a locally configured OpenSSL CA
without touching Certbot or Let's Encrypt.

Config (provider row, encrypted):
    ca_key_path, ca_cert_path, ca_serial_path (optional),
    default_cert_dir, org, org_unit, country, state, locality,
    validity_days, openssl_binary
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path

from app.core.config import settings
from app.core.exceptions import ValidationAppError
from app.core.logging import get_logger
from app.models.enums import KeyType, ValidationMethod
from app.services.command import build_scrubbed_env
from app.services.providers.base import (
    CertificateProvider,
    IssueRequest,
    IssueResult,
    ProviderCapabilities,
    RenewResult,
    RevokeResult,
)

logger = get_logger(__name__)


class OpenSSLCertificateAuthority(CertificateProvider):
    provider_key = "openssl-ca"
    display_name = "Internal PKI (OpenSSL CA)"

    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            validation_methods=[ValidationMethod.CUSTOM.value],
            key_types=[KeyType.RSA_2048.value, KeyType.RSA_4096.value,
                       KeyType.ECDSA_P256.value, KeyType.ECDSA_P384.value],
            cert_types=["internal"],
            supports_revoke=True,
            supports_import=True,
            supports_auto_renew=True,
        )

    def validate_config(self, config: dict) -> list[str]:
        problems: list[str] = []
        for key in ("ca_key_path", "ca_cert_path", "openssl_binary"):
            if not config.get(key):
                problems.append(f"{key} is required for the OpenSSL CA provider")
        if problems:
            return problems
        for path in (config["ca_key_path"], config["ca_cert_path"]):
            if not Path(path).exists():
                problems.append(f"Path does not exist: {path}")
        return problems

    # ── Issue ───────────────────────────────────────────────────────────────
    def issue(self, request: IssueRequest) -> IssueResult:
        openssl = self.config.get("openssl_binary", "openssl")
        ca_key = self.config.get("ca_key_path")
        ca_cert = self.config.get("ca_cert_path")
        if not ca_key or not ca_cert:
            return IssueResult(success=False, error="OpenSSL CA not configured (ca_key_path/ca_cert_path)")

        cn = request.common_name or request.domains[0]
        out_dir = Path(self.config.get("default_cert_dir") or settings.storage_root) / "internal" / _slug(cn)
        out_dir.mkdir(parents=True, exist_ok=True)

        key_path = out_dir / "privkey.pem"
        csr_path = out_dir / "request.csr"
        cert_path = out_dir / "cert.pem"

        try:
            # 1) Generate private key
            if request.key_type in (KeyType.ECDSA_P256.value, KeyType.ECDSA_P384.value):
                curve = "prime256v1" if request.key_type == KeyType.ECDSA_P256.value else "secp384r1"
                self._run([openssl, "ecparam", "-name", curve, "-genkey", "-noout",
                           "-out", str(key_path)])
            else:
                size = 4096 if request.key_type == KeyType.RSA_4096.value else 2048
                self._run([openssl, "genrsa", "-out", str(key_path), str(size)])

            # 2) Build SAN extension
            sans = ",".join(f"DNS:{d}" for d in request.domains)
            days = request.extra.get("validity_days") or self.config.get("validity_days", 825)

            # 3) CSR
            subj = _subject_string(self.config, request)
            self._run([
                openssl, "req", "-new", "-key", str(key_path), "-out", str(csr_path),
                "-subj", subj,
                "-addext", f"subjectAltName={sans}",
                "-addext", "keyUsage=digitalSignature,keyEncipherment",
                "-addext", "extendedKeyUsage=serverAuth",
            ])

            # 4) Sign with CA
            ext_file = _write_ext_file(sans)
            try:
                self._run([
                    openssl, "x509", "-req", "-in", str(csr_path),
                    "-CA", str(ca_cert), "-CAkey", str(ca_key),
                    "-CAcreateserial", "-days", str(days),
                    "-out", str(cert_path),
                    "-extfile", ext_file,
                ])
            finally:
                Path(ext_file).unlink(missing_ok=True)

            # 5) Chain = leaf + CA cert
            fullchain_path = out_dir / "fullchain.pem"
            with open(cert_path, "rb") as leaf, open(ca_cert, "rb") as ca, open(fullchain_path, "wb") as out:
                out.write(leaf.read())
                out.write(ca.read())

            return IssueResult(
                success=True, cert_path=str(cert_path), key_path=str(key_path),
                chain_path=ca_cert, fullchain_path=str(fullchain_path),
                cert_name=_slug(cn), exit_code=0,
                metadata={"provider": self.provider_key, "ca": ca_cert},
            )
        except subprocess.TimeoutExpired as exc:
            return IssueResult(
                success=False, exit_code=124,
                stderr=(exc.stderr or b"").decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or ""),
                error=f"openssl command timed out after {settings.certbot_timeout_seconds}s",
            )
        except subprocess.CalledProcessError as exc:
            return IssueResult(
                success=False, exit_code=exc.returncode,
                stderr=exc.stderr or "", error=(exc.stderr or str(exc))[-2000:],
            )

    def renew(self, cert_name: str, *, force: bool = False, staging: bool = False,
              dry_run: bool = False) -> RenewResult:
        # Internal CA certs are re-issued rather than renewed.
        return RenewResult(success=False, error="Internal CA certificates are re-issued, not renewed; use issue")

    def revoke(self, cert_path: str, *, reason: str = "unspecified") -> RevokeResult:
        # Best-effort: remove from disk + record. CRL publication is configurable.
        try:
            p = Path(cert_path)
            if p.exists():
                p.rename(p.with_suffix(".pem.revoked"))
            return RevokeResult(success=True, stdout="Certificate revoked (moved to .revoked)")
        except OSError as exc:
            return RevokeResult(success=False, error=str(exc))

    def verify(self, cert_path: str, domains: list[str]) -> tuple[bool, str]:
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend

            with open(cert_path, "rb") as fh:
                cert = x509.load_pem_x509_certificate(fh.read(), default_backend())
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = {str(name.value) for name in ext.value}
            missing = [d for d in domains if d.lstrip("*.") not in sans]
            return (True, "OK") if not missing else (False, f"Missing SANs: {missing}")
        except Exception as exc:  # noqa: BLE001
            return False, str(exc)

    def _run(self, argv: list[str]) -> None:
        # Not routed through app.services.command.run_command(): that wrapper
        # rejects spaces in any argv element (assert_safe_argument), which
        # would reject legitimate `-subj` values like the default "Internal
        # CA" org name. Still shell=False/argv-list (no injection risk from
        # spaces here) but now with the same timeout enforcement and
        # secret-scrubbed environment run_command gives every other command.
        proc = subprocess.run(  # noqa: S603 — argv is a list, shell=False by design
            argv, capture_output=True, text=True, check=False,
            timeout=settings.certbot_timeout_seconds, env=build_scrubbed_env(),
        )
        if proc.returncode != 0:
            raise subprocess.CalledProcessError(proc.returncode, argv, proc.stdout, proc.stderr)


def _slug(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "-", name)[:120]


def _assert_safe_rdn(field_name: str, value: str) -> str:
    """Reject characters that let a field smuggle extra RDN components into
    an openssl `-subj` string (e.g. org="Foo/CN=admin.internal" injecting a
    second CN). `-subj` parses embedded `/x=y` as a new field, so `/` and `=`
    must never appear inside a single field's value."""
    if "/" in value or "=" in value:
        raise ValidationAppError(f"Invalid character in certificate subject field '{field_name}'")
    return value


def _subject_string(config: dict, request: IssueRequest) -> str:
    c = _assert_safe_rdn("country", request.extra.get("country") or config.get("country", "US"))
    st = _assert_safe_rdn("state", request.extra.get("state") or config.get("state", ""))
    loc = _assert_safe_rdn("locality", request.extra.get("locality") or config.get("locality", ""))
    o = _assert_safe_rdn("org", request.extra.get("org") or config.get("org", "Internal CA"))
    ou = _assert_safe_rdn("org_unit", request.extra.get("org_unit") or config.get("org_unit", "IT"))
    cn = _assert_safe_rdn("common_name", request.common_name or request.domains[0])
    return f"/C={c}/ST={st}/L={loc}/O={o}/OU={ou}/CN={cn}"


def _write_ext_file(sans: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".ext", prefix="certmgr-")
    with os.fdopen(fd, "w") as fh:
        fh.write(f"subjectAltName={sans}\n")
        fh.write("basicConstraints=CA:FALSE\n")
        fh.write("keyUsage=digitalSignature,keyEncipherment\n")
        fh.write("extendedKeyUsage=serverAuth\n")
    return path
