"""Certificate provider abstraction.

New CAs (DigiCert, GoDaddy, Sectigo, GlobalSign, Entrust, MS ADCS, internal PKI)
are added by implementing CertificateProvider and registering it via the plugin
registry — the core application never changes.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class IssueRequest:
    """Normalized issuance request consumed by every provider."""

    domains: list[str]
    email: str
    key_type: str = "rsa2048"          # rsa2048 | rsa4096 | ecdsa_p256 | ecdsa_p384
    validation_method: str = "http-01"  # http-01 | dns-01 | manual-* | standalone | webroot | custom
    environment: str = "production"
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
    ssh_private_key_encrypted: str | None = None
    ssh_target_host: str | None = None
    cert_name: str | None = None
    common_name: str | None = None
    organizational_units: list[str] = field(default_factory=list)
    validity_days: int = 90
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class IssueResult:
    success: bool
    cert_path: str | None = None
    key_path: str | None = None
    chain_path: str | None = None
    fullchain_path: str | None = None
    pfx_path: str | None = None
    cert_name: str | None = None
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


@dataclass
class RenewResult:
    success: bool
    renewed: bool = False          # False when certbot says "no renewal attempted"
    cert_path: str | None = None
    key_path: str | None = None
    chain_path: str | None = None
    fullchain_path: str | None = None
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    error: str | None = None


@dataclass
class RevokeResult:
    success: bool
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    error: str | None = None


@dataclass
class ProviderCapabilities:
    validation_methods: list[str]
    key_types: list[str]
    cert_types: list[str]        # single | multi | wildcard | internal | imported
    supports_revoke: bool = True
    supports_import: bool = True
    supports_auto_renew: bool = True


class CertificateProvider(ABC):
    """Interface implemented by each certificate authority plugin."""

    provider_key: str = "base"
    display_name: str = "Base Provider"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config: dict[str, Any] = config or {}

    @abstractmethod
    def capabilities(self) -> ProviderCapabilities:
        """What this provider supports (drives wizard steps in the UI)."""

    @abstractmethod
    def validate_config(self, config: dict[str, Any]) -> list[str]:
        """Return a list of configuration problems (empty == valid)."""

    @abstractmethod
    def issue(self, request: IssueRequest) -> IssueResult:
        """Request a certificate; returns file paths of issued material."""

    @abstractmethod
    def renew(self, cert_name: str, *, force: bool = False, staging: bool = False,
              dry_run: bool = False) -> RenewResult:
        """Renew an existing certificate managed by this provider."""

    @abstractmethod
    def revoke(self, cert_path: str, *, reason: str = "unspecified") -> RevokeResult:
        """Revoke a certificate."""

    @abstractmethod
    def verify(self, cert_path: str, domains: list[str]) -> tuple[bool, str]:
        """Validate the issued certificate matches the requested domains."""

    @classmethod
    def from_config(cls, config: dict[str, Any] | None = None) -> CertificateProvider:
        return cls(config)
