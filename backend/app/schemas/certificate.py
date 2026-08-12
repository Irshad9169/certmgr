"""Certificate schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.domain_utils import validate_domain_list


class IssueRequestSchema(BaseModel):
    """Full issuance request (wizard submit). Individual wizard steps can be
    validated with the /certificates/wizard/validate endpoints."""

    domains: list[str] = Field(min_length=1, max_length=200)
    email: str | None = Field(default=None, max_length=255)
    provider: str = Field(default="letsencrypt", max_length=64)
    validation_method: str = Field(default="http-01", max_length=32)
    key_type: str = Field(default="rsa2048", max_length=16)
    environment: str = Field(default="production", max_length=32)
    staging: bool = False
    dry_run: bool = False
    auto_renew: bool = True
    webroot_path: str | None = Field(default=None, max_length=1024)
    standalone_port: int | None = Field(default=None, ge=1, le=65535)
    auth_hook: str | None = Field(default=None, max_length=2048)
    cleanup_hook: str | None = Field(default=None, max_length=2048)
    auth_hook_id: int | None = None
    cleanup_hook_id: int | None = None
    hook_env: dict[str, str] = Field(default_factory=dict)
    cert_name: str | None = Field(default=None, max_length=200)
    owner_id: int | None = None
    tags: list[str] = Field(default_factory=list, max_length=50)
    notes: str | None = Field(default=None, max_length=4000)
    extra: dict[str, Any] = Field(default_factory=dict)

    @field_validator("domains")
    @classmethod
    def _domains(cls, v: list[str]) -> list[str]:
        return validate_domain_list(v, allow_wildcard=True)


class RenewRequest(BaseModel):
    force: bool = False


class RevokeRequest(BaseModel):
    reason: str = Field(default="unspecified", max_length=64)
    delete_after: bool = True


class CloneRequest(BaseModel):
    domains: list[str] | None = None


class ImportRequest(BaseModel):
    """Server-side import (from paths on the platform host)."""

    cert_path: str = Field(min_length=1, max_length=2048)
    key_path: str | None = Field(default=None, max_length=2048)
    chain_path: str | None = Field(default=None, max_length=2048)
    environment: str = "production"
    auto_renew: bool = False
    tags: list[str] = Field(default_factory=list)
    owner_id: int | None = None
    notes: str | None = None


class CertificateOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    domain: str
    cert_name: str | None
    sans: list[str]
    is_wildcard: bool
    cert_type: str
    subject: str | None
    issuer: str | None
    serial_number: str | None
    fingerprint_sha256: str | None
    public_key_algorithm: str | None
    key_type: str
    key_size: int | None
    signature_algorithm: str | None
    valid_from: datetime | None
    valid_until: datetime | None
    status: str
    environment: str
    provider_name: str
    validation_method: str
    auto_renew: bool
    renewal_status: str
    renewal_error: str | None
    last_renewed_at: datetime | None
    imported: bool
    staging: bool
    owner_id: int | None
    notes: str | None
    favorite: bool
    health_score: float | None
    health_status: str
    compliance_status: str
    days_remaining: int | None
    created_at: datetime
    updated_at: datetime
    tags: list[str] = Field(default_factory=list)

    @field_validator("tags", mode="before")
    @classmethod
    def _tags(cls, v):
        if v is None:
            return []
        return [t.name if hasattr(t, "name") else str(t) for t in v]

    @field_validator("days_remaining", mode="before")
    @classmethod
    def _days(cls, v):
        return int(v) if v is not None else None


class PaginatedCertificates(BaseModel):
    items: list[CertificateOut]
    total: int
    page: int
    page_size: int
    pages: int
    summary: dict[str, int] = Field(default_factory=dict)
