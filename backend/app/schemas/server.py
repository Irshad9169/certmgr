"""Server schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.domain_utils import is_valid_ip, validate_domain, validate_port, validate_proxy_jump


class ServerCreate(BaseModel):
    hostname: str = Field(max_length=253)
    ip_address: str | None = None
    environment: str = "production"
    os_type: str = "linux"
    ssh_port: int = 22
    auth_method: str = "ssh_key"
    ssh_user: str = "root"
    ssh_password: str | None = None
    ssh_key_path: str | None = None
    ssh_key_passphrase: str | None = None
    proxy_jump: str | None = None
    certificate_directory: str | None = None
    web_server_type: str | None = None
    owner_id: int | None = None
    tags: list[str] = Field(default_factory=list)
    notes: str | None = None

    @field_validator("hostname")
    @classmethod
    def _hostname(cls, v: str) -> str:
        return validate_domain(v)

    @field_validator("ip_address")
    @classmethod
    def _ip(cls, v: str | None) -> str | None:
        if v and not is_valid_ip(v):
            raise ValueError("Invalid IP address")
        return v

    @field_validator("ssh_port")
    @classmethod
    def _port(cls, v: int) -> int:
        return validate_port(v)

    @field_validator("proxy_jump")
    @classmethod
    def _proxy_jump(cls, v: str | None) -> str | None:
        return validate_proxy_jump(v) if v else v


class ServerUpdate(BaseModel):
    hostname: str | None = None
    ip_address: str | None = None
    environment: str | None = None
    os_type: str | None = None
    ssh_port: int | None = None
    auth_method: str | None = None
    ssh_user: str | None = None
    ssh_password: str | None = None
    ssh_key_path: str | None = None
    ssh_key_passphrase: str | None = None
    proxy_jump: str | None = None
    certificate_directory: str | None = None
    web_server_type: str | None = None
    owner_id: int | None = None
    tags: list[str] | None = None
    notes: str | None = None

    @field_validator("proxy_jump")
    @classmethod
    def _proxy_jump(cls, v: str | None) -> str | None:
        return validate_proxy_jump(v) if v else v


class ServerOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    hostname: str
    ip_address: str | None
    environment: str
    os_type: str
    ssh_port: int
    auth_method: str
    ssh_user: str
    ssh_key_path: str | None
    proxy_jump: str | None
    certificate_directory: str | None
    web_server_type: str | None
    owner_id: int | None
    connection_status: str
    last_check_at: datetime | None
    notes: str | None
    tags: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime
