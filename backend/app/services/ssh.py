"""Secure SSH/SFTP/SCP client wrapper (paramiko).

Passwords are decrypted only in-memory for the connection attempt and never
logged. Supports SSH keys, passwords and jump hosts (ProxyJump).
"""

from __future__ import annotations

import io
import os
from dataclasses import dataclass
from typing import Any

from app.core.config import settings
from app.core.logging import get_logger, redact
from app.core.security import decrypt_secret

logger = get_logger(__name__)


class SSHConnectionError(Exception):
    pass


@dataclass
class SSHResult:
    command: str
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0


@dataclass
class SSHConfig:
    hostname: str
    port: int = 22
    username: str = "root"
    password: str | None = None
    key_path: str | None = None
    key_passphrase: str | None = None
    proxy_jump: str | None = None
    connect_timeout: int = 10
    command_timeout: int = 120


class SSHClient:
    def __init__(self, config: SSHConfig) -> None:
        self.config = config
        self._client = None
        self._sftp = None

    # ── Connection ──────────────────────────────────────────────────────────
    def connect(self) -> None:
        import paramiko

        try:
            client = paramiko.SSHClient()
            # AutoAddPolicy for managed hosts; pin host keys via known_hosts
            # for stricter environments.
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # noqa: S507

            connect_kwargs: dict[str, Any] = {
                "hostname": self.config.hostname,
                "port": self.config.port,
                "username": self.config.username,
                "timeout": self.config.connect_timeout,
                "allow_agent": bool(self.config.password is None and not self.config.key_path),
            }
            if self.config.password:
                connect_kwargs["password"] = self.config.password
            if self.config.key_path and os.path.exists(self.config.key_path):
                connect_kwargs["key_filename"] = self.config.key_path
                if self.config.key_passphrase:
                    connect_kwargs["passphrase"] = self.config.key_passphrase
            if self.config.proxy_jump:
                connect_kwargs["sock"] = self._build_proxy_socket(paramiko)

            client.connect(**connect_kwargs)
            self._client = client
        except Exception as exc:  # noqa: BLE001
            raise SSHConnectionError(
                f"Cannot connect to {self.config.username}@{self.config.hostname}:{self.config.port}: "
                f"{redact(str(exc))}"
            ) from exc

    def _build_proxy_socket(self, paramiko):
        # ProxyCommand runs this string via a local shell, so the spec must be
        # strictly validated first — an attacker-controlled user/host here is
        # arbitrary command execution on the CertMgr host itself, not just the
        # remote server.
        from paramiko import ProxyCommand

        from app.core.domain_utils import validate_proxy_jump

        spec = validate_proxy_jump(self.config.proxy_jump)
        user, hostport = spec.rsplit("@", 1)
        host, _, port = hostport.partition(":")
        port = int(port) if port else 22
        cmd = f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -W {host}:{port} -p 22 {user}@{host}"
        return ProxyCommand(cmd)

    def _ensure(self):
        if self._client is None:
            self.connect()
        return self._client

    # ── Execution ───────────────────────────────────────────────────────────
    def exec(self, command: str, *, timeout: int | None = None) -> SSHResult:
        import time as _time

        client = self._ensure()
        timeout = timeout or self.config.command_timeout
        start = _time.perf_counter()
        logger.info("SSH exec on %s: %s", self.config.hostname, redact(command)[:500])
        try:
            stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            code = stdout.channel.recv_exit_status()
            return SSHResult(
                command=command, exit_code=code, stdout=out, stderr=err,
                duration_ms=int((_time.perf_counter() - start) * 1000),
            )
        except Exception as exc:  # noqa: BLE001
            raise SSHConnectionError(f"SSH command failed: {redact(str(exc))}") from exc

    # ── File transfer ───────────────────────────────────────────────────────
    def sftp_put(self, local_path: str, remote_path: str, mode: int = 0o600) -> None:
        client = self._ensure()
        if self._sftp is None:
            self._sftp = client.open_sftp()
        self._sftp.put(local_path, remote_path)
        self._sftp.chmod(remote_path, mode)

    def sftp_put_bytes(self, data: bytes, remote_path: str, mode: int = 0o600) -> None:
        client = self._ensure()
        if self._sftp is None:
            self._sftp = client.open_sftp()
        with self._sftp.open(remote_path, "wb") as fh:
            fh.write(data)
        self._sftp.chmod(remote_path, mode)

    def sftp_get_bytes(self, remote_path: str) -> bytes:
        client = self._ensure()
        if self._sftp is None:
            self._sftp = client.open_sftp()
        buf = io.BytesIO()
        with self._sftp.open(remote_path, "rb") as fh:
            buf.write(fh.read())
        return buf.getvalue()

    def sftp_mkdir_p(self, remote_path: str) -> None:
        self.exec(f"mkdir -p {_quote(remote_path)}")

    def close(self) -> None:
        try:
            if self._sftp:
                self._sftp.close()
            if self._client:
                self._client.close()
        finally:
            self._sftp = None
            self._client = None

    def __enter__(self) -> SSHClient:
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def _quote(path: str) -> str:
    return path.replace("'", "'\\''").replace(" ", "\\ ")


def build_ssh_config(server) -> SSHConfig:
    """Convert a Server model row into a connection config (decrypts password)."""
    password = None
    if server.ssh_password_encrypted:
        password = decrypt_secret(server.ssh_password_encrypted)
    passphrase = None
    if server.ssh_key_passphrase_encrypted:
        passphrase = decrypt_secret(server.ssh_key_passphrase_encrypted)
    return SSHConfig(
        hostname=server.ip_address or server.hostname,
        port=server.ssh_port,
        username=server.ssh_user,
        password=password,
        key_path=server.ssh_key_path,
        key_passphrase=passphrase,
        proxy_jump=server.proxy_jump,
        connect_timeout=settings.ssh_connect_timeout,
        command_timeout=settings.ssh_command_timeout,
    )
