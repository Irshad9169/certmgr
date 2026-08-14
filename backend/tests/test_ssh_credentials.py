"""TemporarySSHIdentity: stages a decrypted key + scoped ssh_config Host
entry for hook scripts that SSH out with no -i flag, and always cleans up.
Requires the include-dir prerequisite to already be wired into ~/.ssh/config
(a one-time, admin-performed step) — refuses to silently proceed without it."""

from __future__ import annotations

import os
import stat

import pytest

from app.core.config import settings
from app.core.exceptions import ValidationAppError
from app.services.ssh_credentials import (
    TemporarySSHIdentity,
    assert_valid_private_key_pem,
    ssh_config_include_ready,
)

_FAKE_PEM = "-----BEGIN OPENSSH PRIVATE KEY-----\nZmFrZQ==\n-----END OPENSSH PRIVATE KEY-----\n"


@pytest.fixture(autouse=True)
def _isolated_ssh_paths(tmp_path, monkeypatch):
    include_dir = tmp_path / ".ssh" / "certmgr.d"
    monkeypatch.setattr(settings, "ssh_config_include_dir", str(include_dir))
    monkeypatch.setattr(settings, "ssh_key_staging_dir", str(tmp_path / "ssh_keys"))
    return include_dir


def test_assert_valid_private_key_pem_rejects_garbage():
    with pytest.raises(ValidationAppError):
        assert_valid_private_key_pem("not a key")


def test_assert_valid_private_key_pem_accepts_pem():
    assert assert_valid_private_key_pem(_FAKE_PEM) == _FAKE_PEM


def test_include_not_ready_when_config_missing():
    assert ssh_config_include_ready() is False


def test_include_not_ready_when_config_lacks_include_line(_isolated_ssh_paths):
    config_path = _isolated_ssh_paths.parent / "config"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text("Host *\n  BatchMode yes\n")
    assert ssh_config_include_ready() is False


def test_include_ready_when_include_line_present(_isolated_ssh_paths):
    include_dir = _isolated_ssh_paths
    config_path = include_dir.parent / "config"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(f"Include {include_dir}/*.conf\nHost *\n  BatchMode yes\n")
    assert ssh_config_include_ready() is True


def test_temporary_identity_refuses_without_include_configured():
    with pytest.raises(ValidationAppError):
        with TemporarySSHIdentity(_FAKE_PEM, "host.example.com"):
            pass


def test_temporary_identity_requires_target_host(_isolated_ssh_paths):
    include_dir = _isolated_ssh_paths
    config_path = include_dir.parent / "config"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(f"Include {include_dir}/*.conf\n")
    with pytest.raises(ValidationAppError):
        TemporarySSHIdentity(_FAKE_PEM, None)


def test_temporary_identity_stages_and_cleans_up_files(_isolated_ssh_paths):
    include_dir = _isolated_ssh_paths
    config_path = include_dir.parent / "config"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(f"Include {include_dir}/*.conf\n")

    with TemporarySSHIdentity(_FAKE_PEM, "target.example.com") as identity:
        key_path = identity._key_path
        frag_path = identity._config_path
        assert key_path.exists()
        assert frag_path.exists()
        assert key_path.read_text() == _FAKE_PEM
        if os.name == "posix":  # chmod bits are not meaningful on Windows/NTFS
            mode = stat.S_IMODE(key_path.stat().st_mode)
            assert mode == 0o600
        frag = frag_path.read_text()
        assert "Host target.example.com" in frag
        assert str(key_path) in frag
        assert "IdentitiesOnly yes" in frag

    assert not key_path.exists()
    assert not frag_path.exists()


def test_temporary_identity_cleans_up_on_exception(_isolated_ssh_paths):
    include_dir = _isolated_ssh_paths
    config_path = include_dir.parent / "config"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(f"Include {include_dir}/*.conf\n")

    key_path = frag_path = None
    with pytest.raises(RuntimeError):
        with TemporarySSHIdentity(_FAKE_PEM, "target.example.com") as identity:
            key_path = identity._key_path
            frag_path = identity._config_path
            raise RuntimeError("boom")

    assert key_path is not None
    assert not key_path.exists()
    assert not frag_path.exists()


def test_letsencrypt_provider_surfaces_missing_include_as_failed_issuance():
    """The provider must catch TemporarySSHIdentity's ValidationAppError and
    turn it into a normal failed IssueResult (visible to the user as a clear
    error), not let it propagate and crash the issuance/task."""
    from app.core.security import encrypt_secret
    from app.services.providers.base import IssueRequest
    from app.services.providers.letsencrypt import LetsEncryptProvider

    provider = LetsEncryptProvider()
    request = IssueRequest(
        domains=["example.com"], email="ops@corp.com",
        ssh_private_key_encrypted=encrypt_secret(_FAKE_PEM),
        ssh_target_host="host.example.com",
    )
    result = provider.issue(request)
    assert result.success is False
    assert "one-time setup" in (result.error or "")
