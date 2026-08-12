"""Certbot command construction — verify correct flags and no shell injection."""

from __future__ import annotations

import pytest

from app.core.exceptions import ValidationAppError
from app.services.certbot import (
    CertbotError,
    CertbotRequest,
    build_issue_command,
    build_renew_command,
    build_revoke_command,
)


def test_issue_http01_rsa2048():
    argv = build_issue_command(
        CertbotRequest(domains=["example.com"], email="ops@corp.com", key_type="rsa2048")
    )
    joined = " ".join(argv)
    assert argv[0] == "certbot"
    assert "certonly" in argv
    assert "--non-interactive" in argv
    assert "--domains example.com" in joined
    assert "--key-type rsa" in joined
    assert "--rsa-key-size 2048" in joined
    assert "--preferred-challenges http" in joined
    assert "--staging" not in joined
    assert any(c in joined for c in (";", "|", "&", "$", "`")) is False


def test_issue_rsa4096():
    argv = build_issue_command(
        CertbotRequest(domains=["x.io"], email="a@b.com", key_type="rsa4096")
    )
    assert "--rsa-key-size 4096" in " ".join(argv)


def test_issue_ecdsa_p384():
    argv = build_issue_command(
        CertbotRequest(domains=["x.io"], email="a@b.com", key_type="ecdsa_p384")
    )
    joined = " ".join(argv)
    assert "--key-type ecdsa" in joined
    assert "--elliptic-curve secp384r1" in joined


def test_issue_dns01_and_staging():
    argv = build_issue_command(
        CertbotRequest(domains=["x.io"], email="a@b.com", validation_method="dns-01",
                       staging=True)
    )
    joined = " ".join(argv)
    assert "--preferred-challenges dns" in joined
    assert "--staging" in joined


def test_issue_standalone():
    argv = build_issue_command(
        CertbotRequest(domains=["x.io"], email="a@b.com", validation_method="standalone",
                       standalone_port=8443)
    )
    joined = " ".join(argv)
    assert "--standalone" in joined
    assert "--http-01-port 8443" in joined


def test_issue_webroot():
    argv = build_issue_command(
        CertbotRequest(domains=["x.io"], email="a@b.com", validation_method="webroot",
                       webroot_path="/var/www/html")
    )
    joined = " ".join(argv)
    assert "--webroot -w /var/www/html" in joined


def test_issue_custom_hooks(tmp_path):
    auth = tmp_path / "auth.pl"
    clean = tmp_path / "clean.pl"
    for p in (auth, clean):
        p.write_text("#!/bin/sh\necho x\n")
        p.chmod(0o755)
    argv = build_issue_command(
        CertbotRequest(domains=["x.io"], email="a@b.com", validation_method="custom",
                       auth_hook=str(auth), cleanup_hook=str(clean))
    )
    joined = " ".join(argv)
    assert "--manual-auth-hook" in joined
    assert str(auth) in joined
    assert str(clean) in joined


def test_issue_missing_hook_file_rejected(tmp_path):
    with pytest.raises(ValidationAppError):
        build_issue_command(
            CertbotRequest(domains=["x.io"], email="a@b.com", validation_method="custom",
                           auth_hook=str(tmp_path / "missing.pl"))
        )


def test_renew_command():
    argv = build_renew_command("my-cert", force=True, dry_run=True)
    joined = " ".join(argv)
    assert "--cert-name my-cert" in joined
    assert "--force-renewal" in joined
    assert "--dry-run" in joined


def test_revoke_command_reason_validation():
    with pytest.raises(CertbotError):
        build_revoke_command("/tmp/cert.pem", reason="; rm -rf /")
    argv = build_revoke_command("/etc/letsencrypt/live/x/cert.pem", reason="keycompromise")
    assert "--reason keycompromise" in " ".join(argv)


def test_issue_domain_injection_rejected():
    with pytest.raises(ValidationAppError):
        build_issue_command(
            CertbotRequest(domains=["x.io; touch /tmp/pwned"], email="a@b.com")
        )
