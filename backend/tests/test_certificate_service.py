"""Certificate service: import (PEM/PFX), metadata extraction, key-at-rest
encryption, issuance with a mocked provider."""

from __future__ import annotations

import os

import pytest
from conftest import _build_pfx, _generate_self_signed  # noqa: F401

from app.core.exceptions import ConflictError, NotFoundError, ValidationAppError
from app.services import storage
from app.services.certificate_service import (
    delete_certificate,
    export_bundle,
    get_certificate,
    import_certificate,
    issue_certificate,
    list_certificates,
    revoke_certificate,
)
from app.services.providers.base import IssueResult


def test_import_pem_certificate(db, sample_certificate):
    cert = import_certificate(
        db, cert_data=sample_certificate["cert_pem"], key_data=sample_certificate["key_pem"],
    )
    assert cert.domain == "example.com"
    assert "www.example.com" in cert.sans
    assert cert.fingerprint_sha256
    assert cert.issuer
    assert cert.key_type == "rsa"
    assert cert.key_size == 2048
    assert cert.imported is True
    assert cert.valid_until is not None
    # Private key content must NOT be in the DB
    assert "PRIVATE KEY" not in repr(cert.__dict__)
    assert cert.key_path and os.path.exists(cert.key_path)


def test_import_detects_duplicate(db, sample_certificate):
    import_certificate(db, cert_data=sample_certificate["cert_pem"],
                       key_data=sample_certificate["key_pem"])
    with pytest.raises(ConflictError):
        import_certificate(db, cert_data=sample_certificate["cert_pem"],
                           key_data=sample_certificate["key_pem"])


def test_import_key_mismatch_rejected(db, sample_certificate):
    _, other_key, _ = _generate_self_signed(["other.example.com"])
    with pytest.raises(ValidationAppError):
        import_certificate(db, cert_data=sample_certificate["cert_pem"], key_data=other_key)


def test_import_invalid_data_rejected(db):
    with pytest.raises(ValidationAppError):
        import_certificate(db, cert_data=b"this is not a certificate")


def test_import_pfx(db, sample_pfx):
    cert = import_certificate(db, pfx_data=sample_pfx, pfx_password="testpass")
    assert cert.domain == "pfx.example.com"
    assert cert.key_path  # key extracted from PFX and stored encrypted


def test_import_pfx_wrong_password(db, sample_pfx):
    with pytest.raises(ValidationAppError):
        import_certificate(db, pfx_data=sample_pfx, pfx_password="wrongpass")


def test_private_key_encrypted_at_rest(db, sample_certificate):
    cert = import_certificate(db, cert_data=sample_certificate["cert_pem"],
                              key_data=sample_certificate["key_pem"])
    raw = open(cert.key_path, encoding="utf-8").read()
    assert "BEGIN PRIVATE KEY" not in raw  # encrypted blob, not PEM
    store = storage.get_file_store()
    decrypted = store.read_private_key(cert.key_path)
    assert "BEGIN PRIVATE KEY" in decrypted


def test_export_pem_and_zip(db, sample_certificate):
    cert = import_certificate(db, cert_data=sample_certificate["cert_pem"],
                              key_data=sample_certificate["key_pem"])
    pem = export_bundle(db, cert.id, format="pem")
    assert pem.startswith(b"-----BEGIN CERTIFICATE-----")
    zip_data = export_bundle(db, cert.id, format="zip", include_key=True)
    import io
    import zipfile

    zf = zipfile.ZipFile(io.BytesIO(zip_data))
    assert "cert.pem" in zf.namelist()
    assert "privkey.pem" in zf.namelist()


def test_export_pfx(db, sample_certificate):
    cert = import_certificate(db, cert_data=sample_certificate["cert_pem"],
                              key_data=sample_certificate["key_pem"])
    pfx = export_bundle(db, cert.id, format="pfx", include_key=True, password="x")
    assert pfx.startswith(b"0")  # ASN.1 DER


def test_list_certificates_search_and_filter(db, sample_certificate):
    import_certificate(db, cert_data=sample_certificate["cert_pem"],
                       key_data=sample_certificate["key_pem"])
    rows, total, summary = list_certificates(db, search="example.com")
    assert total == 1
    rows, total, _ = list_certificates(db, filters={"status": "active"})
    assert total == 1
    rows, total, _ = list_certificates(db, filters={"status": "revoked"})
    assert total == 0


def test_issue_with_mocked_provider(db, admin_user, monkeypatch, tmp_path):
    """Issue through the service with a fake provider returning real files."""
    from app.services.providers.letsencrypt import LetsEncryptProvider

    cert_obj, cert_pem, key_pem = _generate_self_signed(["issued.example.com"])
    cert_file = tmp_path / "cert.pem"
    key_file = tmp_path / "key.pem"
    cert_file.write_bytes(cert_pem)
    key_file.write_bytes(key_pem)

    def fake_issue(self, request):
        return IssueResult(
            success=True, cert_path=str(cert_file), key_path=str(key_file),
            cert_name="issued.example.com", exit_code=0, stdout="issued", stderr="",
        )

    monkeypatch.setattr(LetsEncryptProvider, "issue", fake_issue)

    cert = issue_certificate(
        db, payload={
            "domains": ["issued.example.com"],
            "validation_method": "http-01",
            "key_type": "rsa2048",
            "environment": "production",
            "email": "ops@corp.com",
        },
        user=admin_user,
    )
    assert cert.status == "active"
    assert cert.fingerprint_sha256
    assert cert.cert_path and os.path.exists(cert.cert_path)
    assert cert.key_path and os.path.exists(cert.key_path)
    # executions recorded
    from app.models.job import JobExecution

    executions = db.query(JobExecution).filter(JobExecution.certificate_id == cert.id).all()
    assert executions and executions[0].status == "success"


def test_issue_failure_records_execution(db, admin_user, monkeypatch, tmp_path):
    from app.services.providers.letsencrypt import LetsEncryptProvider

    def fake_issue(self, request):
        return IssueResult(success=False, exit_code=1, stderr="DNS problem: NXDOMAIN")

    monkeypatch.setattr(LetsEncryptProvider, "issue", fake_issue)
    cert = issue_certificate(
        db, payload={"domains": ["bad.example.com"], "validation_method": "dns-01",
                     "key_type": "rsa2048", "email": "ops@corp.com"},
        user=admin_user,
    )
    assert cert.status == "failed"
    assert "NXDOMAIN" in (cert.renewal_error or "")


def test_revoke_flow(db, admin_user, monkeypatch, tmp_path):
    from app.services.providers.letsencrypt import LetsEncryptProvider

    cert_obj, cert_pem, key_pem = _generate_self_signed(["rv.example.com"])
    cert_file = tmp_path / "cert.pem"
    cert_file.write_bytes(cert_pem)

    def fake_issue(self, request):
        return IssueResult(success=True, cert_path=str(cert_file), cert_name="rv.example.com",
                           exit_code=0, stdout="", stderr="")

    def fake_revoke(self, cert_path, *, reason="unspecified"):
        from app.services.providers.base import RevokeResult

        return RevokeResult(success=True, stdout="revoked")

    monkeypatch.setattr(LetsEncryptProvider, "issue", fake_issue)
    monkeypatch.setattr(LetsEncryptProvider, "revoke", fake_revoke)

    cert = issue_certificate(db, payload={"domains": ["rv.example.com"],
                                          "validation_method": "http-01",
                                          "key_type": "rsa2048", "email": "ops@corp.com"},
                             user=admin_user)
    execution = revoke_certificate(db, cert.id, user=admin_user)
    assert execution.status == "success"
    assert cert.status == "revoked"


def test_delete_revoked_certificate(db, sample_certificate, admin_user):
    cert = import_certificate(db, cert_data=sample_certificate["cert_pem"],
                              key_data=sample_certificate["key_pem"])
    cert.status = "revoked"
    db.commit()
    cert_id = cert.id

    delete_certificate(db, cert_id, user=admin_user)

    with pytest.raises(NotFoundError):
        get_certificate(db, cert_id)


def test_delete_active_platform_managed_certificate_rejected(db, admin_user, monkeypatch, tmp_path):
    """Platform-managed (CertMgr-issued) certs keep the original guard —
    deleting one CertMgr's own renewal automation might still rely on stays
    blocked while active."""
    from app.services.providers.letsencrypt import LetsEncryptProvider

    cert_obj, cert_pem, key_pem = _generate_self_signed(["managed.example.com"])
    cert_file = tmp_path / "cert.pem"
    cert_file.write_bytes(cert_pem)

    def fake_issue(self, request):
        return IssueResult(success=True, cert_path=str(cert_file), cert_name="managed.example.com",
                           exit_code=0, stdout="", stderr="")

    monkeypatch.setattr(LetsEncryptProvider, "issue", fake_issue)
    cert = issue_certificate(
        db, payload={"domains": ["managed.example.com"], "validation_method": "http-01",
                     "key_type": "rsa2048", "email": "ops@corp.com"},
        user=admin_user,
    )
    assert cert.status == "active"
    assert cert.imported is False
    with pytest.raises(ValidationAppError):
        delete_certificate(db, cert.id)
    # Row must still exist — rejection shouldn't have deleted anything.
    assert get_certificate(db, cert.id) is not None


def test_delete_active_imported_certificate_allowed_and_ignored(db, sample_certificate, admin_user):
    """Imported/discovered certs are just tracking records — CertMgr was
    never their issuing/renewal authority, so they're deletable regardless
    of status, and get remembered in discovery_ignores so a future scan
    doesn't just re-import the same file (see discovery_service.py)."""
    from app.models.job import DiscoveryIgnore

    cert = import_certificate(db, cert_data=sample_certificate["cert_pem"],
                              key_data=sample_certificate["key_pem"])
    assert cert.status == "active"
    assert cert.imported is True
    fingerprint, domain = cert.fingerprint_sha256, cert.domain

    delete_certificate(db, cert.id, user=admin_user)

    with pytest.raises(NotFoundError):
        get_certificate(db, cert.id)

    ignore_row = db.query(DiscoveryIgnore).filter(DiscoveryIgnore.fingerprint_sha256 == fingerprint).first()
    assert ignore_row is not None
    assert ignore_row.domain == domain


def test_async_issuance_reconstructs_persisted_hook_config(db, admin_user, monkeypatch, tmp_path):
    """Regression test: async/queued issuance only ever gets a certificate_id
    (see app/tasks/certificates.py), not the original request payload, so
    hooks/webroot/standalone/email must round-trip through the Certificate
    row itself. Exercises the exact `_execute_issuance(db, cert, None, ...,
    payload=None)` call the Celery task makes."""
    from app.core.security import encrypt_secret
    from app.models.certificate import Hook
    from app.services.certificate_service import _execute_issuance
    from app.services.providers.letsencrypt import LetsEncryptProvider

    ssh_key_pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nZmFrZQ==\n-----END OPENSSH PRIVATE KEY-----\n"
    auth_hook = Hook(name="auth-hook", hook_type="auth", script_path="/opt/hooks/auth.pl",
                     execution_user="hookuser", working_directory="/opt/hooks", timeout_seconds=120,
                     ssh_private_key_encrypted=encrypt_secret(ssh_key_pem),
                     ssh_target_host="lets-encrypt01.example.com")
    cleanup_hook = Hook(name="cleanup-hook", hook_type="cleanup", script_path="/opt/hooks/cleanup.pl",
                        env_vars={"HOOK_TOKEN": "abc"})
    db.add_all([auth_hook, cleanup_hook])
    db.flush()

    cert = issue_certificate(
        db, payload={
            "domains": ["hooked.example.com"],
            "validation_method": "manual-http",
            "key_type": "rsa2048",
            "email": "ops@corp.com",
            "auth_hook_id": auth_hook.id,
            "cleanup_hook_id": cleanup_hook.id,
        },
        user=admin_user,
        execute=False,
    )

    # Row must carry everything needed to reconstruct the request later.
    assert cert.email == "ops@corp.com"
    assert cert.auth_hook_path == "/opt/hooks/auth.pl"
    assert cert.cleanup_hook_path == "/opt/hooks/cleanup.pl"
    assert cert.hook_env == {"HOOK_TOKEN": "abc"}
    assert cert.hook_execution_user == "hookuser"
    assert cert.hook_working_directory == "/opt/hooks"
    assert cert.hook_timeout == 120
    assert cert.ssh_target_host == "lets-encrypt01.example.com"
    assert cert.ssh_private_key_encrypted is not None
    assert cert.ssh_private_key_encrypted != ssh_key_pem  # stored encrypted

    _cert_obj, cert_pem, _key_pem = _generate_self_signed(["hooked.example.com"])
    cert_file = tmp_path / "cert.pem"
    cert_file.write_bytes(cert_pem)

    captured = {}

    def fake_issue(self, request):
        captured["request"] = request
        return IssueResult(success=True, cert_path=str(cert_file), cert_name="hooked.example.com",
                           exit_code=0, stdout="", stderr="")

    monkeypatch.setattr(LetsEncryptProvider, "issue", fake_issue)

    _execute_issuance(db, cert, None, "manual")

    request = captured["request"]
    assert request.email == "ops@corp.com"
    assert request.auth_hook == "/opt/hooks/auth.pl"
    assert request.cleanup_hook == "/opt/hooks/cleanup.pl"
    assert request.hook_env == {"HOOK_TOKEN": "abc"}
    assert request.hook_execution_user == "hookuser"
    assert request.hook_working_directory == "/opt/hooks"
    assert request.hook_timeout == 120
    assert request.ssh_target_host == "lets-encrypt01.example.com"
    assert request.ssh_private_key_encrypted == cert.ssh_private_key_encrypted
