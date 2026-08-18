"""Fetching an already-issued certificate from GoDaddy and importing it.

GoDaddy's own ?domain= filter was confirmed (against the live API) to not
reliably narrow results to the requested domain — these tests lock in that
_find_certificate_id() re-checks every candidate's actual
commonName/subjectAlternativeNames itself rather than trusting the API."""

from __future__ import annotations

import pytest
from conftest import _generate_self_signed

from app.core.exceptions import NotFoundError, ValidationAppError
from app.models.certificate import Certificate
from app.services.godaddy_service import fetch_certificate_from_godaddy
from app.services.settings_service import set_setting


def _configure_credentials(db):
    set_setting(db, "godaddy.api_key", "test-key")
    set_setting(db, "godaddy.api_secret", "test-secret")


def _fake_bundle(domain: str) -> dict:
    _obj, cert_pem, _key_pem = _generate_self_signed([domain])
    return {
        "serialNumber": "123",
        "certificateThumbprint": "abc",
        "pems": {"certificate": cert_pem.decode(), "intermediate": None, "root": None, "cross": None},
    }


def test_fetch_requires_exactly_one_of_domain_or_certificate_id(db):
    _configure_credentials(db)
    with pytest.raises(ValidationAppError):
        fetch_certificate_from_godaddy(db)
    with pytest.raises(ValidationAppError):
        fetch_certificate_from_godaddy(db, domain="a.example.com", certificate_id="123")


def test_fetch_raises_without_configured_credentials(db):
    with pytest.raises(ValidationAppError):
        fetch_certificate_from_godaddy(db, certificate_id="123")


def test_fetch_by_certificate_id_imports_cert(db, monkeypatch, admin_user):
    _configure_credentials(db)
    from app.services.godaddy_client import GoDaddyClient

    monkeypatch.setattr(GoDaddyClient, "download_certificate",
                        lambda self, cert_id: _fake_bundle("godaddy-direct.example.com"))

    result = fetch_certificate_from_godaddy(db, certificate_id="gd-abc123", user=admin_user)

    cert = db.query(Certificate).filter(Certificate.id == result["certificate_id"]).first()
    assert cert is not None
    assert cert.domain == "godaddy-direct.example.com"
    assert cert.provider_name == "godaddy"
    assert cert.imported is True
    assert result["godaddy_certificate_id"] == "gd-abc123"


def test_fetch_by_domain_filters_unreliable_api_results_client_side(db, monkeypatch):
    """Simulates the real, confirmed quirk: the list endpoint returns
    certificates unrelated to the requested domain alongside the real
    match."""
    _configure_credentials(db)
    from app.services.godaddy_client import GoDaddyClient

    candidates = [
        {"certificateId": "unrelated-1", "commonName": "other.example.com",
         "subjectAlternativeNames": [], "certificateStatus": "ISSUED", "validEnd": "2030-01-01T00:00:00.000Z"},
        {"certificateId": "the-real-one", "commonName": "target.example.com",
         "subjectAlternativeNames": [{"subjectAlternativeName": "www.target.example.com"}],
         "certificateStatus": "ISSUED", "validEnd": "2030-06-01T00:00:00.000Z"},
        {"certificateId": "unrelated-2", "commonName": "hybrid.corp.example.com",
         "subjectAlternativeNames": [{"subjectAlternativeName": "autodiscover.corp.example.com"}],
         "certificateStatus": "ISSUED", "validEnd": "2030-01-01T00:00:00.000Z"},
    ]
    monkeypatch.setattr(GoDaddyClient, "list_certificates", lambda self, domain=None: candidates)

    downloaded_ids = []

    def fake_download(self, cert_id):
        downloaded_ids.append(cert_id)
        return _fake_bundle("target.example.com")

    monkeypatch.setattr(GoDaddyClient, "download_certificate", fake_download)

    result = fetch_certificate_from_godaddy(db, domain="target.example.com")

    assert downloaded_ids == ["the-real-one"]
    assert result["godaddy_certificate_id"] == "the-real-one"


def test_fetch_by_domain_matches_via_san_not_just_common_name(db, monkeypatch):
    _configure_credentials(db)
    from app.services.godaddy_client import GoDaddyClient

    candidates = [
        {"certificateId": "san-match", "commonName": "primary.example.com",
         "subjectAlternativeNames": [{"subjectAlternativeName": "san-only.example.com"}],
         "certificateStatus": "ISSUED", "validEnd": "2030-01-01T00:00:00.000Z"},
    ]
    monkeypatch.setattr(GoDaddyClient, "list_certificates", lambda self, domain=None: candidates)
    monkeypatch.setattr(GoDaddyClient, "download_certificate",
                        lambda self, cert_id: _fake_bundle("san-only.example.com"))

    result = fetch_certificate_from_godaddy(db, domain="san-only.example.com")
    assert result["godaddy_certificate_id"] == "san-match"


def test_fetch_by_domain_prefers_live_over_revoked(db, monkeypatch):
    _configure_credentials(db)
    from app.services.godaddy_client import GoDaddyClient

    candidates = [
        {"certificateId": "old-revoked", "commonName": "renewed.example.com",
         "subjectAlternativeNames": [], "certificateStatus": "REVOKED", "revokedAt": "2020-01-01T00:00:00.000Z",
         "validEnd": "2030-12-01T00:00:00.000Z"},  # later validEnd but revoked
        {"certificateId": "current-live", "commonName": "renewed.example.com",
         "subjectAlternativeNames": [], "certificateStatus": "ISSUED", "revokedAt": None,
         "validEnd": "2025-01-01T00:00:00.000Z"},
    ]
    monkeypatch.setattr(GoDaddyClient, "list_certificates", lambda self, domain=None: candidates)
    monkeypatch.setattr(GoDaddyClient, "download_certificate",
                        lambda self, cert_id: _fake_bundle("renewed.example.com"))

    result = fetch_certificate_from_godaddy(db, domain="renewed.example.com")
    assert result["godaddy_certificate_id"] == "current-live"


def test_fetch_by_domain_raises_not_found_when_nothing_actually_matches(db, monkeypatch):
    _configure_credentials(db)
    from app.services.godaddy_client import GoDaddyClient

    candidates = [
        {"certificateId": "unrelated", "commonName": "other.example.com",
         "subjectAlternativeNames": [], "certificateStatus": "ISSUED", "validEnd": "2030-01-01T00:00:00.000Z"},
    ]
    monkeypatch.setattr(GoDaddyClient, "list_certificates", lambda self, domain=None: candidates)

    with pytest.raises(NotFoundError):
        fetch_certificate_from_godaddy(db, domain="not-in-the-list.example.com")


def test_fetch_combines_intermediate_and_cross_into_chain(db, monkeypatch):
    _configure_credentials(db)
    from app.services.godaddy_client import GoDaddyClient

    _obj, cert_pem, _key = _generate_self_signed(["chain-test.example.com"])

    def fake_download(self, cert_id):
        return {
            "pems": {
                "certificate": cert_pem.decode(),
                "intermediate": "-----BEGIN CERTIFICATE-----\nINTERMEDIATE\n-----END CERTIFICATE-----\n",
                "cross": "-----BEGIN CERTIFICATE-----\nCROSS\n-----END CERTIFICATE-----\n",
                "root": "-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----\n",
            }
        }

    monkeypatch.setattr(GoDaddyClient, "download_certificate", fake_download)

    result = fetch_certificate_from_godaddy(db, certificate_id="chain-cert")
    cert = db.query(Certificate).filter(Certificate.id == result["certificate_id"]).first()
    assert cert.chain_path is not None
    chain_content = open(cert.chain_path).read()
    assert "INTERMEDIATE" in chain_content
    assert "CROSS" in chain_content
    assert "ROOT" not in chain_content  # root is deliberately excluded from the served chain


def test_import_godaddy_api_requires_permission(client, role_headers_factory):
    headers = role_headers_factory("ro_godaddy", "read_only")
    resp = client.post("/api/v1/certificates/import/godaddy", headers=headers,
                       json={"certificate_id": "abc123"})
    assert resp.status_code == 403


def test_import_godaddy_api_success(client, admin_headers, monkeypatch):
    import app.services.godaddy_service as godaddy_service_module

    monkeypatch.setattr(
        godaddy_service_module, "fetch_certificate_from_godaddy",
        lambda db, **kwargs: {"certificate_id": 1, "domain": "api-test.example.com",
                              "godaddy_certificate_id": kwargs.get("certificate_id")},
    )

    resp = client.post("/api/v1/certificates/import/godaddy", headers=admin_headers,
                       json={"certificate_id": "gd-999"})
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"certificate_id": 1, "domain": "api-test.example.com",
                           "godaddy_certificate_id": "gd-999"}
