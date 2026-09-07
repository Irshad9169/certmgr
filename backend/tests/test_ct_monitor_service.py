"""run_ct_monitor() with crt.sh calls monkeypatched — no live network
dependency (matches the reference prompt's own rule: don't depend on live
CT infrastructure for tests). A real self-signed cert (from the existing
_generate_self_signed() conftest helper) stands in for what crt.sh's raw
PEM endpoint would return."""

from __future__ import annotations

from conftest import _generate_self_signed  # noqa: F401

from app.models.certificate import Certificate
from app.models.finding import CTFinding
from app.models.job import CTObservation
from app.services import ct_monitor
from app.services.discovery_service import run_ct_monitor


def _crtsh_entry(crt_sh_id: int, name: str) -> dict:
    return {"id": crt_sh_id, "name_value": name}


def test_benign_new_certificate_creates_informational_finding(db, monkeypatch):
    _, cert_pem, _ = _generate_self_signed(["example.com"])

    monkeypatch.setattr(ct_monitor, "fetch_crtsh_entries",
                        lambda domain, *, limit, timeout=15.0: [_crtsh_entry(1001, "example.com")])
    monkeypatch.setattr(ct_monitor, "fetch_crtsh_certificate_pem",
                        lambda crt_sh_id, *, timeout=15.0: cert_pem)

    run = run_ct_monitor(db, domains=["example.com"])

    assert run.status == "completed"
    assert run.scan_type == "ct_log"
    assert run.scan_domains == ["example.com"]
    assert run.found_count == 1
    assert run.imported_count == 1

    cert = db.query(Certificate).filter(Certificate.provider_name == "ct-log").one()
    assert cert.managed_by_platform is False
    assert cert.key_path is None

    obs = db.query(CTObservation).filter(CTObservation.crt_sh_id == 1001).one()
    assert obs.certificate_id == cert.id

    finding = db.query(CTFinding).filter(CTFinding.certificate_id == cert.id).one()
    assert finding.severity == "informational"
    assert finding.status == "open"
    assert any(d["code"] == "NEW_CERTIFICATE" for d in finding.detections)


def test_unknown_ca_and_sensitive_hostname_raises_severity(db, monkeypatch):
    _, cert_pem, _ = _generate_self_signed(["vpn.example.com"])

    monkeypatch.setattr(ct_monitor, "fetch_crtsh_entries",
                        lambda domain, *, limit, timeout=15.0: [_crtsh_entry(2002, "vpn.example.com")])
    monkeypatch.setattr(ct_monitor, "fetch_crtsh_certificate_pem",
                        lambda crt_sh_id, *, timeout=15.0: cert_pem)

    run_ct_monitor(
        db, domains=["example.com"],
        expected_issuers=["DigiCert"],  # self-signed cert's issuer won't match -> UNKNOWN_CA
        sensitive_keywords=["vpn"],
        staging_keywords=[],
    )

    cert = db.query(Certificate).filter(Certificate.provider_name == "ct-log").one()
    finding = db.query(CTFinding).filter(CTFinding.certificate_id == cert.id).one()
    codes = {d["code"] for d in finding.detections}
    assert {"NEW_CERTIFICATE", "UNKNOWN_CA", "SENSITIVE_HOSTNAME"} <= codes
    assert finding.risk_score == 10 + 25 + 20
    assert finding.severity == "medium"


def test_rescan_of_known_ct_entry_does_not_refetch_or_duplicate(db, monkeypatch):
    _, cert_pem, _ = _generate_self_signed(["example.com"])
    fetch_pem_calls: list[int] = []

    def _fetch_pem(crt_sh_id: int, *, timeout: float = 15.0):
        fetch_pem_calls.append(crt_sh_id)
        return cert_pem

    monkeypatch.setattr(ct_monitor, "fetch_crtsh_entries",
                        lambda domain, *, limit, timeout=15.0: [_crtsh_entry(3003, "example.com")])
    monkeypatch.setattr(ct_monitor, "fetch_crtsh_certificate_pem", _fetch_pem)

    run_ct_monitor(db, domains=["example.com"])
    assert len(fetch_pem_calls) == 1

    run2 = run_ct_monitor(db, domains=["example.com"])
    assert len(fetch_pem_calls) == 1  # no re-fetch for an already-known crt_sh_id
    assert run2.imported_count == 0
    assert run2.found_count == 1
    assert "already known and unchanged" in run2.log

    assert db.query(Certificate).filter(Certificate.provider_name == "ct-log").count() == 1
    assert db.query(CTObservation).filter(CTObservation.crt_sh_id == 3003).count() == 1
    assert db.query(CTFinding).count() == 1


def test_deleted_ct_certificate_is_not_recreated_by_next_scan(db, monkeypatch):
    from app.models.job import DiscoveryIgnore
    from app.services.certificate_service import delete_certificate

    _, cert_pem, _ = _generate_self_signed(["example.com"])
    monkeypatch.setattr(ct_monitor, "fetch_crtsh_entries",
                        lambda domain, *, limit, timeout=15.0: [_crtsh_entry(4004, "example.com")])
    monkeypatch.setattr(ct_monitor, "fetch_crtsh_certificate_pem",
                        lambda crt_sh_id, *, timeout=15.0: cert_pem)

    run_ct_monitor(db, domains=["example.com"])
    cert = db.query(Certificate).filter(Certificate.provider_name == "ct-log").one()
    fingerprint = cert.fingerprint_sha256

    delete_certificate(db, cert.id)
    assert db.query(DiscoveryIgnore).filter(DiscoveryIgnore.fingerprint_sha256 == fingerprint).count() == 1

    # A fresh crt.sh id for the SAME certificate (e.g. it also got submitted
    # to a second CT log) — must still respect the ignore list.
    monkeypatch.setattr(ct_monitor, "fetch_crtsh_entries",
                        lambda domain, *, limit, timeout=15.0: [_crtsh_entry(4005, "example.com")])
    run2 = run_ct_monitor(db, domains=["example.com"])

    assert run2.imported_count == 0
    assert db.query(Certificate).filter(Certificate.fingerprint_sha256 == fingerprint).count() == 0
    assert "SKIP ignored" in run2.log


def test_duplicate_crt_sh_ids_for_the_same_certificate_reuse_the_row_without_refetch(db, monkeypatch):
    """crt.sh commonly logs one certificate to several CT logs, each getting
    its own id (confirmed live against crt.sh: a single-domain query returned
    paired identical serial numbers under different ids). The second id for
    the same certificate must be matched via the cheap serial_number/issuer
    fields in its JSON row, not a second raw-PEM-fetch round-trip."""
    from app.services.x509_utils import parse_certificate

    _, cert_pem, _ = _generate_self_signed(["example.com"])
    _, meta = parse_certificate(cert_pem)
    fetch_pem_calls: list[int] = []

    def _fetch_pem(crt_sh_id: int, *, timeout: float = 15.0):
        fetch_pem_calls.append(crt_sh_id)
        return cert_pem

    entries = [
        {"id": 5005, "name_value": "example.com",
         "serial_number": meta.serial_number, "issuer_name": meta.issuer},
        {"id": 5006, "name_value": "example.com",
         "serial_number": meta.serial_number, "issuer_name": meta.issuer},
    ]
    monkeypatch.setattr(ct_monitor, "fetch_crtsh_entries",
                        lambda domain, *, limit, timeout=15.0: entries)
    monkeypatch.setattr(ct_monitor, "fetch_crtsh_certificate_pem", _fetch_pem)

    run = run_ct_monitor(db, domains=["example.com"])

    assert len(fetch_pem_calls) == 1
    assert db.query(Certificate).filter(Certificate.provider_name == "ct-log").count() == 1
    assert db.query(CTObservation).filter(CTObservation.crt_sh_id.in_([5005, 5006])).count() == 2
    assert run.imported_count == 1
    assert run.found_count == 2


def test_crtsh_unavailable_does_not_fail_the_scan(db, monkeypatch):
    monkeypatch.setattr(ct_monitor, "fetch_crtsh_entries", lambda domain, *, limit, timeout=15.0: [])

    run = run_ct_monitor(db, domains=["example.com"])
    assert run.status == "completed"
    assert run.found_count == 0
