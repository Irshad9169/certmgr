"""Report generation tests: CSV/XLSX/PDF/JSON."""

from __future__ import annotations

import json
from datetime import datetime, timedelta

from conftest import _generate_self_signed

from app.services.certificate_service import import_certificate
from app.services.report_service import generate_report


def test_inventory_csv(db):
    cert, cert_pem, key_pem = _generate_self_signed(["report.example.com"])
    import_certificate(db, cert_data=cert_pem, key_data=key_pem)
    data, filename = generate_report(db, "inventory", "csv")
    assert filename == "inventory.csv"
    text = data.decode("utf-8-sig")
    assert "domain" in text
    assert "report.example.com" in text


def test_inventory_xlsx(db):
    cert, cert_pem, key_pem = _generate_self_signed(["report2.example.com"])
    import_certificate(db, cert_data=cert_pem, key_data=key_pem)
    data, filename = generate_report(db, "inventory", "xlsx")
    assert filename == "inventory.xlsx"
    assert data[:2] == b"PK"  # zip container


def test_inventory_json(db):
    data, filename = generate_report(db, "inventory", "json")
    parsed = json.loads(data)
    assert parsed["title"] == "Certificate Inventory"


def test_inventory_pdf(db):
    data, filename = generate_report(db, "inventory", "pdf")
    assert filename == "inventory.pdf"
    assert data[:5] == b"%PDF-"


def test_expiry_report(db):
    cert, cert_pem, key_pem = _generate_self_signed(["exp.example.com"], validity_days=20)
    import_certificate(db, cert_data=cert_pem, key_data=key_pem)
    data, filename = generate_report(db, "expiry", "json")
    parsed = json.loads(data)
    assert any(r["domain"] == "exp.example.com" for r in parsed["data"])


def test_unknown_report_type_rejected(db):
    import pytest

    from app.services.report_service import generate_report

    with pytest.raises(ValueError):
        generate_report(db, "does-not-exist", "csv")


def test_inventory_pdf_handles_long_issuer_without_error(db):
    """Regression test: the PDF table had no explicit column widths and
    rendered raw (non-wrapping) strings, so a full issuer DN — or the
    inventory report's 17 columns in general — overflowed the page rather
    than wrapping. A long, unbroken issuer string must still produce a
    valid, non-trivial PDF."""
    cert, cert_pem, key_pem = _generate_self_signed(["longissuer.example.com"])
    row = import_certificate(db, cert_data=cert_pem, key_data=key_pem)
    row.issuer = ("countryName=US, organizationName=Let's Encrypt, "
                 "commonName=(STAGING) SomeVeryLongCertificateAuthorityNameThatWontFitInOneLine YR1")
    db.commit()

    data, filename = generate_report(db, "inventory", "pdf")
    assert filename == "inventory.pdf"
    assert data[:5] == b"%PDF-"
    assert len(data) > 500  # not a truncated/empty document


def test_inventory_pdf_uses_trimmed_print_friendly_columns():
    """Regression test: PDF-specific column trimming for the 17-column
    inventory report — see pdf_headers in generate_report(). Directly
    exercises _to_pdf() with the full header set to confirm it still
    succeeds (would previously overflow badly at 17 columns)."""
    from app.services.report_service import _to_pdf

    headers = ["id", "domain", "sans", "issuer", "environment", "status", "key_type",
               "key_size", "signature_algorithm", "created_at", "expires_at",
               "days_remaining", "auto_renew", "renewal_status", "provider", "imported", "tags"]
    data = [{h: f"value-{h}" for h in headers}]
    pdf_bytes = _to_pdf("Certificate Inventory", headers, data)
    assert pdf_bytes[:5] == b"%PDF-"


def test_audit_report_date_range_filters(db):
    from app.models.audit import AuditLog

    old = AuditLog(username="alice", action="certificate.issue", result="success",
                   created_at=datetime(2020, 1, 1))
    recent = AuditLog(username="bob", action="certificate.revoke", result="success",
                      created_at=datetime(2026, 6, 15))
    db.add_all([old, recent])
    db.commit()

    data, _ = generate_report(db, "audit", "json",
                              date_from=datetime(2026, 1, 1), date_to=datetime(2026, 12, 31))
    parsed = json.loads(data)
    usernames = {r["username"] for r in parsed["data"]}
    assert "bob" in usernames
    assert "alice" not in usernames
    assert "2026-01-01" in parsed["title"]


def test_audit_report_date_to_is_inclusive_of_whole_day(db):
    """generate_report() itself just passes date_from/date_to straight to
    query_audit() — the end-of-day bump for a bare date happens one layer
    up, in the API endpoint (app/api/v1/extras.py), since that's where a
    plain YYYY-MM-DD string first arrives. This test locks in that
    query_audit()'s own date_to comparison is a plain <=, so passing an
    already-end-of-day datetime includes everything on that day."""
    from app.models.audit import AuditLog

    same_day_late = AuditLog(username="carol", action="certificate.issue", result="success",
                             created_at=datetime(2026, 6, 15, 23, 59, 0))
    db.add(same_day_late)
    db.commit()

    end_of_day = datetime(2026, 6, 15) + timedelta(days=1) - timedelta(microseconds=1)
    data, _ = generate_report(db, "audit", "json",
                              date_from=datetime(2026, 6, 15), date_to=end_of_day)
    parsed = json.loads(data)
    assert any(r["username"] == "carol" for r in parsed["data"])


def test_audit_report_api_bumps_bare_date_to_end_of_day(client, admin_headers, db):
    """End-to-end through the real endpoint: a plain YYYY-MM-DD `date_to`
    (exactly what the Reports page's <input type="date"> sends) must still
    include entries later that same day, not just up to midnight."""
    from app.models.audit import AuditLog

    same_day_late = AuditLog(username="dave", action="certificate.issue", result="success",
                             created_at=datetime(2026, 6, 15, 23, 59, 0))
    db.add(same_day_late)
    db.commit()

    resp = client.get("/api/v1/reports/audit.json",
                      params={"date_from": "2026-06-15", "date_to": "2026-06-15"},
                      headers=admin_headers)
    assert resp.status_code == 200, resp.text
    usernames = {r["username"] for r in resp.json()["data"]}
    assert "dave" in usernames
