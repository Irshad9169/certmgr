"""Report generation tests: CSV/XLSX/PDF/JSON."""

from __future__ import annotations

import json

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
