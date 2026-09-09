"""Pure-function tests for certificate_usage_service.py — no DB, no network."""

from __future__ import annotations

from app.services.certificate_usage_service import (
    _candidate_hostnames_from_inventory,
    _is_ip_literal,
    _normalize_fingerprint,
    _parse_manual_hostnames,
    _wildcard_suffix,
)


def test_normalize_fingerprint_strips_colons_and_case():
    assert _normalize_fingerprint("8A:31:92:AA") == _normalize_fingerprint("8a3192aa")


def test_normalize_fingerprint_handles_none():
    assert _normalize_fingerprint(None) == ""


def test_wildcard_suffix_strips_prefix():
    assert _wildcard_suffix("*.example.com") == "example.com"


def test_wildcard_suffix_passthrough_for_non_wildcard():
    assert _wildcard_suffix("example.com") == "example.com"


def test_is_ip_literal():
    assert _is_ip_literal("10.0.0.5") is True
    assert _is_ip_literal("api.example.com") is False


def test_parse_manual_hostnames_plain_lines():
    result = _parse_manual_hostnames(["api.example.com", "portal.example.com"])
    assert result == [("api.example.com", None), ("portal.example.com", None)]


def test_parse_manual_hostnames_with_explicit_port():
    result = _parse_manual_hostnames(["api.example.com:8443"])
    assert result == [("api.example.com", 8443)]


def test_parse_manual_hostnames_skips_blank_lines():
    result = _parse_manual_hostnames(["api.example.com", "", "   ", "portal.example.com"])
    assert len(result) == 2


def test_parse_manual_hostnames_skips_invalid_entries():
    result = _parse_manual_hostnames(["not a hostname!!", "api.example.com"])
    assert result == [("api.example.com", None)]


def test_parse_manual_hostnames_accepts_ip_literal():
    result = _parse_manual_hostnames(["10.20.1.15"])
    assert result == [("10.20.1.15", None)]


def test_parse_manual_hostnames_deduplication_is_caller_responsibility():
    # start_scan() dedups via a dict keyed by hostname — this function itself
    # just parses, so duplicate lines pass through unchanged here.
    result = _parse_manual_hostnames(["api.example.com", "api.example.com"])
    assert len(result) == 2


def test_candidate_hostnames_from_inventory_filters_by_suffix(db):
    from app.models.certificate import Certificate, CertificateDomain
    from app.models.enums import CertificateType, ValidationMethod
    from app.models.server import Server

    db.add(Server(hostname="api.example.com", environment="production"))
    db.add(Server(hostname="unrelated.other.com", environment="production"))
    cert = Certificate(domain="portal.example.com", cert_name="portal.example.com",
                       sans=["portal.example.com"], cert_type=CertificateType.SINGLE.value,
                       validation_method=ValidationMethod.HTTP_01.value)
    db.add(cert)
    db.flush()
    db.add(CertificateDomain(certificate_id=cert.id, domain="portal.example.com", is_primary=True))
    # A wildcard domain entry must never itself become a candidate hostname.
    wildcard_cert = Certificate(domain="*.example.com", cert_name="wildcard.example.com",
                                sans=["*.example.com"], cert_type=CertificateType.WILDCARD.value,
                                validation_method=ValidationMethod.HTTP_01.value, is_wildcard=True)
    db.add(wildcard_cert)
    db.flush()
    db.add(CertificateDomain(certificate_id=wildcard_cert.id, domain="*.example.com", is_primary=True))
    db.commit()

    candidates = _candidate_hostnames_from_inventory(db, "example.com")
    assert candidates == {"api.example.com", "portal.example.com"}
