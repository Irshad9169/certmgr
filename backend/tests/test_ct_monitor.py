"""Pure-function tests for ct_monitor.py — no DB, no network."""

from __future__ import annotations

from app.services.ct_monitor import (
    classify_domain_match,
    risk_score_for,
    risk_severity,
    run_detections,
)


def test_classify_exact_match():
    assert classify_domain_match("example.com", ["example.com"]) == "exact"


def test_classify_subdomain_match():
    assert classify_domain_match("vpn.example.com", ["example.com"]) == "subdomain"


def test_classify_wildcard_match():
    assert classify_domain_match("*.example.com", ["example.com"]) == "wildcard"


def test_classify_wildcard_subdomain_match():
    # *.vpn.example.com is a wildcard whose base (vpn.example.com) is itself
    # a subdomain of the monitored root, not an exact match to it.
    assert classify_domain_match("*.vpn.example.com", ["example.com"]) == "wildcard"


def test_classify_unrelated():
    assert classify_domain_match("othercompany.com", ["example.com"]) == "unrelated"


def test_classify_does_not_match_substring_lookalike():
    # examp1e.com is NOT a subdomain/exact match of example.com — confirms
    # why lookalike detection genuinely doesn't fit this classifier (or the
    # crt.sh substring-search ingestion method at all).
    assert classify_domain_match("examp1e.com", ["example.com"]) == "unrelated"


def test_classify_case_and_trailing_dot_insensitive():
    assert classify_domain_match("VPN.EXAMPLE.COM.", ["example.com"]) == "subdomain"


_LETS_ENCRYPT = "CN=R3, O=Let's Encrypt"


def test_new_certificate_detection_fires():
    detections = run_detections(
        _LETS_ENCRYPT, "example.com", is_new=True,
        expected_issuers=[], sensitive_keywords=[], staging_keywords=[],
    )
    codes = [d["code"] for d in detections]
    assert "NEW_CERTIFICATE" in codes


def test_rescan_of_known_cert_does_not_refire_new_certificate():
    detections = run_detections(
        _LETS_ENCRYPT, "example.com", is_new=False,
        expected_issuers=[], sensitive_keywords=[], staging_keywords=[],
    )
    codes = [d["code"] for d in detections]
    assert "NEW_CERTIFICATE" not in codes


def test_unknown_ca_detection_only_fires_when_expected_issuers_configured():
    # Empty expected_issuers means "nothing configured to compare against",
    # not "flag everything" — must not fire.
    detections = run_detections(
        "CN=Some Random CA", "example.com", is_new=False,
        expected_issuers=[], sensitive_keywords=[], staging_keywords=[],
    )
    assert "UNKNOWN_CA" not in [d["code"] for d in detections]


def test_unknown_ca_detection_fires_for_unexpected_issuer():
    detections = run_detections(
        "CN=Some Random CA", "example.com", is_new=False,
        expected_issuers=["Let's Encrypt", "DigiCert"], sensitive_keywords=[], staging_keywords=[],
    )
    assert "UNKNOWN_CA" in [d["code"] for d in detections]


def test_unknown_ca_detection_does_not_fire_for_expected_issuer():
    detections = run_detections(
        _LETS_ENCRYPT, "example.com", is_new=False,
        expected_issuers=["Let's Encrypt"], sensitive_keywords=[], staging_keywords=[],
    )
    assert "UNKNOWN_CA" not in [d["code"] for d in detections]


def test_sensitive_hostname_detection():
    detections = run_detections(
        _LETS_ENCRYPT, "vpn.example.com", is_new=False,
        expected_issuers=[], sensitive_keywords=["vpn", "admin"], staging_keywords=[],
    )
    assert "SENSITIVE_HOSTNAME" in [d["code"] for d in detections]


def test_staging_hostname_detection():
    detections = run_detections(
        _LETS_ENCRYPT, "staging-api.example.com", is_new=False,
        expected_issuers=[], sensitive_keywords=[], staging_keywords=["staging", "dev"],
    )
    assert "STAGING_HOSTNAME" in [d["code"] for d in detections]


def test_no_detections_for_benign_known_cert():
    detections = run_detections(
        _LETS_ENCRYPT, "api.example.com", is_new=False,
        expected_issuers=["Let's Encrypt"], sensitive_keywords=["vpn"], staging_keywords=["staging"],
    )
    assert detections == []


def test_risk_score_caps_at_100():
    detections = [{"code": "A", "weight": 60, "reason": "x"}, {"code": "B", "weight": 60, "reason": "y"}]
    assert risk_score_for(detections) == 100


def test_risk_severity_buckets():
    assert risk_severity(0) == "informational"
    assert risk_severity(24) == "informational"
    assert risk_severity(25) == "low"
    assert risk_severity(49) == "low"
    assert risk_severity(50) == "medium"
    assert risk_severity(74) == "medium"
    assert risk_severity(75) == "high"
    assert risk_severity(89) == "high"
    assert risk_severity(90) == "critical"
    assert risk_severity(100) == "critical"
