"""certificate_usage_service.start_scan()/probe_hostname() against real local
TLS servers — reuses the same self-contained listener harness proven in
test_network_scan_service.py (binds 127.0.0.1:0, no external services)."""

from __future__ import annotations

import socket
import threading

import pytest
from conftest import _generate_self_signed  # noqa: F401
from test_network_scan_service import _LocalTLSServer  # noqa: F401

from app.core.exceptions import ValidationAppError
from app.models.certificate import Certificate
from app.models.certificate_usage import CertificateUsageResult
from app.models.enums import CertificateType, ValidationMethod
from app.services.certificate_usage_service import probe_hostname, start_scan
from app.services.network_scanner import build_scan_context
from app.services.x509_utils import parse_certificate


def _make_wildcard_cert(db, domain: str = "*.example.com", fingerprint: str | None = None) -> Certificate:
    from app.core.timeutils import utcnow

    cert = Certificate(
        domain=domain, cert_name="wildcard-example", sans=[domain],
        cert_type=CertificateType.WILDCARD.value, validation_method=ValidationMethod.HTTP_01.value,
        is_wildcard=True, fingerprint_sha256=fingerprint, last_checked_at=utcnow(),
    )
    db.add(cert)
    db.commit()
    return cert


@pytest.fixture
def tls_server(tmp_path):
    _, cert_pem, key_pem = _generate_self_signed(["api.example.com"])
    server = _LocalTLSServer(tmp_path, cert_pem, key_pem)
    yield server, cert_pem
    server.stop()


class _RawSocketServer:
    """A bare TCP listener for simulating TLS_FAILED / TIMEOUT — accepts a
    connection and either sends non-TLS garbage (TLS_FAILED) or just holds
    it open without responding (TIMEOUT)."""

    def __init__(self, *, respond_garbage: bool):
        self.respond_garbage = respond_garbage
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def _accept_loop(self) -> None:
        self.sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            if self.respond_garbage:
                try:
                    conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                except OSError:
                    pass
                conn.close()
            # else: hold the connection open, never respond — simulates a hang

    def stop(self) -> None:
        self._stop.set()
        self.sock.close()
        self._thread.join(timeout=2)


def test_probe_confirmed_on_exact_fingerprint_match(tls_server):
    server, cert_pem = tls_server
    _, meta = parse_certificate(cert_pem)
    ctx = build_scan_context()

    result = probe_hostname("127.0.0.1", server.port, meta.fingerprint_sha256, timeout=2, ctx=ctx)

    assert result.status == "confirmed"
    assert result.presented_fingerprint == meta.fingerprint_sha256


def test_probe_different_certificate_on_mismatch(tls_server):
    server, _ = tls_server
    ctx = build_scan_context()

    result = probe_hostname("127.0.0.1", server.port, "00" * 32, timeout=2, ctx=ctx)

    assert result.status == "different_certificate"


def test_probe_confirmed_ignores_colon_and_case_differences(tls_server):
    server, cert_pem = tls_server
    _, meta = parse_certificate(cert_pem)
    ctx = build_scan_context()
    lowercase_no_colons = meta.fingerprint_sha256.replace(":", "").lower()

    result = probe_hostname("127.0.0.1", server.port, lowercase_no_colons, timeout=2, ctx=ctx)

    assert result.status == "confirmed"


def test_probe_reports_failure_status_for_closed_port():
    # Whether a closed local port yields an immediate refusal or a timeout
    # is a platform/firewall detail outside this code's control (confirmed:
    # differs between environments even for the same "nothing is listening
    # here" scenario — network_scanner.py's own equivalent test avoids
    # asserting a specific failure category for the same reason). What
    # matters is that a real failure is reported, not silently misread as
    # CONFIRMED/DIFFERENT_CERTIFICATE.
    probe_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe_sock.bind(("127.0.0.1", 0))
    closed_port = probe_sock.getsockname()[1]
    probe_sock.close()

    ctx = build_scan_context()
    result = probe_hostname("127.0.0.1", closed_port, "irrelevant", timeout=2, ctx=ctx)
    assert result.status in ("unreachable", "timeout")
    assert result.error_code in ("connect_failed", "connect_timeout")


def test_probe_bounds_a_hanging_dns_resolver(monkeypatch):
    """socket.gethostbyname() has no timeout of its own — a hung resolver
    must not block the probe past its configured timeout (the exact failure
    mode this project hit for real with crt.sh DNS lookups elsewhere)."""
    import time

    from app.services import certificate_usage_service as svc

    def _hang(hostname):
        time.sleep(5)
        return "127.0.0.1"

    monkeypatch.setattr(svc.socket, "gethostbyname", _hang)
    ctx = build_scan_context()

    start = time.monotonic()
    result = probe_hostname("slow-dns.example.com", 443, "irrelevant", timeout=0.3, ctx=ctx)
    elapsed = time.monotonic() - start

    assert result.status == "timeout"
    assert result.error_code == "dns_timeout"
    assert elapsed < 2  # bounded by the probe's own timeout, not the 5s hang


def test_probe_dns_failed_on_unresolvable_hostname():
    ctx = build_scan_context()
    result = probe_hostname("this-host-does-not-exist.invalid", 443, "irrelevant", timeout=1, ctx=ctx)
    assert result.status == "dns_failed"
    assert result.error_code == "dns_failed"


def test_probe_tls_failed_on_non_tls_response():
    server = _RawSocketServer(respond_garbage=True)
    try:
        ctx = build_scan_context()
        result = probe_hostname("127.0.0.1", server.port, "irrelevant", timeout=2, ctx=ctx)
        assert result.status in ("tls_failed", "unreachable")  # peer may close before/after the record header
    finally:
        server.stop()


def test_probe_timeout_when_peer_never_completes_handshake():
    server = _RawSocketServer(respond_garbage=False)
    try:
        ctx = build_scan_context()
        result = probe_hostname("127.0.0.1", server.port, "irrelevant", timeout=0.3, ctx=ctx)
        assert result.status == "timeout"
    finally:
        server.stop()


def test_start_scan_rejects_single_domain_certificate(db):
    # Exactly one possible hostname — no coverage-vs-usage question to answer.
    cert = Certificate(domain="single.example.com", cert_name="single", sans=["single.example.com"],
                       cert_type=CertificateType.SINGLE.value, validation_method=ValidationMethod.HTTP_01.value,
                       is_wildcard=False)
    db.add(cert)
    db.commit()

    with pytest.raises(ValidationAppError):
        start_scan(db, cert.id, sources=["manual"], hostnames=["api.example.com"])


def test_start_scan_accepts_multi_san_non_wildcard_certificate(db, tls_server):
    # A non-wildcard certificate with several SANs has the exact same
    # "coverage isn't usage" ambiguity as a wildcard — it must be eligible.
    server, cert_pem = tls_server
    _, meta = parse_certificate(cert_pem)
    cert = Certificate(
        domain="api.example.com", cert_name="multi-san",
        sans=["api.example.com", "portal.example.com", "vpn.example.com"],
        cert_type=CertificateType.MULTI.value, validation_method=ValidationMethod.HTTP_01.value,
        is_wildcard=False, fingerprint_sha256=meta.fingerprint_sha256,
    )
    db.add(cert)
    db.commit()

    scan = start_scan(db, cert.id, sources=["manual"], hostnames=[f"127.0.0.1:{server.port}"])
    assert scan.status == "completed"


def test_sans_source_scans_the_certificates_own_san_list(db, tls_server):
    server, cert_pem = tls_server
    _, meta = parse_certificate(cert_pem)
    cert = Certificate(
        domain="api.example.com", cert_name="multi-san",
        sans=["api.example.com", "portal.example.com"],
        cert_type=CertificateType.MULTI.value, validation_method=ValidationMethod.HTTP_01.value,
        is_wildcard=False, fingerprint_sha256=meta.fingerprint_sha256,
    )
    db.add(cert)
    db.commit()

    scan = start_scan(db, cert.id, sources=["sans"], ports=[server.port], timeout=0.5)

    assert scan.candidate_count == 2  # both SANs, expanded across the one configured port
    results = db.query(CertificateUsageResult).filter(CertificateUsageResult.certificate_id == cert.id).all()
    assert {r.hostname for r in results} == {"api.example.com", "portal.example.com"}
    assert all(r.discovery_source == "certificate_sans" for r in results)


def test_sans_source_excludes_wildcard_entries_for_mixed_certificate(db, tls_server):
    # A mixed wildcard+SAN certificate's "sans" source must only scan the
    # literal extra hostname, not re-list the wildcard pattern itself as a
    # literal (unresolvable) candidate.
    server, cert_pem = tls_server
    _, meta = parse_certificate(cert_pem)
    cert = Certificate(
        domain="*.example.com", cert_name="mixed",
        sans=["*.example.com", "example.com"],
        cert_type=CertificateType.WILDCARD.value, validation_method=ValidationMethod.HTTP_01.value,
        is_wildcard=True, fingerprint_sha256=meta.fingerprint_sha256,
    )
    db.add(cert)
    db.commit()

    scan = start_scan(db, cert.id, sources=["sans"], ports=[server.port], timeout=0.5)

    assert scan.candidate_count == 1
    result = db.query(CertificateUsageResult).filter(CertificateUsageResult.certificate_id == cert.id).one()
    assert result.hostname == "example.com"


def test_start_scan_confirms_manual_hostname(db, tls_server):
    server, cert_pem = tls_server
    _, meta = parse_certificate(cert_pem)
    cert = _make_wildcard_cert(db, fingerprint=meta.fingerprint_sha256)

    scan = start_scan(db, cert.id, sources=["manual"], hostnames=[f"127.0.0.1:{server.port}"])

    assert scan.status == "completed"
    assert scan.candidate_count == 1
    assert scan.confirmed_count == 1

    result = db.query(CertificateUsageResult).filter(CertificateUsageResult.certificate_id == cert.id).one()
    assert result.status == "confirmed"
    assert result.hostname == "127.0.0.1"
    assert result.port == server.port


def test_rescan_preserves_first_seen_at_updates_last_checked_at(db, tls_server):
    from app.core.timeutils import ensure_aware

    server, cert_pem = tls_server
    _, meta = parse_certificate(cert_pem)
    cert = _make_wildcard_cert(db, fingerprint=meta.fingerprint_sha256)
    hostname_arg = [f"127.0.0.1:{server.port}"]

    start_scan(db, cert.id, sources=["manual"], hostnames=hostname_arg)
    first = db.query(CertificateUsageResult).filter(CertificateUsageResult.certificate_id == cert.id).one()
    first_seen = first.first_seen_at
    first_checked = first.last_checked_at

    start_scan(db, cert.id, sources=["manual"], hostnames=hostname_arg)
    db.refresh(first)

    assert db.query(CertificateUsageResult).filter(CertificateUsageResult.certificate_id == cert.id).count() == 1
    assert first.first_seen_at == first_seen  # preserved, not overwritten
    assert ensure_aware(first.last_checked_at) >= ensure_aware(first_checked)


def test_manual_and_inventory_candidates_are_deduplicated(db, tls_server):
    from app.models.server import Server

    server, cert_pem = tls_server
    _, meta = parse_certificate(cert_pem)
    cert = _make_wildcard_cert(db, fingerprint=meta.fingerprint_sha256)
    db.add(Server(hostname="api.example.com", environment="production"))
    db.commit()

    scan = start_scan(db, cert.id, sources=["inventory", "manual"], hostnames=["api.example.com"], ports=[server.port])

    # "api.example.com" appears in both sources but must only be scanned once per port.
    assert scan.candidate_count == 1
