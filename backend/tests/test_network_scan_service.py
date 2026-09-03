"""run_network_scan() against a real local TLS server — first test in the
repo to spin up a socket/SSLContext listener (grepped: none existed before).
Fully self-contained: binds 127.0.0.1:0 (OS-assigned ephemeral port, no
hardcoded port/race), no external services, nothing elevated."""

from __future__ import annotations

import socket
import ssl
import threading

import pytest
from conftest import _generate_self_signed  # noqa: F401

from app.core.timeutils import ensure_aware
from app.models.certificate import Certificate
from app.models.job import NetworkCertificateSighting
from app.services.discovery_service import run_network_scan


class _LocalTLSServer:
    """A minimal TLS-terminating listener for one certificate at a time.

    Each accepted connection is handled on its own thread (not a single
    accept-then-handshake loop) so concurrent scanner connections can't
    starve each other; update_cert() swaps the context so newly-accepted
    connections present a different certificate, simulating rotation.
    """

    def __init__(self, tmp_path, cert_pem: bytes, key_pem: bytes):
        self._tmp_path = tmp_path
        self._n = 0
        self.ctx = self._build_context(cert_pem, key_pem)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]

        self._stop = threading.Event()
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread.start()

    def _build_context(self, cert_pem: bytes, key_pem: bytes) -> ssl.SSLContext:
        self._n += 1
        cert_file = self._tmp_path / f"server_cert_{self._n}.pem"
        key_file = self._tmp_path / f"server_key_{self._n}.pem"
        cert_file.write_bytes(cert_pem)
        key_file.write_bytes(key_pem)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
        return ctx

    def update_cert(self, cert_pem: bytes, key_pem: bytes) -> None:
        self.ctx = self._build_context(cert_pem, key_pem)

    def _accept_loop(self) -> None:
        self.sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            with self.ctx.wrap_socket(conn, server_side=True):
                pass
        except (ssl.SSLError, OSError):
            pass

    def stop(self) -> None:
        self._stop.set()
        self.sock.close()
        self._accept_thread.join(timeout=2)


@pytest.fixture
def tls_server(tmp_path):
    _, cert_pem, key_pem = _generate_self_signed(["scan-target.example.com"])
    server = _LocalTLSServer(tmp_path, cert_pem, key_pem)
    yield server
    server.stop()


def test_scan_creates_certificate_and_sighting(db, tls_server):
    run = run_network_scan(db, targets=["127.0.0.1"], ports=[tls_server.port], concurrency=2, timeout_seconds=2)

    assert run.status == "completed"
    assert run.found_count == 1
    assert run.imported_count == 1

    cert = db.query(Certificate).filter(Certificate.provider_name == "network-scan").one()
    assert cert.status == "discovered"
    assert cert.domain == "scan-target.example.com"
    assert cert.key_path is None
    assert cert.cert_path is not None

    sighting = db.query(NetworkCertificateSighting).filter(
        NetworkCertificateSighting.host == "127.0.0.1", NetworkCertificateSighting.port == tls_server.port,
    ).one()
    assert sighting.certificate_id == cert.id


def test_rescan_same_endpoint_reuses_row_no_duplicate(db, tls_server):
    run_network_scan(db, targets=["127.0.0.1"], ports=[tls_server.port], concurrency=2, timeout_seconds=2)
    first_sighting = db.query(NetworkCertificateSighting).filter(
        NetworkCertificateSighting.host == "127.0.0.1", NetworkCertificateSighting.port == tls_server.port,
    ).one()
    first_seen_at = first_sighting.last_seen_at

    run2 = run_network_scan(db, targets=["127.0.0.1"], ports=[tls_server.port], concurrency=2, timeout_seconds=2)

    assert run2.imported_count == 0  # already-known fingerprint, no new Certificate row
    assert db.query(Certificate).filter(Certificate.provider_name == "network-scan").count() == 1
    sightings = db.query(NetworkCertificateSighting).filter(
        NetworkCertificateSighting.host == "127.0.0.1", NetworkCertificateSighting.port == tls_server.port,
    ).all()
    assert len(sightings) == 1  # no duplicate row — same row, last_seen_at bumped
    assert ensure_aware(sightings[0].last_seen_at) >= ensure_aware(first_seen_at)


def test_cert_rotation_at_same_endpoint_preserves_history(db, tls_server):
    run_network_scan(db, targets=["127.0.0.1"], ports=[tls_server.port], concurrency=2, timeout_seconds=2)
    original_cert = db.query(Certificate).filter(Certificate.provider_name == "network-scan").one()

    _, new_cert_pem, new_key_pem = _generate_self_signed(["rotated.example.com"])
    tls_server.update_cert(new_cert_pem, new_key_pem)

    run_network_scan(db, targets=["127.0.0.1"], ports=[tls_server.port], concurrency=2, timeout_seconds=2)

    certs = db.query(Certificate).filter(Certificate.provider_name == "network-scan").all()
    assert len(certs) == 2  # both certs tracked, old one not overwritten

    sightings = (
        db.query(NetworkCertificateSighting)
        .filter(NetworkCertificateSighting.host == "127.0.0.1", NetworkCertificateSighting.port == tls_server.port)
        .order_by(NetworkCertificateSighting.id)
        .all()
    )
    assert len(sightings) == 2  # rotation recorded as a new row, not overwritten in place
    assert sightings[0].certificate_id == original_cert.id
    assert sightings[1].certificate_id != original_cert.id


def test_closed_port_yields_no_certificate(db):
    # Nothing listens here — connection should fail fast and cleanly, not raise.
    run = run_network_scan(db, targets=["127.0.0.1"], ports=[1], concurrency=2, timeout_seconds=1)
    assert run.status == "completed"
    assert run.found_count == 0
    assert run.imported_count == 0
