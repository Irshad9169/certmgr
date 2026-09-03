"""Network TLS endpoint scanning — pure functions, no database access.

Fetches whatever certificate a live host:port presents over TLS, regardless
of trust (self-signed, expired, internal-CA are all fetched, not rejected —
that's the point: surfacing certificates CertMgr doesn't already know about,
including ones nobody would trust). This is deliberately NOT the same
verification approach as `health_service.py`'s live-TLS check, which uses a
verifying `ssl.create_default_context()` to answer "is this domain's serving
cert currently valid" — a different question from "what cert is being
served here at all."
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor

from app.core.exceptions import ValidationAppError


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def expand_targets(targets: list[str], *, max_targets: int, port_count: int) -> list[str]:
    """Expand CIDR ranges into individual hosts; pass hostnames/IPs through.

    Raises ValidationAppError if the resulting host count × port_count would
    exceed max_targets — a hard safety cap so an accidental wide CIDR (e.g. a
    /8) can't turn into an unbounded, disruptive scan.
    """
    hosts: list[str] = []
    for target in targets:
        t = target.strip()
        if not t:
            continue
        try:
            network = ipaddress.ip_network(t, strict=False)
        except ValueError:
            hosts.append(t)
            continue
        if network.num_addresses > 1:
            hosts.extend(str(ip) for ip in network.hosts())
        else:
            hosts.append(str(network.network_address))

    if len(hosts) * max(port_count, 1) > max_targets:
        raise ValidationAppError(
            f"Scan would cover {len(hosts) * max(port_count, 1)} host:port combinations, "
            f"exceeding the configured limit of {max_targets} (tls_scan.max_targets) — "
            "scan in smaller batches or raise the limit."
        )
    return hosts


def build_scan_context() -> ssl.SSLContext:
    """One shared, reusable context — safe across threads/connections.

    verify_mode=CERT_NONE deliberately: we want to see every certificate a
    host presents, not just ones that already chain to a trusted root.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def fetch_tls_certificate(host: str, port: int, *, timeout: float, ctx: ssl.SSLContext) -> bytes | None:
    """Connect and complete a TLS handshake; return the peer cert as DER bytes.

    Returns None on any connection/timeout/handshake failure — a closed port
    is the expected common case here, not an error worth raising.
    """
    # SNI can't carry an IP literal (RFC 6066); CPython's ssl module rejects
    # or silently drops it, so only pass server_hostname for real hostnames.
    server_hostname = None if _is_ip_literal(host) else host
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=server_hostname) as tls_sock:
                return tls_sock.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError):
        return None


def scan_targets(
    hosts: list[str], ports: list[int], *, concurrency: int, timeout: float
) -> list[tuple[str, int, bytes | None]]:
    """Fetch certificates from every (host, port) combination concurrently.

    Worker threads perform ONLY this network I/O — no database session is
    touched here, since SQLAlchemy sessions aren't safe for concurrent
    cross-thread use. Callers should process the returned results (writing
    to the DB) sequentially on the calling thread.
    """
    ctx = build_scan_context()
    combos = [(host, port) for host in hosts for port in ports]
    results: list[tuple[str, int, bytes | None]] = []
    with ThreadPoolExecutor(max_workers=max(concurrency, 1)) as pool:
        futures = {
            pool.submit(fetch_tls_certificate, host, port, timeout=timeout, ctx=ctx): (host, port)
            for host, port in combos
        }
        for future, (host, port) in futures.items():
            results.append((host, port, future.result()))
    return results
