"""Wildcard certificate usage discovery.

Answers: given a specific wildcard certificate already in CertMgr, which
real endpoints are actually presenting *that exact* certificate over TLS
right now? This is deliberately a different question from "does this
hostname fall under the wildcard" (CN/SAN/wildcard coverage) — coverage is
only ever a *candidate* signal here. The authoritative result always comes
from an exact SHA-256 fingerprint match against what a live TLS/SNI
handshake actually presents:

    presented certificate SHA-256 == selected certificate SHA-256

Reuses network_scanner.build_scan_context() for the discovery SSL context
(CERT_NONE — we're asking "what did you present", not "is it trusted") and
x509_utils.parse_certificate() for fingerprinting, matching the exact
canonical format already used for Certificate.fingerprint_sha256 elsewhere
in this codebase (uppercase, colon-separated).
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import Session

from app.core.domain_utils import validate_domain, validate_port
from app.core.exceptions import NotFoundError, ValidationAppError
from app.core.logging import get_logger
from app.core.timeutils import utcnow
from app.models.certificate import Certificate, CertificateDomain
from app.models.certificate_usage import CertificateUsageResult, CertificateUsageScan
from app.models.enums import (
    AuditResult,
    CertUsageResultStatus,
    CertUsageScanStatus,
    JobStatus,
    JobTrigger,
    JobType,
)
from app.models.job import JobExecution
from app.models.server import Server
from app.services import network_scanner
from app.services.audit_service import record
from app.services.x509_utils import parse_certificate

logger = get_logger(__name__)


def _normalize_fingerprint(value: str | None) -> str:
    """Canonical form for comparison only: upper-case, no separators.

    Both sides of the comparison already use the same "AA:BB:..." format
    elsewhere in this codebase, but normalizing defensively here means a
    stray lower-case value or missing colons can never cause a false
    DIFFERENT_CERTIFICATE."""
    return (value or "").upper().replace(":", "").replace(" ", "")


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _parse_manual_hostnames(raw: list[str]) -> list[tuple[str, int | None]]:
    """One hostname per line; optional trailing ":port" per line.

    Invalid lines are skipped (not raised) — one malformed line in a large
    pasted list shouldn't block every other valid candidate, matching this
    feature's "one endpoint failing must not stop the scan" philosophy.
    """
    out: list[tuple[str, int | None]] = []
    for line in raw:
        item = (line or "").strip()
        if not item:
            continue
        host, port = item, None
        if ":" in item and not _is_ip_literal(item):
            candidate_host, _, port_str = item.rpartition(":")
            try:
                port = validate_port(int(port_str))
                host = candidate_host.strip()
            except (ValueError, ValidationAppError):
                host, port = item, None
        try:
            out.append((validate_domain(host, allow_wildcard=False), port))
        except ValidationAppError:
            if _is_ip_literal(host):
                out.append((host.lower(), port))
            else:
                logger.warning("Skipping invalid manual hostname: %r", host)
    return out


def _wildcard_suffix(domain: str) -> str:
    """"*.example.com" -> "example.com" """
    return domain[2:] if domain.startswith("*.") else domain


def _covered_by_single_label_wildcard(hostname: str, suffix: str) -> bool:
    """Per RFC 6125/X.509 wildcard matching, "*.example.com" covers exactly
    ONE additional DNS label — "api.example.com" is covered,
    "a.b.example.com" is not (that needs its own "*.b.example.com" cert). A
    plain suffix check (hostname.endswith(".example.com")) would wrongly
    treat any subdomain depth as covered, pulling unrelated multi-level
    hostnames into the candidate list. Also excludes the bare suffix itself
    (the apex domain isn't covered by the wildcard label at all — it needs
    its own SAN entry, which the caller can already see and doesn't need
    this function to infer)."""
    h = hostname.rstrip(".")
    s = suffix.rstrip(".").lower()
    if not h.endswith(f".{s}"):
        return False
    remainder = h[: -(len(s) + 1)]
    return bool(remainder) and "." not in remainder


def _wildcard_suffixes(certificate: Certificate) -> list[str]:
    """All distinct suffixes this certificate's wildcard SAN entries cover —
    a certificate can carry more than one wildcard SAN (e.g. *.example.com
    and *.corp.example.com together). Empty for a certificate with no
    wildcard SAN at all (a pure multi-SAN certificate)."""
    sans = certificate.sans or []
    wildcard_sans = [s for s in sans if s.startswith("*.")]
    if not wildcard_sans and certificate.domain.startswith("*."):
        wildcard_sans = [certificate.domain]
    return sorted({_wildcard_suffix(s) for s in wildcard_sans})


def _literal_sans(certificate: Certificate) -> list[str]:
    """Non-wildcard SAN entries. For a pure multi-SAN certificate these ARE
    the complete, exact set of hostnames it was issued for — the same
    "coverage isn't usage" question a wildcard raises, just enumerated
    instead of pattern-matched. For a mixed wildcard+SAN certificate these
    are the specific extra hostnames alongside the wildcard's broader (but
    still single-label) coverage."""
    return [s.strip().lower() for s in (certificate.sans or []) if s and not s.startswith("*.")]


def _candidate_hostnames_from_inventory(db: Session, suffixes: list[str]) -> set[str]:
    """Reuse hostnames CertMgr already knows about: managed servers and
    domains from any certificate record (its own or others') that are
    actually covered by one of this certificate's wildcard suffixes'
    single-label scope — e.g. if *.example.com is selected, "api.example.com"
    already tracked as its own certificate's domain is an obvious candidate,
    but "api.internal.example.com" is not (a different, deeper wildcard
    would be needed to cover that, so surfacing it here would be a false
    candidate the live probe could never confirm). Empty suffixes (a pure
    multi-SAN certificate with no wildcard SAN) yields no candidates —
    there's no pattern to discover more hostnames from; the "sans" source
    already provides the certificate's own exact, finite hostname list."""
    if not suffixes:
        return set()
    candidates: set[str] = set()

    for (hostname,) in db.query(Server.hostname).all():
        h = (hostname or "").strip().lower()
        if h and any(_covered_by_single_label_wildcard(h, s) for s in suffixes):
            candidates.add(h)

    for (domain,) in db.query(CertificateDomain.domain).all():
        d = (domain or "").strip().lower()
        if d and not d.startswith("*.") and any(_covered_by_single_label_wildcard(d, s) for s in suffixes):
            candidates.add(d)

    return candidates


@dataclass
class _ProbeResult:
    status: str
    ip_address: str | None = None
    presented_fingerprint: str | None = None
    presented_subject: str | None = None
    presented_issuer: str | None = None
    presented_serial: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    error_code: str | None = None
    error_message: str | None = None


def _resolve_with_timeout(hostname: str, timeout: float) -> str:
    """socket.gethostbyname() has no timeout of its own — a hung resolver
    (seen for real during this project's crt.sh CT-monitoring integration:
    an OS-level DNS lookup that outlives any application-level timeout
    passed elsewhere) could otherwise block a scan indefinitely. Bounding it
    in a throwaway worker thread means a hang there can only ever cost this
    one probe its configured timeout, never more — the resolver thread may
    leak until it eventually returns, but the scan itself is never stuck."""
    pool = ThreadPoolExecutor(max_workers=1)
    try:
        return pool.submit(socket.gethostbyname, hostname).result(timeout=timeout)
    finally:
        pool.shutdown(wait=False)


def probe_hostname(hostname: str, port: int, expected_fingerprint: str, *,
                    timeout: float, ctx: ssl.SSLContext) -> _ProbeResult:
    """DNS resolve -> TCP connect -> TLS/SNI handshake -> fingerprint compare.

    Certificate verification is deliberately disabled for this probe (see
    build_scan_context()) — the question is "what did this endpoint
    present", not "is it trusted". Every failure stage is preserved
    distinctly (DNS/TCP/TLS/timeout) rather than collapsed to one generic
    failure, since that distinction is the whole point of this feature.
    """
    ip: str | None = None
    if _is_ip_literal(hostname):
        ip = hostname
    else:
        try:
            ip = _resolve_with_timeout(hostname, timeout)
        except FutureTimeoutError:
            return _ProbeResult(status=CertUsageResultStatus.TIMEOUT.value,
                                error_code="dns_timeout", error_message="DNS resolution timed out")
        except (socket.gaierror, UnicodeError) as exc:
            return _ProbeResult(status=CertUsageResultStatus.DNS_FAILED.value,
                                error_code="dns_failed", error_message=str(exc)[:500])

    server_hostname = None if _is_ip_literal(hostname) else hostname
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            try:
                with ctx.wrap_socket(sock, server_hostname=server_hostname) as tls_sock:
                    der = tls_sock.getpeercert(binary_form=True)
            except TimeoutError:
                return _ProbeResult(status=CertUsageResultStatus.TIMEOUT.value, ip_address=ip,
                                    error_code="tls_timeout", error_message="TLS handshake timed out")
            except ssl.SSLError as exc:
                return _ProbeResult(status=CertUsageResultStatus.TLS_FAILED.value, ip_address=ip,
                                    error_code="tls_failed", error_message=str(exc)[:500])
    except TimeoutError:
        return _ProbeResult(status=CertUsageResultStatus.TIMEOUT.value, ip_address=ip,
                            error_code="connect_timeout", error_message="Connection timed out")
    except OSError as exc:
        return _ProbeResult(status=CertUsageResultStatus.UNREACHABLE.value, ip_address=ip,
                            error_code="connect_failed", error_message=str(exc)[:500])

    if der is None:
        return _ProbeResult(status=CertUsageResultStatus.TLS_FAILED.value, ip_address=ip,
                            error_code="no_certificate",
                            error_message="TLS handshake succeeded but no certificate was presented")

    try:
        _, meta = parse_certificate(der)
    except ValidationAppError as exc:
        return _ProbeResult(status=CertUsageResultStatus.TLS_FAILED.value, ip_address=ip,
                            error_code="parse_failed", error_message=str(exc)[:500])

    presented = meta.fingerprint_sha256
    matched = _normalize_fingerprint(presented) == _normalize_fingerprint(expected_fingerprint)
    return _ProbeResult(
        status=(CertUsageResultStatus.CONFIRMED.value if matched
               else CertUsageResultStatus.DIFFERENT_CERTIFICATE.value),
        ip_address=ip,
        presented_fingerprint=presented,
        presented_subject=meta.subject,
        presented_issuer=meta.issuer,
        presented_serial=meta.serial_number,
        not_before=meta.valid_from,
        not_after=meta.valid_until,
    )


def _record_result(db: Session, scan: CertificateUsageScan, certificate: Certificate,
                   hostname: str, port: int, source: str, probe: _ProbeResult) -> str:
    """Upsert-in-place: first_seen_at is preserved across rescans."""
    now = utcnow()
    existing = db.query(CertificateUsageResult).filter(
        CertificateUsageResult.certificate_id == certificate.id,
        CertificateUsageResult.hostname == hostname,
        CertificateUsageResult.ip_address == probe.ip_address,
        CertificateUsageResult.port == port,
    ).first()

    if existing is None:
        existing = CertificateUsageResult(
            certificate_id=certificate.id, hostname=hostname, ip_address=probe.ip_address,
            port=port, discovery_source=source, first_seen_at=now,
        )
        db.add(existing)

    existing.status = probe.status
    existing.expected_fingerprint = certificate.fingerprint_sha256
    existing.presented_fingerprint = probe.presented_fingerprint
    existing.presented_subject = probe.presented_subject
    existing.presented_issuer = probe.presented_issuer
    existing.presented_serial = probe.presented_serial
    existing.not_before = probe.not_before
    existing.not_after = probe.not_after
    existing.error_code = probe.error_code
    existing.error_message = probe.error_message
    existing.last_checked_at = now
    existing.scan_id = scan.id
    if probe.status in (CertUsageResultStatus.CONFIRMED.value, CertUsageResultStatus.DIFFERENT_CERTIFICATE.value):
        existing.last_seen_at = now
    return probe.status


def get_usage_discovery_certificate(db: Session, certificate_id: int) -> Certificate:
    """Shared validation for both the eager and async trigger paths — the
    async path needs it BEFORE dispatch (to fail fast in the request instead
    of creating a queued row for a certificate that was never eligible).

    Eligible: wildcard certificates (the original case — "*.example.com"
    covers a pattern, not a specific endpoint) and multi-SAN certificates
    (the exact same "coverage isn't usage" ambiguity — a cert listing
    api/portal/vpn.example.com as SANs doesn't tell you which of those are
    actually still serving it). A single-domain, non-wildcard certificate
    has exactly one possible hostname — there's no coverage-vs-usage
    question left to answer, so it's excluded."""
    certificate = db.query(Certificate).filter(Certificate.id == certificate_id).first()
    if certificate is None:
        raise NotFoundError("Certificate not found")
    if not certificate.is_wildcard and len(certificate.sans or []) <= 1:
        raise ValidationAppError(
            "Usage discovery is only available for wildcard or multi-domain (SAN) certificates in this release"
        )
    return certificate


def start_scan(
    db: Session, certificate_id: int, *,
    sources: list[str] | None = None,
    hostnames: list[str] | None = None,
    ports: list[int] | None = None,
    timeout: float | None = None,
    concurrency: int | None = None,
    created_by: int | None = None,
    scan_id: int | None = None,
) -> CertificateUsageScan:
    """scan_id: reuse an existing (pre-created, QUEUED) scan row rather than
    creating a new one — lets the async API route hand the frontend a scan
    id to poll immediately at dispatch time, before the Celery task actually
    starts running."""
    certificate = get_usage_discovery_certificate(db, certificate_id)

    from app.services.settings_service import get_setting

    resolved_sources = sources or ["sans", "inventory", "manual"]
    raw_ports = ports or [
        int(p) for p in (get_setting(db, "cert_usage_scan.ports") or "443,8443,9443").split(",") if p.strip()
    ]
    resolved_ports = [validate_port(p) for p in raw_ports]
    resolved_timeout = timeout or float(get_setting(db, "cert_usage_scan.timeout_seconds") or 5)
    resolved_concurrency = concurrency or int(get_setting(db, "cert_usage_scan.max_concurrency") or 25)

    suffixes = _wildcard_suffixes(certificate)

    # (hostname, explicit_port_or_None, source)
    candidates: dict[str, tuple[str, int | None]] = {}
    if "sans" in resolved_sources:
        for h in _literal_sans(certificate):
            candidates[h] = ("certificate_sans", None)
    if "inventory" in resolved_sources:
        for h in _candidate_hostnames_from_inventory(db, suffixes):
            candidates[h] = ("inventory", None)
    if "manual" in resolved_sources and hostnames:
        for h, explicit_port in _parse_manual_hostnames(hostnames):
            candidates[h] = ("manual", explicit_port)

    # Expand each candidate hostname across the configured ports, unless the
    # candidate itself specified one explicitly (manual "host:port" form).
    targets: list[tuple[str, int, str]] = []
    for hostname, (source, explicit_port) in candidates.items():
        for port in ([explicit_port] if explicit_port else resolved_ports):
            targets.append((hostname, port, source))

    scan = db.get(CertificateUsageScan, scan_id) if scan_id is not None else None
    if scan is None:
        scan = CertificateUsageScan(certificate_id=certificate.id, sources=resolved_sources, created_by=created_by)
        db.add(scan)
    scan.status = CertUsageScanStatus.RUNNING.value
    scan.sources = resolved_sources
    scan.started_at = utcnow()
    scan.candidate_count = len(targets)
    db.commit()

    if not targets:
        scan.status = CertUsageScanStatus.COMPLETED.value
        scan.completed_at = utcnow()
        scan.log = "No candidate hostnames — nothing to scan."
        db.commit()
        return scan

    ctx = network_scanner.build_scan_context()
    counts = {
        CertUsageResultStatus.CONFIRMED.value: 0,
        CertUsageResultStatus.DIFFERENT_CERTIFICATE.value: 0,
        CertUsageResultStatus.UNREACHABLE.value: 0,
        CertUsageResultStatus.DNS_FAILED.value: 0,
        CertUsageResultStatus.TLS_FAILED.value: 0,
        CertUsageResultStatus.TIMEOUT.value: 0,
    }

    # Worker threads perform ONLY network I/O — no DB session touched here,
    # matching network_scanner.scan_targets()'s exact concurrency pattern.
    with ThreadPoolExecutor(max_workers=max(resolved_concurrency, 1)) as pool:
        futures = {
            pool.submit(probe_hostname, hostname, port, certificate.fingerprint_sha256 or "",
                       timeout=resolved_timeout, ctx=ctx): (hostname, port, source)
            for hostname, port, source in targets
        }
        for future, (hostname, port, source) in futures.items():
            try:
                probe = future.result()
            except Exception as exc:  # noqa: BLE001
                probe = _ProbeResult(status=CertUsageResultStatus.UNREACHABLE.value,
                                     error_code="probe_error", error_message=str(exc)[:500])
            status = _record_result(db, scan, certificate, hostname, port, source, probe)
            counts[status] = counts.get(status, 0) + 1
            scan.scanned_count += 1

    scan.confirmed_count = counts[CertUsageResultStatus.CONFIRMED.value]
    scan.different_certificate_count = counts[CertUsageResultStatus.DIFFERENT_CERTIFICATE.value]
    scan.unreachable_count = counts[CertUsageResultStatus.UNREACHABLE.value]
    scan.error_count = (counts[CertUsageResultStatus.DNS_FAILED.value]
                       + counts[CertUsageResultStatus.TLS_FAILED.value]
                       + counts[CertUsageResultStatus.TIMEOUT.value])
    scan.status = CertUsageScanStatus.COMPLETED.value
    scan.completed_at = utcnow()
    scan.log = (
        f"{scan.scanned_count} candidate(s) scanned: "
        f"{scan.confirmed_count} confirmed, {scan.different_certificate_count} different certificate, "
        f"{scan.unreachable_count} unreachable, {scan.error_count} DNS/TLS/timeout errors."
    )
    db.commit()

    logger.info(
        "cert usage scan #%s completed for certificate #%s: candidates=%s confirmed=%s different=%s errors=%s",
        scan.id, certificate.id, scan.candidate_count, scan.confirmed_count,
        scan.different_certificate_count, scan.error_count,
    )

    db.add(JobExecution(
        job_type=JobType.CERT_USAGE_SCAN.value, certificate_id=certificate.id,
        trigger=JobTrigger.MANUAL.value, status=JobStatus.SUCCESS.value,
        started_at=scan.started_at, finished_at=scan.completed_at,
        stdout=scan.log, created_by=created_by,
    ))
    record(db, action="certificate.usage_scan", resource_type="certificate", resource_id=certificate.id,
          result=AuditResult.SUCCESS, details={"scan_id": scan.id, "candidates": scan.candidate_count,
                                               "confirmed": scan.confirmed_count})
    db.commit()
    return scan


def usage_summary(db: Session, certificate_id: int) -> dict:
    from sqlalchemy import func

    rows = (
        db.query(CertificateUsageResult.status, func.count(CertificateUsageResult.id))
        .filter(CertificateUsageResult.certificate_id == certificate_id)
        .group_by(CertificateUsageResult.status)
        .all()
    )
    counts = dict(rows)
    return {
        "candidates": sum(counts.values()),
        "confirmed": counts.get(CertUsageResultStatus.CONFIRMED.value, 0),
        "different_certificate": counts.get(CertUsageResultStatus.DIFFERENT_CERTIFICATE.value, 0),
        "unreachable": counts.get(CertUsageResultStatus.UNREACHABLE.value, 0),
        "dns_failed": counts.get(CertUsageResultStatus.DNS_FAILED.value, 0),
        "tls_failed": counts.get(CertUsageResultStatus.TLS_FAILED.value, 0),
        "timeout": counts.get(CertUsageResultStatus.TIMEOUT.value, 0),
    }
