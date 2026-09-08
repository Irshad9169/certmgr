"""Automatic certificate discovery.

Scans configurable directories for PEM/DER/PKCS12 files, extracts metadata,
matches private keys to certificates, and imports new discoveries.
"""

from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.core.timeutils import ensure_aware, utcnow
from app.models.certificate import Certificate, CertificateDomain
from app.models.enums import (
    AuditResult,
    CertificateStatus,
    FindingStatus,
    JobStatus,
    JobTrigger,
    JobType,
    RenewalStatus,
)
from app.models.finding import CTFinding
from app.models.job import (
    CTObservation,
    DiscoveryIgnore,
    DiscoveryRun,
    JobExecution,
    NetworkCertificateSighting,
)
from app.services.audit_service import record
from app.services.certificate_service import _cert_type_for, import_from_paths
from app.services.x509_utils import parse_certificate, parse_pfx

logger = get_logger(__name__)

DEFAULT_SCAN_PATHS = [
    "/etc/letsencrypt/live",
    "/etc/pki/tls/certs",
    "/etc/pki/tls/private",
    "/etc/nginx",
    "/etc/httpd",
    "/etc/apache2",
    "/etc/openvpn",
]

_CERT_EXTS = (".pem", ".crt", ".cer", ".cert", ".der")
_KEY_EXTS = (".pem", ".key")
_PFX_EXTS = (".pfx", ".p12")


def _paths_from_settings(db: Session | None, extra: list[str] | None = None) -> list[str]:
    paths = list(settings_scan_paths(db))
    for p in extra or []:
        if p not in paths:
            paths.append(p)
    return paths


def settings_scan_paths(db: Session | None = None) -> list[str]:
    """Scan paths from app settings (admin configurable), else defaults."""
    from app.services.settings_service import get_setting

    try:
        raw = get_setting(db, "discovery.scan_paths")
        if raw:
            return [p.strip() for p in raw.split(",") if p.strip()]
    except Exception:  # noqa: BLE001, S110 — fall back to defaults if settings unreadable
        pass
    return DEFAULT_SCAN_PATHS


def run_discovery(db: Session, *, extra_paths: list[str] | None = None,
                  created_by: int | None = None) -> DiscoveryRun:
    run = DiscoveryRun(
        started_at=utcnow(),
        status="running",
        scan_paths=_paths_from_settings(db, extra_paths),
        created_by=created_by,
    )
    db.add(run)
    db.commit()

    logs: list[str] = []
    found = 0
    seen_fingerprints = {c.fingerprint_sha256 for c in db.query(Certificate).all() if c.fingerprint_sha256}
    # Certificates a user deliberately deleted from tracking (see
    # certificate_service.delete_certificate) must stay gone — without this,
    # the next scan just re-imports the same file it found before.
    seen_fingerprints |= {
        i.fingerprint_sha256 for i in db.query(DiscoveryIgnore).all()
    }

    for base in run.scan_paths:
        root = Path(base)
        if not root.exists():
            logs.append(f"SKIP (missing): {base}")
            continue
        found += _walk(root, run, db, seen_fingerprints, logs)

    # run.imported_count / run.skipped_count are already correct here —
    # _maybe_import_cert()/_maybe_import_pfx() increment them in place on
    # `run` as they go.
    run.found_count = found
    run.status = "completed"
    run.finished_at = utcnow()
    run.log = "\n".join(logs[-500:]) or "No certificates found."
    db.commit()

    db.add(JobExecution(
        job_type=JobType.DISCOVERY.value, trigger=JobTrigger.SCHEDULER.value,
        status=JobStatus.SUCCESS.value, started_at=run.started_at, finished_at=run.finished_at,
        stdout=run.log, created_by=created_by,
    ))
    record(db, action="discovery.run", resource_type="discovery", resource_id=run.id,
           result=AuditResult.SUCCESS, details={"found": run.found_count, "imported": run.imported_count})
    db.commit()
    return run


def _tls_scan_setting(db: Session | None, key: str, default: str) -> str:
    from app.services.settings_service import get_setting

    try:
        return get_setting(db, key) or default
    except Exception:  # noqa: BLE001, S110 — fall back to the hardcoded default
        return default


def run_network_scan(
    db: Session,
    *,
    targets: list[str],
    ports: list[int] | None = None,
    concurrency: int | None = None,
    timeout_seconds: float | None = None,
    created_by: int | None = None,
) -> DiscoveryRun:
    """Scan hosts/CIDRs across a port list for live TLS certificates.

    Unlike run_discovery() (filesystem paths, imports cert/key pairs it
    finds), this never has a private key — network-found certificates are
    read-only inventory entries (status=DISCOVERED), matching how a live TLS
    handshake can never yield the peer's private key.
    """
    from app.services import network_scanner

    resolved_ports = ports or [
        int(p) for p in _tls_scan_setting(db, "tls_scan.default_ports", "443,8443,636,465").split(",") if p.strip()
    ]
    resolved_concurrency = concurrency or int(_tls_scan_setting(db, "tls_scan.concurrency", "20"))
    resolved_timeout = timeout_seconds or float(_tls_scan_setting(db, "tls_scan.timeout_seconds", "3"))
    max_targets = int(_tls_scan_setting(db, "tls_scan.max_targets", "2048"))

    hosts = network_scanner.expand_targets(targets, max_targets=max_targets, port_count=len(resolved_ports))

    run = DiscoveryRun(
        started_at=utcnow(),
        status="running",
        scan_type="network",
        scan_targets=targets,
        scan_ports=resolved_ports,
        created_by=created_by,
    )
    db.add(run)
    db.commit()

    logs: list[str] = []
    found = 0
    # Certificates a user deliberately deleted from tracking must stay
    # gone — same set run_discovery() builds, so deleting a network-found
    # certificate here also stops the next scan from just recreating it.
    ignored_fingerprints = {i.fingerprint_sha256 for i in db.query(DiscoveryIgnore).all()}
    results = network_scanner.scan_targets(
        hosts, resolved_ports, concurrency=resolved_concurrency, timeout=resolved_timeout
    )
    for host, port, der in results:
        if der is None:
            continue
        found += 1
        try:
            _record_sighting(db, host, port, der, run, logs, ignored_fingerprints)
        except Exception as exc:  # noqa: BLE001
            run.skipped_count = (run.skipped_count or 0) + 1
            logs.append(f"ERR {host}:{port}: {exc}")

    run.found_count = found
    run.status = "completed"
    run.finished_at = utcnow()
    # Only FOUND/ROTATED/ERR lines are logged (see _record_sighting) — the
    # common case (an already-known cert unchanged) is silent, so signal
    # isn't buried across up to max_targets endpoints. That means an empty
    # `logs` list is ambiguous by itself: it's both "found nothing" (closed
    # ports only) and "found N already-known certs, nothing changed" — use
    # `found` to tell those apart rather than always falling back to
    # "No certificates found."
    if logs:
        run.log = "\n".join(logs[-500:])
    elif found:
        run.log = f"{found} certificate(s) found, all already known and unchanged."
    else:
        run.log = "No certificates found."
    db.commit()

    db.add(JobExecution(
        job_type=JobType.NETWORK_SCAN.value, trigger=JobTrigger.SCHEDULER.value,
        status=JobStatus.SUCCESS.value, started_at=run.started_at, finished_at=run.finished_at,
        stdout=run.log, created_by=created_by,
    ))
    record(db, action="discovery.network_scan", resource_type="discovery", resource_id=run.id,
           result=AuditResult.SUCCESS, details={"found": run.found_count, "imported": run.imported_count})
    db.commit()
    return run


def _validity_status(valid_until, *, threshold_days: int) -> str:
    """Network-found certificates never go through issue/renew (no private
    key, auto_renew is always False), so nothing else ever revisits their
    status after creation — unlike platform-managed certs, which get a
    fresh status on every renewal attempt. Compute it from the actual
    validity window instead of a fixed placeholder, and recompute it on
    every rescan too, so a cert that expires between scans is reflected
    next time it's seen rather than staying frozen at whatever it was."""
    if valid_until is None:
        return CertificateStatus.DISCOVERED.value  # unknown validity window
    remaining = ensure_aware(valid_until) - utcnow()
    if remaining.total_seconds() <= 0:
        return CertificateStatus.EXPIRED.value
    if remaining.days <= threshold_days:
        return CertificateStatus.EXPIRING.value
    return CertificateStatus.ACTIVE.value


def _record_sighting(db: Session, host: str, port: int, der: bytes, run: DiscoveryRun, logs: list[str],
                     ignored_fingerprints: set[str]) -> None:
    from app.core.config import settings
    from app.services.storage import get_file_store

    cert_obj, meta = parse_certificate(der)

    certificate = db.query(Certificate).filter(
        Certificate.fingerprint_sha256 == meta.fingerprint_sha256
    ).first()
    is_new = certificate is None

    if is_new and meta.fingerprint_sha256 in ignored_fingerprints:
        logs.append(f"SKIP ignored cert at {host}:{port} ({meta.fingerprint_sha256})")
        return

    if is_new:
        store = get_file_store()
        store_dir = store.cert_dir(meta.fingerprint_sha256)
        primary = meta.sans[0] if meta.sans else host
        (store_dir / "cert.pem").write_bytes(cert_obj.public_bytes(serialization.Encoding.PEM))

        certificate = Certificate(
            domain=primary,
            sans=meta.sans or [primary],
            is_wildcard=meta.is_wildcard,
            cert_type=_cert_type_for(meta.sans or [primary]),
            subject=meta.subject, issuer=meta.issuer, serial_number=meta.serial_number,
            fingerprint_sha256=meta.fingerprint_sha256,
            public_key_algorithm=meta.public_key_algorithm,
            key_type=meta.key_type, key_size=meta.key_size,
            signature_algorithm=meta.signature_algorithm,
            valid_from=meta.valid_from, valid_until=meta.valid_until,
            status=_validity_status(meta.valid_until, threshold_days=settings.renewal_threshold_days),
            environment=settings.default_environment,
            provider_name="network-scan",
            imported=False,
            auto_renew=False,
            renewal_status=RenewalStatus.NONE.value,
            cert_path=str(store_dir / "cert.pem"),
            managed_by_platform=False,
        )
        db.add(certificate)
        db.flush()
        for idx, d in enumerate(certificate.sans):
            db.add(CertificateDomain(certificate_id=certificate.id, domain=d, is_primary=(idx == 0)))
        run.imported_count = (run.imported_count or 0) + 1
        logs.append(f"FOUND new cert at {host}:{port} ({certificate.fingerprint_sha256})")

    latest = (
        db.query(NetworkCertificateSighting)
        .filter(NetworkCertificateSighting.host == host, NetworkCertificateSighting.port == port)
        .order_by(NetworkCertificateSighting.id.desc())
        .first()
    )
    now = utcnow()
    if latest is not None and latest.certificate_id == certificate.id:
        latest.last_seen_at = now
        latest.discovery_run_id = run.id
        if not certificate.managed_by_platform:
            certificate.status = _validity_status(certificate.valid_until, threshold_days=settings.renewal_threshold_days)
    else:
        db.add(NetworkCertificateSighting(
            fingerprint_sha256=certificate.fingerprint_sha256,
            certificate_id=certificate.id,
            host=host, port=port,
            first_seen_at=now, last_seen_at=now,
            discovery_run_id=run.id,
        ))
        if latest is not None:
            logs.append(f"ROTATED cert at {host}:{port} (was cert #{latest.certificate_id}, now #{certificate.id})")


def run_ct_monitor(
    db: Session,
    *,
    domains: list[str],
    expected_issuers: list[str] | None = None,
    sensitive_keywords: list[str] | None = None,
    staging_keywords: list[str] | None = None,
    max_certs_per_domain: int | None = None,
    created_by: int | None = None,
) -> DiscoveryRun:
    """Query crt.sh for admin-configured domains and turn what comes back
    into inventory + investigable Findings.

    Unlike run_network_scan() (what's reachable), this finds what's been
    *issued* — including a certificate that was never deployed anywhere,
    e.g. a mis-issued/rogue certificate for your domain from an unexpected CA.
    """
    from app.services import ct_monitor

    resolved_expected_issuers = expected_issuers if expected_issuers is not None else [
        e for e in _tls_scan_setting(db, "ct_monitoring.expected_issuers", "").split(",") if e.strip()
    ]
    resolved_sensitive = sensitive_keywords if sensitive_keywords is not None else [
        k for k in _tls_scan_setting(
            db, "ct_monitoring.sensitive_keywords",
            "admin,vpn,sso,login,auth,portal,mail,owa,gateway,remote,internal,secure",
        ).split(",") if k.strip()
    ]
    resolved_staging = staging_keywords if staging_keywords is not None else [
        k for k in _tls_scan_setting(
            db, "ct_monitoring.staging_keywords",
            "dev,test,qa,uat,stage,staging,sandbox,preprod,demo,lab",
        ).split(",") if k.strip()
    ]
    max_certs = max_certs_per_domain or int(_tls_scan_setting(db, "ct_monitoring.max_certs_per_domain", "200"))

    run = DiscoveryRun(
        started_at=utcnow(),
        status="running",
        scan_type="ct_log",
        scan_domains=domains,
        created_by=created_by,
    )
    db.add(run)
    db.commit()

    logs: list[str] = []
    found = 0
    ignored_fingerprints = {i.fingerprint_sha256 for i in db.query(DiscoveryIgnore).all()}
    known_crt_sh_ids = {o.crt_sh_id for o in db.query(CTObservation).all()}

    for domain in domains:
        entries = ct_monitor.fetch_crtsh_entries(domain, limit=max_certs)
        if entries is None:
            run.skipped_count = (run.skipped_count or 0) + 1
            logs.append(f"SKIP {domain}: crt.sh query failed (see server logs for details)")
            continue
        for entry in entries:
            try:
                crt_sh_id = int(entry.get("id"))
            except (TypeError, ValueError):
                continue
            found += 1
            try:
                _record_ct_observation(
                    db, domain, crt_sh_id, run, logs,
                    ignored_fingerprints=ignored_fingerprints,
                    known_crt_sh_ids=known_crt_sh_ids,
                    monitored_domains=domains,
                    expected_issuers=resolved_expected_issuers,
                    sensitive_keywords=resolved_sensitive,
                    staging_keywords=resolved_staging,
                    serial_number=entry.get("serial_number"),
                    issuer_name=entry.get("issuer_name"),
                )
            except Exception as exc:  # noqa: BLE001
                run.skipped_count = (run.skipped_count or 0) + 1
                logs.append(f"ERR {domain} crt.sh id={crt_sh_id}: {exc}")

    run.found_count = found
    run.status = "completed"
    run.finished_at = utcnow()
    if logs:
        run.log = "\n".join(logs[-500:])
    elif found:
        run.log = f"{found} CT entries found, all already known and unchanged."
    else:
        run.log = "No certificates found."
    db.commit()

    db.add(JobExecution(
        job_type=JobType.CT_MONITOR.value, trigger=JobTrigger.SCHEDULER.value,
        status=JobStatus.SUCCESS.value, started_at=run.started_at, finished_at=run.finished_at,
        stdout=run.log, created_by=created_by,
    ))
    record(db, action="discovery.ct_monitor", resource_type="discovery", resource_id=run.id,
           result=AuditResult.SUCCESS, details={"found": run.found_count, "imported": run.imported_count})
    db.commit()
    return run


def _record_ct_observation(
    db: Session, domain: str, crt_sh_id: int, run: DiscoveryRun, logs: list[str],
    *, ignored_fingerprints: set[str], known_crt_sh_ids: set[int], monitored_domains: list[str],
    expected_issuers: list[str], sensitive_keywords: list[str], staging_keywords: list[str],
    serial_number: str | None = None, issuer_name: str | None = None,
) -> None:
    from app.core.config import settings
    from app.services import ct_monitor
    from app.services.storage import get_file_store

    if crt_sh_id in known_crt_sh_ids:
        # An immutable historical record — no need to re-fetch/re-parse.
        obs = db.query(CTObservation).filter(CTObservation.crt_sh_id == crt_sh_id).first()
        if obs is not None:
            obs.last_seen_at = utcnow()
            obs.ct_monitor_run_id = run.id
        return

    match_type = ct_monitor.classify_domain_match(domain, monitored_domains)

    # crt.sh commonly logs the exact same certificate to several CT logs,
    # each getting its own crt_sh_id (confirmed live: a single-domain query
    # returned duplicate serial numbers under different ids). crt.sh's cheap
    # JSON row already carries serial_number/issuer_name, so a known
    # certificate can be matched here without the expensive raw-PEM-fetch
    # round-trip. A mismatch or absent serial just falls through to the
    # normal path below — this is a pure optimization, never a source of
    # incorrect matches.
    certificate = None
    if serial_number and issuer_name:
        try:
            serial_hex = f"{int(serial_number, 16):x}"
        except (TypeError, ValueError):
            serial_hex = None
        if serial_hex:
            certificate = db.query(Certificate).filter(
                Certificate.serial_number == serial_hex,
                Certificate.issuer == issuer_name,
            ).first()

    if certificate is not None:
        is_new = False
        matched_name = certificate.sans[0] if certificate.sans else domain
    else:
        pem = ct_monitor.fetch_crtsh_certificate_pem(crt_sh_id)
        if pem is None:
            run.skipped_count = (run.skipped_count or 0) + 1
            logs.append(f"SKIP crt.sh id={crt_sh_id}: could not fetch certificate")
            return
        cert_obj, meta = parse_certificate(pem)

        if meta.fingerprint_sha256 in ignored_fingerprints:
            logs.append(f"SKIP ignored cert (crt.sh id={crt_sh_id}, {meta.fingerprint_sha256})")
            return

        matched_name = meta.sans[0] if meta.sans else domain

        certificate = db.query(Certificate).filter(
            Certificate.fingerprint_sha256 == meta.fingerprint_sha256
        ).first()
        is_new = certificate is None

        if is_new:
            store = get_file_store()
            store_dir = store.cert_dir(meta.fingerprint_sha256)
            primary = meta.sans[0] if meta.sans else domain
            (store_dir / "cert.pem").write_bytes(cert_obj.public_bytes(serialization.Encoding.PEM))

            certificate = Certificate(
                domain=primary,
                sans=meta.sans or [primary],
                is_wildcard=meta.is_wildcard,
                cert_type=_cert_type_for(meta.sans or [primary]),
                subject=meta.subject, issuer=meta.issuer, serial_number=meta.serial_number,
                fingerprint_sha256=meta.fingerprint_sha256,
                public_key_algorithm=meta.public_key_algorithm,
                key_type=meta.key_type, key_size=meta.key_size,
                signature_algorithm=meta.signature_algorithm,
                valid_from=meta.valid_from, valid_until=meta.valid_until,
                status=_validity_status(meta.valid_until, threshold_days=settings.renewal_threshold_days),
                environment=settings.default_environment,
                provider_name="ct-log",
                imported=False,
                auto_renew=False,
                renewal_status=RenewalStatus.NONE.value,
                cert_path=str(store_dir / "cert.pem"),
                managed_by_platform=False,
            )
            db.add(certificate)
            db.flush()
            for idx, d in enumerate(certificate.sans):
                db.add(CertificateDomain(certificate_id=certificate.id, domain=d, is_primary=(idx == 0)))
            run.imported_count = (run.imported_count or 0) + 1
            logs.append(f"FOUND new cert via CT for {domain} ({certificate.fingerprint_sha256})")

    now = utcnow()
    db.add(CTObservation(
        certificate_id=certificate.id,
        crt_sh_id=crt_sh_id,
        matched_domain=domain,
        first_seen_at=now, last_seen_at=now,
        ct_monitor_run_id=run.id,
    ))

    detections = ct_monitor.run_detections(
        certificate.issuer, matched_name, is_new=is_new,
        expected_issuers=expected_issuers, sensitive_keywords=sensitive_keywords,
        staging_keywords=staging_keywords,
    )
    if not detections:
        return

    score = ct_monitor.risk_score_for(detections)
    severity = ct_monitor.risk_severity(score)

    # One correlated finding per certificate, not one per detection/scan —
    # only terminal-status findings (false_positive/resolved) get a fresh
    # replacement; an active one (open/acknowledged/investigating) just gets
    # its evidence refreshed, status untouched (never silently reopen work
    # an analyst is already engaged with).
    active_finding = (
        db.query(CTFinding)
        .filter(
            CTFinding.certificate_id == certificate.id,
            CTFinding.status.in_([
                FindingStatus.OPEN.value, FindingStatus.ACKNOWLEDGED.value, FindingStatus.INVESTIGATING.value,
            ]),
        )
        .order_by(CTFinding.id.desc())
        .first()
    )
    if active_finding is not None:
        active_finding.last_seen_at = now
        active_finding.detections = detections
        active_finding.risk_score = score
        active_finding.severity = severity
        active_finding.ct_monitor_run_id = run.id
    else:
        db.add(CTFinding(
            certificate_id=certificate.id,
            domain=matched_name,
            match_type=match_type,
            detections=detections,
            risk_score=score,
            severity=severity,
            status=FindingStatus.OPEN.value,
            first_seen_at=now, last_seen_at=now,
            ct_monitor_run_id=run.id,
        ))
        logs.append(
            f"FINDING {severity.upper()} for {matched_name} (score={score}): "
            f"{', '.join(d['code'] for d in detections)}"
        )


def _walk(root: Path, run: DiscoveryRun, db: Session, seen: set[str], logs: list[str]) -> int:
    """Recursively scan; returns number of certificate files found."""
    found = 0
    key_candidates: dict[str, Path] = {}
    cert_files: list[Path] = []

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        try:
            if path.suffix.lower() in _PFX_EXTS:
                found += 1
                _maybe_import_pfx(db, path, run, seen, logs)
            elif path.suffix.lower() in _CERT_EXTS:
                if _looks_like_private_key(path):
                    key_candidates[path.stem] = path
                    continue
                cert_files.append(path)
                found += 1
        except Exception as exc:  # noqa: BLE001
            logs.append(f"ERR scanning {path}: {exc}")

    for cert_file in cert_files:
        try:
            _maybe_import_cert(db, cert_file, key_candidates, run, seen, logs)
        except Exception as exc:  # noqa: BLE001
            logs.append(f"ERR importing {cert_file}: {exc}")
    return found


def _looks_like_private_key(path: Path) -> bool:
    try:
        head = path.read_bytes()[:200]
        return b"PRIVATE KEY" in head
    except OSError:
        return False


def _maybe_import_cert(db: Session, cert_file: Path, key_candidates: dict[str, Path],
                       run: DiscoveryRun, seen: set[str], logs: list[str]) -> None:
    try:
        data = cert_file.read_bytes()
        _, meta = parse_certificate(data)
    except Exception as exc:  # noqa: BLE001
        logs.append(f"SKIP unparseable {cert_file}: {exc}")
        return
    if meta.fingerprint_sha256 in seen:
        logs.append(f"SKIP duplicate {cert_file}")
        return

    key_path = key_candidates.get(cert_file.stem)
    if key_path is None:
        # try sibling privkey.key / privkey.pem
        for name in ("privkey.pem", "privkey.key", "key.pem"):
            cand = cert_file.parent / name
            if cand.exists():
                key_path = cand
                break

    try:
        import_from_paths(
            db,
            cert_path=str(cert_file),
            key_path=str(key_path) if key_path else None,
            payload={"environment": "production", "auto_renew": False},
        )
        seen.add(meta.fingerprint_sha256)
        run.imported_count = (run.imported_count or 0) + 1
        logs.append(f"IMPORTED {cert_file}")
    except Exception as exc:  # noqa: BLE001
        run.skipped_count = (run.skipped_count or 0) + 1
        logs.append(f"SKIP {cert_file}: {exc}")


def _maybe_import_pfx(db: Session, path: Path, run: DiscoveryRun, seen: set[str],
                      logs: list[str]) -> None:
    from cryptography.hazmat.primitives import hashes

    try:
        cert, key, _ = parse_pfx(path.read_bytes(), "")
        fingerprint = cert.fingerprint(hashes.SHA256()).hex().upper()
        fingerprint = ":".join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2))
        if fingerprint in seen:
            logs.append(f"SKIP duplicate pfx {path}")
            return
        from app.services.certificate_service import import_certificate

        import_certificate(
            db, pfx_data=path.read_bytes(), pfx_password="",
            payload={"environment": "production"},
        )
        seen.add(fingerprint)
        run.imported_count = (run.imported_count or 0) + 1
        logs.append(f"IMPORTED {path}")
    except Exception as exc:  # noqa: BLE001
        run.skipped_count = (run.skipped_count or 0) + 1
        logs.append(f"SKIP pfx {path}: {exc}")
