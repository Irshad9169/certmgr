"""Automatic certificate discovery.

Scans configurable directories for PEM/DER/PKCS12 files, extracts metadata,
matches private keys to certificates, and imports new discoveries.
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.core.timeutils import utcnow
from app.models.certificate import Certificate
from app.models.enums import AuditResult, JobStatus, JobTrigger, JobType
from app.models.job import DiscoveryRun, JobExecution
from app.services.audit_service import record
from app.services.certificate_service import import_from_paths
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


def _paths_from_settings(extra: list[str] | None = None) -> list[str]:
    paths = list(settings_scan_paths())
    for p in extra or []:
        if p not in paths:
            paths.append(p)
    return paths


def settings_scan_paths() -> list[str]:
    """Scan paths from app settings (admin configurable), else defaults."""
    from app.services.settings_service import get_setting

    try:
        raw = get_setting("discovery.scan_paths")
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
        scan_paths=_paths_from_settings(extra_paths),
        created_by=created_by,
    )
    db.add(run)
    db.commit()

    logs: list[str] = []
    found = imported = skipped = 0
    seen_fingerprints = {c.fingerprint_sha256 for c in db.query(Certificate).all() if c.fingerprint_sha256}

    for base in run.scan_paths:
        root = Path(base)
        if not root.exists():
            logs.append(f"SKIP (missing): {base}")
            continue
        found += _walk(root, run, db, seen_fingerprints, logs)

    # post-pass: count
    run.found_count = found
    run.imported_count = imported if imported else _count_imported(db, run)
    run.skipped_count = skipped if skipped else _count_skipped(db, run)
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


def _count_imported(db, run) -> int:
    return 0


def _count_skipped(db, run) -> int:
    return 0


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
