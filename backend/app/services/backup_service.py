"""Automated backups: certificate material + database dump, restore + verify."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tarfile
from datetime import timedelta
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import ConflictError, NotFoundError, ValidationAppError
from app.core.logging import get_logger
from app.core.security import decrypt_secret
from app.core.timeutils import utcnow
from app.models.certificate import Backup, Certificate
from app.models.enums import AuditResult, BackupKind

logger = get_logger(__name__)

# Archive members created by backup_certificate()
_ARCHIVE_MEMBER_KEYS = ("cert_path", "key_path", "chain_path", "fullchain_path", "pfx_path")


def _read_archive_safely(archive_path: Path) -> dict[str, bytes]:
    """Read archive members into memory, sanitizing names (no extractall —
    defends against path-traversal archives). Returns {key: content}."""
    if not archive_path.exists():
        raise NotFoundError(f"Backup archive not found: {archive_path}")
    try:
        tar = tarfile.open(archive_path, "r:gz")
    except (tarfile.TarError, OSError) as exc:
        raise ValidationAppError(f"Corrupt or unreadable backup archive: {exc}") from exc

    members: dict[str, bytes] = {}
    with tar:
        for m in tar.getmembers():
            if not m.isfile():
                continue
            name = Path(m.name).name  # strip any directory components
            if not name.endswith(".bin"):
                continue
            key = name[:-4]  # "cert_path" from "cert_path.bin"
            if key not in _ARCHIVE_MEMBER_KEYS:
                continue
            fh = tar.extractfile(m)
            members[key] = fh.read() if fh else b""
    if "cert_path" not in members:
        raise ValidationAppError("Archive does not contain a certificate member (cert_path.bin)")
    return members


def backup_certificate(db: Session, cert: Certificate) -> Backup | None:
    """Copy a certificate's material (encrypted keys) into the backup root.

    Returns None (and creates nothing) when the certificate has no material on
    disk (e.g. failed/revoked certs) — we never create empty archives.
    """
    import tarfile

    has_material = False
    for attr in _ARCHIVE_MEMBER_KEYS:
        path = getattr(cert, attr)
        if path and Path(path).exists():
            has_material = True
            break
    if not has_material:
        logger.info("Skipping backup for cert %s — no material on disk", cert.id)
        return None

    backup_root = settings.backup_root_path / "certificates" / str(cert.id)
    backup_root.mkdir(parents=True, exist_ok=True)
    stamp = utcnow().strftime("%Y%m%d%H%M%S")
    archive = backup_root / f"cert-{cert.id}-{stamp}.tar.gz"

    with tarfile.open(archive, "w:gz") as tar:
        for attr in _ARCHIVE_MEMBER_KEYS:
            path = getattr(cert, attr)
            if path and Path(path).exists():
                tar.add(path, arcname=f"{attr}.bin")

    row = Backup(
        certificate_id=cert.id,
        kind=BackupKind.CERTIFICATE.value,
        storage_path=str(archive),
        size_bytes=archive.stat().st_size,
        checksum_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
        backup_metadata={"domain": cert.domain, "fingerprint": cert.fingerprint_sha256},
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def backup_all(db: Session) -> dict[str, int]:
    count = 0
    skipped = 0
    for cert in db.query(Certificate).all():
        try:
            row = backup_certificate(db, cert)
            if row is None:
                skipped += 1
            else:
                count += 1
        except Exception as exc:  # noqa: BLE001
            logger.warning("Backup failed for cert %s: %s", cert.id, exc)
    return {"backed_up": count, "skipped_no_material": skipped}


def backup_database() -> Path:
    """pg_dump (PostgreSQL), mysqldump (MariaDB/MySQL), or sqlite file copy."""
    db_url = settings.database_url
    backup_root = settings.backup_root_path / "database"
    backup_root.mkdir(parents=True, exist_ok=True)
    stamp = utcnow().strftime("%Y%m%d%H%M%S")
    target = backup_root / f"db-{stamp}.dump"

    if db_url.startswith("postgresql"):
        # URL: postgresql://user:pass@host:port/dbname
        m = re.match(r"postgresql(?:\+psycopg)?://([^:]+):([^@]+)@([^:/]+):(\d+)/(\w+)", db_url)
        if m:
            user, password, host, port, dbname = m.groups()
            env = {**os.environ, "PGPASSWORD": password}
            proc = subprocess.run(  # noqa: S603 — fixed argv, no shell
                [settings.pg_dump_binary, "-h", host, "-p", port, "-U", user, "-Fc", "-f", str(target), dbname],
                env=env, capture_output=True, text=True,
            )
            if proc.returncode != 0:
                raise RuntimeError(f"pg_dump failed: {proc.stderr[-500:]}")
            return target

    if db_url.startswith(("mysql", "mariadb")):
        # URL: mysql+pymysql://user:pass@host[:port]/dbname
        m = re.match(r"(?:mysql|mariadb)(?:\+pymysql)?://([^:]+):([^@]+)@([^:/]+)(?::(\d+))?/(\w+)", db_url)
        if m:
            user, password, host, port, dbname = m.groups()
            env = {**os.environ, "MYSQL_PWD": password}
            with open(target, "wb") as out:
                proc = subprocess.run(  # noqa: S603 — fixed argv, no shell
                    [settings.mysqldump_binary, "-h", host, "-P", port or "3306", "-u", user,
                     "--single-transaction", "--routines", "--triggers", dbname],
                    stdout=out, stderr=subprocess.PIPE, text=True, env=env,
                )
            if proc.returncode != 0:
                raise RuntimeError(f"mysqldump failed: {proc.stderr[-500:]}")
            return target

    if db_url.startswith("sqlite:///"):
        db_file = db_url.replace("sqlite:///", "", 1)
        if Path(db_file).exists():
            shutil.copy2(db_file, target)
            return target

    raise RuntimeError("Database backup not supported for this DATABASE_URL")


def cleanup_old_backups(db: Session) -> int:
    cutoff = utcnow() - timedelta(days=settings.backup_keep_days)
    rows = db.query(Backup).filter(Backup.created_at < cutoff).all()
    removed = 0
    for row in rows:
        try:
            Path(row.storage_path).unlink(missing_ok=True)
        except OSError:
            pass
        db.delete(row)
        removed += 1
    db.commit()
    return removed


# ── Restore ─────────────────────────────────────────────────────────────────
def restore_certificate(
    db: Session,
    archive_path: str,
    *,
    certificate_id: int | None = None,
    dry_run: bool = False,
    restored_by: int | None = None,
) -> dict:
    """Restore certificate material from a backup archive.

    - `certificate_id` given  → restores into that row (fingerprint must match).
    - otherwise               → matches by fingerprint; if no row exists, a new
                                certificate row is created via the import path.
    Private keys stay encrypted at rest (the archive holds the Fernet blob).
    """
    from app.services import storage
    from app.services.audit_service import record
    from app.services.x509_utils import parse_certificate

    archive = Path(archive_path)
    members = _read_archive_safely(archive)
    _, meta = parse_certificate(members["cert_path"])

    # Locate the target row
    target: Certificate | None = None
    if certificate_id is not None:
        target = db.query(Certificate).filter(Certificate.id == certificate_id).first()
        if target is None:
            raise NotFoundError(f"Certificate {certificate_id} not found")
        if target.fingerprint_sha256 and target.fingerprint_sha256 != meta.fingerprint_sha256:
            raise ConflictError(
                "Fingerprint mismatch — this backup belongs to a different certificate"
            )
    else:
        target = (
            db.query(Certificate)
            .filter(Certificate.fingerprint_sha256 == meta.fingerprint_sha256)
            .first()
        )

    if dry_run:
        return {
            "dry_run": True,
            "archive": str(archive),
            "fingerprint": meta.fingerprint_sha256,
            "domain": meta.sans[0] if meta.sans else "unknown",
            "target": f"certificate #{target.id}" if target else "new certificate (will be imported)",
            "members": sorted(members),
        }

    store = storage.get_file_store()
    store_dir = store.cert_dir(meta.fingerprint_sha256)

    if target is None:
        # Create a new row via the import pipeline (re-validates everything).
        from app.services.certificate_service import import_certificate

        key_data: bytes | None = members.get("key_path")
        if key_data:
            # Archive holds the Fernet-encrypted blob — decrypt to PEM for import
            try:
                key_data = decrypt_secret(key_data.decode("utf-8")).encode("utf-8")
            except Exception:  # noqa: BLE001
                raise ValidationAppError(
                    "Cannot decrypt private key from archive (wrong master key?)"
                ) from None
        import_certificate(
            db,
            cert_data=members["cert_path"],
            key_data=key_data,
            chain_data=members.get("chain_path") or members.get("fullchain_path"),
            payload={"environment": "production", "notes": "Restored from backup"},
            trigger="system",
        )
        target = (
            db.query(Certificate)
            .filter(Certificate.fingerprint_sha256 == meta.fingerprint_sha256)
            .first()
        )
        action = "restored (new row imported)"
    else:
        # Write material back into the existing certificate's store directory.
        (store_dir / "cert.pem").write_bytes(members["cert_path"])
        target.cert_path = str(store_dir / "cert.pem")
        if "key_path" in members:
            (store_dir / "privkey.enc.pem").write_bytes(members["key_path"])
            target.key_path = str(store_dir / "privkey.enc.pem")
        if "chain_path" in members:
            (store_dir / "chain.pem").write_bytes(members["chain_path"])
            target.chain_path = str(store_dir / "chain.pem")
        if "fullchain_path" in members:
            (store_dir / "fullchain.pem").write_bytes(members["fullchain_path"])
            target.fullchain_path = str(store_dir / "fullchain.pem")
        if "pfx_path" in members:
            (store_dir / "bundle.pfx").write_bytes(members["pfx_path"])
            target.pfx_path = str(store_dir / "bundle.pfx")
        # Refresh x.509 metadata from the restored certificate
        target.fingerprint_sha256 = meta.fingerprint_sha256
        target.subject = meta.subject
        target.issuer = meta.issuer
        target.serial_number = meta.serial_number
        target.valid_from = meta.valid_from
        target.valid_until = meta.valid_until
        target.sans = meta.sans or target.sans
        action = "restored into existing certificate"

    # Mark the backup row as restored
    backup_row = db.query(Backup).filter(Backup.storage_path == str(archive)).first()
    if backup_row:
        backup_row.restored_at = utcnow()

    record(
        db, action="backup.restore", resource_type="certificate",
        resource_id=target.id if target else None,
        result=AuditResult.SUCCESS,
        details={"archive": str(archive), "fingerprint": meta.fingerprint_sha256},
        user_id=restored_by,
    )
    db.commit()
    return {
        "restored": True,
        "action": action,
        "certificate_id": target.id if target else None,
        "domain": meta.sans[0] if meta.sans else "unknown",
        "fingerprint": meta.fingerprint_sha256,
        "key_restored": "key_path" in members,
    }


# ── Verify ──────────────────────────────────────────────────────────────────
def _verify_database_dump(path: Path) -> tuple[bool, str]:
    """Best-effort integrity check of a database dump, by content detection."""
    try:
        head = path.read_bytes()[:16]
        if head.startswith(b"SQLite format 3"):
            import sqlite3

            conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            try:
                result = conn.execute("PRAGMA integrity_check").fetchone()
                ok = result and result[0] == "ok"
                return ok, "sqlite integrity_check" if ok else f"sqlite check: {result}"
            finally:
                conn.close()
        if head.startswith(b"PGDMP"):
            pg_restore = shutil.which("pg_restore")
            if pg_restore:
                proc = subprocess.run(  # noqa: S603 — fixed argv, no shell
                    [pg_restore, "--list", str(path)], capture_output=True, text=True,
                )
                ok = proc.returncode == 0
                return ok, "pg_restore --list" if ok else f"pg_restore: {proc.stderr[-200:]}"
            return True, "pg custom-format dump (pg_restore not installed — skipped)"
        # assume plain SQL (mysqldump / pg_dump plain)
        text = path.read_text(errors="replace")[:2000]
        if "CREATE TABLE" in text or "DROP TABLE" in text or text.strip():
            return True, "SQL text dump looks valid"
        return False, "empty dump"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def verify_backup_archives(db: Session, *, sample_only: bool = False,
                           check_checksums: bool = True) -> dict:
    """Verify every (or a sample of) certificate backup archives + DB dumps.

    Used by the weekly backup-verification timer / Celery task. Detects corrupt
    archives, missing members and checksum drift.
    """
    certs_dir = settings.backup_root_path / "certificates"
    db_dir = settings.backup_root_path / "database"

    archives = sorted(certs_dir.rglob("*.tar.gz"))
    sample = archives[: max(1, len(archives) // 10 + 1)] if sample_only and len(archives) > 5 else archives

    verified = failed = skipped = 0
    errors: list[str] = []
    for archive in sample:
        try:
            members = _read_archive_safely(archive)
            if "cert_path" not in members:
                raise ValueError("missing cert_path.bin member")
            if check_checksums:
                row = db.query(Backup).filter(Backup.storage_path == str(archive)).first()
                if row and row.checksum_sha256:
                    actual = hashlib.sha256(archive.read_bytes()).hexdigest()
                    if actual != row.checksum_sha256:
                        raise ValueError("checksum mismatch with DB record")
            verified += 1
        except Exception as exc:  # noqa: BLE001
            failed += 1
            errors.append(f"{archive.name}: {exc}")

    db_verified = db_failed = 0
    db_errors: list[str] = []
    for dump in sorted(db_dir.glob("db-*.dump")) if db_dir.exists() else []:
        ok, note = _verify_database_dump(dump)
        if ok:
            db_verified += 1
        else:
            db_failed += 1
            db_errors.append(f"{dump.name}: {note}")

    summary = {
        "checked_at": utcnow().isoformat(),
        "sample_only": sample_only,
        "archives_total": len(archives),
        "archives_checked": len(sample),
        "archives_verified": verified,
        "archives_failed": failed,
        "archives_skipped": skipped,
        "errors": errors[:20],
        "database_dumps_total": len(list(db_dir.glob("db-*.dump"))) if db_dir.exists() else 0,
        "database_dumps_verified": db_verified,
        "database_dumps_failed": db_failed,
        "database_errors": db_errors[:10],
        "ok": failed == 0 and db_failed == 0,
    }
    if failed or db_failed:
        logger.error("Backup verification found problems: %s", errors[:5] + db_errors[:5])
    else:
        logger.info(
            "Backup verification OK: %s archives, %s db dumps",
            verified, db_verified,
            extra={"event": "backup_verify", "archives": verified, "dumps": db_verified},
        )
    return summary
