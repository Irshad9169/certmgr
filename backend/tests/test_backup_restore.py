"""Backup restore + verification tests — real archives, encrypted keys at rest."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from conftest import _generate_self_signed  # noqa: F401

from app.core.config import settings
from app.core.exceptions import ConflictError, ValidationAppError
from app.models.certificate import Certificate
from app.services import storage
from app.services.backup_service import (
    backup_certificate,
    restore_certificate,
    verify_backup_archives,
)
from app.services.certificate_service import import_certificate


def _seed_cert(db):
    cert, cert_pem, key_pem = _generate_self_signed(["restore.example.com", "www.restore.example.com"])
    imported = import_certificate(db, cert_data=cert_pem, key_data=key_pem)
    return imported, cert_pem, key_pem


def test_backup_then_verify(db):
    cert, _, _ = _seed_cert(db)
    row = backup_certificate(db, cert)
    assert Path(row.storage_path).exists()
    assert row.checksum_sha256
    result = verify_backup_archives(db)
    assert result["ok"] is True
    assert result["archives_verified"] >= 1
    assert result["archives_failed"] == 0


def test_verify_detects_corrupt_archive(db, storage_root):
    # A file that is not a valid gzip/tar must be flagged
    backup_root = Path(settings.backup_root_path) / "certificates"
    backup_root.mkdir(parents=True, exist_ok=True)
    corrupt = backup_root / "corrupt.tar.gz"
    corrupt.write_bytes(b"this is not a real archive")
    result = verify_backup_archives(db)
    assert result["archives_failed"] >= 1
    assert any("corrupt.tar.gz" in e for e in result["errors"])
    corrupt.unlink()


def test_restore_into_existing_certificate(db):
    cert, cert_pem, key_pem = _seed_cert(db)
    row = backup_certificate(db, cert)
    store = storage.get_file_store()
    # Simulate lost material: remove files + null the paths
    store.delete_cert_material(cert.fingerprint_sha256)
    cert.cert_path = cert.key_path = cert.chain_path = cert.fullchain_path = None
    db.commit()

    result = restore_certificate(db, row.storage_path, certificate_id=cert.id)
    assert result["restored"] is True
    assert result["certificate_id"] == cert.id

    db.refresh(cert)
    assert cert.cert_path and os.path.exists(cert.cert_path)
    assert cert.key_path and os.path.exists(cert.key_path)
    # Key must still be encrypted at rest and decryptable
    raw = Path(cert.key_path).read_text()
    assert "BEGIN PRIVATE KEY" not in raw
    assert "BEGIN PRIVATE KEY" in store.read_private_key(cert.key_path)
    # Backup row marked restored
    db.refresh(row)
    assert row.restored_at is not None


def test_restore_dry_run_does_not_write(db):
    cert, _, _ = _seed_cert(db)
    row = backup_certificate(db, cert)
    result = restore_certificate(db, row.storage_path, certificate_id=cert.id, dry_run=True)
    assert result["dry_run"] is True
    db.refresh(cert)
    assert "cert_path" in result["members"]


def test_restore_creates_new_row_when_missing(db):
    cert, cert_pem, key_pem = _seed_cert(db)
    row = backup_certificate(db, cert)
    # Delete the certificate row entirely
    db.delete(cert)
    db.commit()

    result = restore_certificate(db, row.storage_path)
    assert result["restored"] is True
    assert result["certificate_id"] is not None
    restored = db.query(Certificate).filter(Certificate.id == result["certificate_id"]).first()
    assert restored.fingerprint_sha256 == cert.fingerprint_sha256
    assert restored.key_path and os.path.exists(restored.key_path)


def test_restore_rejects_fingerprint_mismatch(db):
    cert, _, _ = _seed_cert(db)
    row = backup_certificate(db, cert)
    other, other_pem, other_key = _generate_self_signed(["other.example.com"])
    other_cert = import_certificate(db, cert_data=other_pem, key_data=other_key)
    with pytest.raises(ConflictError):
        restore_certificate(db, row.storage_path, certificate_id=other_cert.id)


def test_restore_rejects_missing_archive(db):
    from app.core.exceptions import NotFoundError

    with pytest.raises(NotFoundError):
        restore_certificate(db, "/nonexistent/backup.tar.gz")


def test_restore_rejects_non_archive(db):
    with pytest.raises(ValidationAppError):
        restore_certificate(db, __file__)  # a .py file is not a gzip archive
