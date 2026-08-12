"""Certificate file storage.

Private keys are ALWAYS encrypted at rest with the Fernet master key before
touching disk (encrypted-filesystem backend). Public material (certs/chains) is
stored plaintext but outside any web-accessible directory.

Supports: filesystem, encrypted-filesystem, NFS (same layout via mount).
Future: S3 object storage behind the same FileStore interface.
"""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

from app.core.config import settings
from app.core.domain_utils import safe_filename
from app.core.exceptions import ValidationAppError
from app.core.logging import get_logger
from app.core.security import decrypt_secret, encrypt_secret

logger = get_logger(__name__)

_PEM_KEY_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
)


class FileStore:
    """Stores certificate material under {storage_root}/{fingerprint}/."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = (root or settings.storage_root_path).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    # ── Paths ───────────────────────────────────────────────────────────────
    def cert_dir(self, fingerprint: str) -> Path:
        d = self.root / fingerprint.replace(":", "").lower()
        d.mkdir(parents=True, exist_ok=True)
        return d

    def key_path(self, fingerprint: str) -> Path:
        return self.cert_dir(fingerprint) / "privkey.enc.pem"

    def cert_path(self, fingerprint: str) -> Path:
        return self.cert_dir(fingerprint) / "cert.pem"

    def chain_path(self, fingerprint: str) -> Path:
        return self.cert_dir(fingerprint) / "chain.pem"

    def fullchain_path(self, fingerprint: str) -> Path:
        return self.cert_dir(fingerprint) / "fullchain.pem"

    def pfx_path(self, fingerprint: str) -> Path:
        return self.cert_dir(fingerprint) / "bundle.pfx"

    # ── Write helpers ───────────────────────────────────────────────────────
    @staticmethod
    def _is_key_blob(data: bytes) -> bool:
        return any(marker in data for marker in _PEM_KEY_MARKERS)

    def write_public(self, rel: str, data: bytes) -> str:
        """Write public material (cert/chain) — never keys through this."""
        if self._is_key_blob(data):
            raise ValidationAppError("Refusing to write private key as public material")
        path = self.root / safe_filename(rel)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return str(path)

    def write_private_key(self, fingerprint: str, pem_bytes: bytes) -> str:
        """Encrypt private key at rest and persist. Returns the encrypted path."""
        if not self._is_key_blob(pem_bytes):
            raise ValidationAppError("Not a recognized PEM private key")
        encrypted = encrypt_secret(pem_bytes.decode("utf-8"))
        target = self.key_path(fingerprint)
        target.write_text(encrypted, encoding="utf-8")
        try:
            target.chmod(0o600)
        except OSError:  # pragma: no cover
            pass
        return str(target)

    def read_private_key(self, key_path_str: str) -> str:
        """Decrypt and return the PEM private key text."""
        p = Path(key_path_str)
        if not p.exists():
            raise ValidationAppError("Private key file missing")
        try:
            return decrypt_secret(p.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            # Fallback: allow reading a plaintext key if the platform stored it
            # before encryption was enabled (migration path), never log content.
            content = p.read_text(encoding="utf-8")
            if self._is_key_blob(content.encode()):
                return content
            raise

    def has_private_key(self, key_path_str: str | None) -> bool:
        return bool(key_path_str) and Path(key_path_str).exists()

    # ── Bundles ─────────────────────────────────────────────────────────────
    def build_bundle(self, fingerprint: str, *, include_key: bool = True,
                     password: str = "") -> Path:
        """Assemble cert+key+chain into a PKCS12 bundle on disk."""
        from app.services.x509_utils import build_pfx

        cert_pem = self.cert_path(fingerprint).read_bytes()
        fullchain = self.fullchain_path(fingerprint).read_bytes() if self.fullchain_path(fingerprint).exists() else None
        key_pem = self.read_private_key(str(self.key_path(fingerprint))).encode() if include_key and self.has_private_key(str(self.key_path(fingerprint))) else None
        chain = self.chain_path(fingerprint).read_bytes() if self.chain_path(fingerprint).exists() else None

        if key_pem is None:
            raise ValidationAppError("No private key available for this certificate")

        pfx = build_pfx(cert_pem, key_pem, chain or fullchain, password=password)
        target = self.pfx_path(fingerprint)
        target.write_bytes(pfx)
        return target

    def export_zip(self, fingerprint: str, *, include_key: bool = True) -> bytes:
        """Zip bundle of cert / key / chain / fullchain / pfx for download."""
        import io
        import zipfile

        buf = io.BytesIO()
        d = self.cert_dir(fingerprint)
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            if self.cert_path(fingerprint).exists():
                zf.write(self.cert_path(fingerprint), "cert.pem")
            if self.fullchain_path(fingerprint).exists():
                zf.write(self.fullchain_path(fingerprint), "fullchain.pem")
            if self.chain_path(fingerprint).exists():
                zf.write(self.chain_path(fingerprint), "chain.pem")
            if include_key and self.has_private_key(str(self.key_path(fingerprint))):
                key_pem = self.read_private_key(str(self.key_path(fingerprint)))
                zf.writestr("privkey.pem", key_pem)
            pfx = d / "bundle.pfx"
            if pfx.exists():
                zf.write(pfx, "bundle.pfx")
        return buf.getvalue()

    def delete_cert_material(self, fingerprint: str) -> None:
        shutil.rmtree(self.cert_dir(fingerprint), ignore_errors=True)

    def checksum(self, path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()


_store: FileStore | None = None


def get_file_store() -> FileStore:
    global _store
    if _store is None:
        _store = FileStore()
    return _store
