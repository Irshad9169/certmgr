"""Local certificate verification (no provider required).

Used for imported certificates and as a fallback when a provider plugin is
unavailable — verifies SAN coverage, validity window and basic integrity.
"""

from __future__ import annotations

from pathlib import Path

from app.core.timeutils import ensure_aware, utcnow
from app.services.x509_utils import parse_certificate


def verify_local(cert_path: str | None, domains: list[str]) -> tuple[bool, str]:
    if not cert_path or not Path(cert_path).exists():
        return False, "Certificate file missing"

    try:
        cert, meta = parse_certificate(Path(cert_path).read_bytes())
    except Exception as exc:  # noqa: BLE001
        return False, f"Cannot parse certificate: {exc}"

    # SAN coverage
    sans = {d.lstrip("*.") for d in meta.sans}
    missing = [d for d in domains if d.lstrip("*.") not in sans]
    if missing:
        return False, f"Certificate does not cover: {missing}"

    # Validity window
    now = utcnow()
    if meta.valid_from and ensure_aware(meta.valid_from) > now:
        return False, "Certificate is not yet valid"
    if meta.valid_until and ensure_aware(meta.valid_until) < now:
        return False, "Certificate is expired"

    return True, "Certificate covers all domains and is within its validity window"


def verify_certificate(db, certificate_id: int) -> dict:
    """Verify a certificate using its provider or the local verifier."""
    from app.services.certificate_service import get_certificate
    from app.services.providers.registry import get_registry

    cert = get_certificate(db, certificate_id, load_relations=False)
    domains = [cert.domain] + [d for d in cert.sans if d != cert.domain]
    try:
        provider = get_registry().create(cert.provider_name)
        ok, message = provider.verify(cert.cert_path, domains)
    except KeyError:
        ok, message = verify_local(cert.cert_path, domains)
    return {"certificate_id": cert.id, "ok": ok, "message": message, "domains": domains}
