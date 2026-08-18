"""Fetch an already-issued certificate from a GoDaddy account and import it
into CertMgr's inventory — no new issuance/renewal, GoDaddy's API doesn't
support that the way Let's Encrypt's ACME does. See godaddy_client.py for
the raw API calls this builds on."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError, ValidationAppError
from app.core.logging import get_logger
from app.models.user import User
from app.services.certificate_service import import_certificate
from app.services.godaddy_client import GoDaddyClient, GoDaddyError
from app.services.settings_service import get_setting

logger = get_logger(__name__)

# GoDaddy's own ?domain= filter does not reliably narrow results (confirmed
# against the live API — a query for one domain returned certificates for
# unrelated domains on the same account). Every candidate is re-checked here
# against its actual commonName/SANs before being considered a match.
_LIVE_STATUSES = {"ISSUED"}


def _client(db: Session) -> GoDaddyClient:
    api_key = get_setting(db, "godaddy.api_key")
    api_secret = get_setting(db, "godaddy.api_secret")
    return GoDaddyClient(api_key or "", api_secret or "")


def _domain_matches(domain: str, cert: dict) -> bool:
    domain = domain.lower().rstrip(".")
    names = {str(cert.get("commonName") or "").lower().rstrip(".")}
    for san in cert.get("subjectAlternativeNames") or []:
        name = san.get("subjectAlternativeName") if isinstance(san, dict) else san
        if name:
            names.add(str(name).lower().rstrip("."))
    return domain in names


def _find_certificate_id(db: Session, domain: str) -> str:
    client = _client(db)
    try:
        candidates = client.list_certificates(domain=domain)
    except GoDaddyError as exc:
        raise ValidationAppError(f"GoDaddy lookup failed: {exc}") from exc

    matches = [c for c in candidates if _domain_matches(domain, c)]
    if not matches:
        raise NotFoundError(
            f"No GoDaddy certificate found for {domain} — GoDaddy's own domain filter is "
            "unreliable, so this checked every returned certificate's commonName/SANs "
            "directly. If you know the exact certificateId from your GoDaddy account, "
            "use that instead of a domain search."
        )

    # Prefer a currently-issued, non-revoked cert; among those, the most
    # recently valid one. Falls back to the most recent overall if none are
    # live (e.g. only historical/revoked entries exist for this domain).
    live = [c for c in matches if c.get("certificateStatus") in _LIVE_STATUSES and not c.get("revokedAt")]
    pool = live or matches
    best = max(pool, key=lambda c: c.get("validEnd") or "")
    return best["certificateId"]


def fetch_certificate_from_godaddy(
    db: Session, *, domain: str | None = None, certificate_id: str | None = None,
    environment: str = "production", auto_renew: bool = False, user: User | None = None,
) -> dict[str, Any]:
    """Downloads the certificate (+ chain) from GoDaddy and imports it via
    the same import_certificate() path a manual PEM upload would use."""
    if bool(domain) == bool(certificate_id):
        raise ValidationAppError("Provide exactly one of domain or certificate_id")

    client = _client(db)
    resolved_id = certificate_id or _find_certificate_id(db, domain)  # type: ignore[arg-type]

    try:
        bundle = client.download_certificate(resolved_id)
    except GoDaddyError as exc:
        raise ValidationAppError(f"GoDaddy download failed: {exc}") from exc

    pems = bundle.get("pems") or {}
    cert_pem = pems.get("certificate")
    if not cert_pem:
        raise ValidationAppError(f"GoDaddy returned no certificate for {resolved_id}")

    chain_parts = [p for p in (pems.get("intermediate"), pems.get("cross")) if p]
    chain_pem = "".join(chain_parts) if chain_parts else None

    cert = import_certificate(
        db,
        cert_data=cert_pem.encode(),
        chain_data=chain_pem.encode() if chain_pem else None,
        payload={"environment": environment, "provider": "godaddy", "auto_renew": auto_renew},
        user=user,
    )
    return {"certificate_id": cert.id, "domain": cert.domain, "godaddy_certificate_id": resolved_id}
