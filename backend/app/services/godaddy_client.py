"""Thin client for GoDaddy's Certificates API — used only to pull an
already-issued certificate into CertMgr's inventory (see
app/services/godaddy_service.py). GoDaddy's API does not support ACME-style
automated issuance; new/renewed certificates still go through GoDaddy's own
portal, this only ever reads what's already there.

Confirmed against GoDaddy's own API (2026-08): GET /v1/certificates?domain=
exists but its `domain` filter does not reliably narrow results to that
domain in practice — it may return the whole account's certificates
regardless of the query. Callers must not trust the API's own filtering and
should verify the returned commonName/subjectAlternativeNames themselves
(see godaddy_service._find_certificate_id).
"""

from __future__ import annotations

import httpx

from app.core.exceptions import ValidationAppError
from app.core.logging import get_logger

logger = get_logger(__name__)

_BASE_URL = "https://api.godaddy.com"
_TIMEOUT = 30.0


class GoDaddyError(Exception):
    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class GoDaddyClient:
    def __init__(self, api_key: str, api_secret: str) -> None:
        if not api_key or not api_secret:
            raise ValidationAppError(
                "GoDaddy API key/secret are not configured — set godaddy.api_key "
                "and godaddy.api_secret in Settings first."
            )
        self._headers = {
            "Authorization": f"sso-key {api_key}:{api_secret}",
            "Accept": "application/json",
        }

    def _get(self, path: str, *, params: dict | None = None) -> httpx.Response:
        try:
            resp = httpx.get(f"{_BASE_URL}{path}", headers=self._headers, params=params, timeout=_TIMEOUT)
        except httpx.HTTPError as exc:
            raise GoDaddyError(f"Could not reach GoDaddy API: {exc}") from exc
        if resp.status_code >= 400:
            raise GoDaddyError(
                f"GoDaddy API returned {resp.status_code} for {path}: {resp.text[:500]}",
                status_code=resp.status_code,
            )
        return resp

    def list_certificates(self, *, domain: str | None = None) -> list[dict]:
        """Best-effort — see the module docstring; do not trust this to
        already be filtered to `domain`, callers must re-check themselves."""
        params = {"domain": domain} if domain else None
        data = self._get("/v1/certificates", params=params).json()
        return data if isinstance(data, list) else data.get("certificates", [])

    def get_certificate(self, certificate_id: str) -> dict:
        return self._get(f"/v1/certificates/{certificate_id}").json()

    def download_certificate(self, certificate_id: str) -> dict:
        """Returns the GoDaddy download response: {"serialNumber", "certificateThumbprint",
        "pems": {"certificate", "intermediate", "root", "cross"}}. No private key —
        GoDaddy never holds it (issued from a CSR the customer generated)."""
        return self._get(f"/v1/certificates/{certificate_id}/download").json()
