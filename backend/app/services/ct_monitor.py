"""Certificate Transparency monitoring — pure functions, no database access.

Queries crt.sh (a free, public CT log aggregator — no API key) for
certificates issued for admin-configured domains, classifies domain matches,
and runs a small set of deterministic detections. This is a different
question from the network TLS scanner: that one finds what's actually
*reachable*; this one finds what's been *issued*, including a certificate
that was never deployed anywhere (e.g. a mis-issued/rogue certificate for
your domain from a CA you never used).

Deliberately NOT implemented here (see docs/architecture-notes on this
feature): lookalike/typosquat domain detection doesn't fit this ingestion
method at all — crt.sh's `q=` search is a substring match, so a lookalike
like `examp1e.com` can never appear in results for a search on
`example.com` in the first place. Real lookalike detection needs a
different technique (generate permutations, query each one), not something
this substring search can produce as a side effect.
"""

from __future__ import annotations

import httpx

from app.core.logging import get_logger
from app.models.enums import FindingSeverity
from app.services.x509_utils import CertificateMetadata

logger = get_logger(__name__)

_CRTSH_BASE = "https://crt.sh/"
_DEFAULT_TIMEOUT = 15.0


def fetch_crtsh_entries(domain: str, *, limit: int, timeout: float = _DEFAULT_TIMEOUT) -> list[dict]:
    """Query crt.sh for a domain. Returns [] on any failure — crt.sh is a
    community service with no contracted SLA; a slow/down crt.sh must not
    fail the whole scan, just skip that domain for this run."""
    try:
        resp = httpx.get(_CRTSH_BASE, params={"q": domain, "output": "json"}, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("crt.sh query failed for %s: %s", domain, exc)
        return []
    if not isinstance(data, list):
        return []
    return data[:limit]


def fetch_crtsh_certificate_pem(crt_sh_id: int, *, timeout: float = _DEFAULT_TIMEOUT) -> bytes | None:
    """Fetch the raw PEM for one crt.sh entry. Only worth calling for entries
    not already recorded (see discovery_service.run_ct_monitor) — this is the
    expensive path, bounded to genuinely new discoveries."""
    try:
        resp = httpx.get(_CRTSH_BASE, params={"d": crt_sh_id}, timeout=timeout)
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        logger.warning("crt.sh certificate fetch failed for id=%s: %s", crt_sh_id, exc)
        return None
    return resp.content


def classify_domain_match(name: str, monitored_domains: list[str]) -> str:
    """exact / subdomain / wildcard / unrelated."""
    n = (name or "").strip().lower().rstrip(".")
    is_wildcard = n.startswith("*.")
    base = n[2:] if is_wildcard else n
    for md in monitored_domains:
        m = (md or "").strip().lower().rstrip(".")
        if not m:
            continue
        if base == m:
            return "wildcard" if is_wildcard else "exact"
        if base.endswith(f".{m}"):
            return "wildcard" if is_wildcard else "subdomain"
    return "unrelated"


def run_detections(
    meta: CertificateMetadata,
    matched_name: str,
    *,
    is_new: bool,
    expected_issuers: list[str],
    sensitive_keywords: list[str],
    staging_keywords: list[str],
) -> list[dict]:
    """Returns triggered {code, weight, reason} entries. Order is
    significant only for display; risk is summed across all of them."""
    detections: list[dict] = []

    if is_new:
        detections.append({
            "code": "NEW_CERTIFICATE", "weight": 10,
            "reason": "First time this certificate has been observed",
        })

    expected = [e.strip() for e in expected_issuers if e.strip()]
    if expected:
        issuer_lower = (meta.issuer or "").lower()
        if not any(exp.lower() in issuer_lower for exp in expected):
            detections.append({
                "code": "UNKNOWN_CA", "weight": 25,
                "reason": f"Issuer not in expected list: {meta.issuer or 'unknown'}",
            })

    name_lower = (matched_name or "").lower()
    for kw in sensitive_keywords:
        k = kw.strip().lower()
        if k and k in name_lower:
            detections.append({
                "code": "SENSITIVE_HOSTNAME", "weight": 20,
                "reason": f"Hostname contains sensitive keyword: {kw.strip()}",
            })
            break
    for kw in staging_keywords:
        k = kw.strip().lower()
        if k and k in name_lower:
            detections.append({
                "code": "STAGING_HOSTNAME", "weight": 15,
                "reason": f"Hostname contains staging/test keyword: {kw.strip()}",
            })
            break

    return detections


def risk_score_for(detections: list[dict]) -> int:
    return min(100, sum(d["weight"] for d in detections))


def risk_severity(score: int) -> str:
    if score >= 90:
        return FindingSeverity.CRITICAL.value
    if score >= 75:
        return FindingSeverity.HIGH.value
    if score >= 50:
        return FindingSeverity.MEDIUM.value
    if score >= 25:
        return FindingSeverity.LOW.value
    return FindingSeverity.INFORMATIONAL.value
