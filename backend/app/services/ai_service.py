"""AI-powered assistance (optional, off by default).

Two layers:
  1. Local heuristic engine — always available: parses Certbot failures into
     root causes, recommends fixes, summarizes renewal logs, detects recurring
     failures, predicts likely renewal failures. No external calls.
  2. Optional LLM enhancement (OpenAI/Anthropic-compatible) when
     CERTMGR_AI_ENABLED=1 — the heuristic context is sent for a polished
     explanation. If the call fails, we fall back to the local engine.
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import UTC
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.models.enums import JobStatus, JobType
from app.models.job import JobExecution

logger = get_logger(__name__)

# ── Known Certbot failure signatures → root cause + fix ─────────────────────
_KNOWN_FAILURES: list[tuple[re.Pattern, str, str, str]] = [
    (re.compile(r"DNS problem: NXDOMAIN", re.I), "dns_nxdomain",
     "DNS lookup failed for the validation domain",
     "Verify the DNS A/AAAA records for the domain; ensure public resolution and correct record at the "
     "authoritative nameserver, then retry."),
    (re.compile(r"DNS problem: SERVFAIL", re.I), "dns_servfail",
     "The authoritative nameserver returned SERVFAIL",
     "Check nameserver health and DNSSEC configuration; test with `dig @8.8.8.8`."),
    (re.compile(r"DNS problem: (?:looking up|expected) A/AAAA", re.I), "dns_no_a",
     "No A/AAAA record found for the validation domain",
     "Add the required DNS record (TXT for dns-01, A/AAAA for http-01) and allow propagation time."),
    (re.compile(r"Connection refused|Failed to connect to .*:80", re.I), "http_conn_refused",
     "The ACME HTTP challenge could not reach port 80",
     "Ensure port 80 is open in the firewall and something listens there (or use dns-01 validation)."),
    (re.compile(r"Timeout during connect|timed out", re.I), "network_timeout",
     "Network timeout contacting the ACME server or validation endpoint",
     "Check outbound connectivity to acme-v02.api.letsencrypt.org and inbound port 80/443."),
    (re.compile(r"Invalid response from http://.*/\\.well-known/acme-challenge", re.I), "http_bad_response",
     "The challenge token was not served at /.well-known/acme-challenge/",
     "Confirm the webroot path points at the served document root; check reverse-proxy config that "
     "forwards /.well-known/ to the correct backend."),
    (re.compile(r"too many certificates|rate limit", re.I), "rate_limited",
     "Let's Encrypt rate limit hit",
     "Check https://letsencrypt.org/docs/rate-limits/; use staging for testing, consolidate SANs, "
     "or wait for the rate limit window (5 certs/7 days for duplicates)."),
    (re.compile(r"unauthorized|Invalid email|account registration", re.I), "account_error",
     "ACME account registration/authorization problem",
     "Verify the contact email and that the account key is not corrupted; register a fresh account."),
    (re.compile(r"Could not bind TCP port 80|Permission denied.*:80", re.I), "standalone_bind",
     "Standalone mode could not bind port 80",
     "Stop the web server on port 80 during issuance or use webroot/http-01 with the running server."),
    (re.compile(r"No valid IP addresses found for", re.I), "no_ip",
     "No valid IP address found for the domain",
     "Create the DNS record before retrying."),
    (re.compile(r"hook command .* returned error", re.I), "hook_failed",
     "The auth/cleanup hook script exited non-zero",
     "Review hook execution logs; check hook path, permissions, environment variables and the "
     "execution user (hooks often need API credentials in env vars)."),
    (re.compile(r"challenge failed for .*? (?:dns|http)-01", re.I), "challenge_failed",
     "The validation challenge failed (generic)",
     "Use certbot --dry-run with `--debug-challenges` to inspect; verify DNS propagation via "
     "https://dnschecker.org before retrying."),
    (re.compile(r"Failed to parse|Unicode|Invalid domain|valueError", re.I), "invalid_input",
     "Invalid domain or certificate input",
     "Confirm domains are valid FQDNs without scheme or path components."),
    (re.compile(r"error during the second phase of the client", re.I), "client_error",
     "Certbot client error during finalization",
     "Run with --verbose and inspect the full log; check disk space and permissions under /etc/letsencrypt."),
    (re.compile(r"Max retries exceeded|Read timed out|ConnectTimeout", re.I), "acme_unreachable",
     "ACME server unreachable from this host",
     "Verify egress to acme-v02.api.letsencrypt.org:443 and corporate proxy settings."),
]


def _match_failure(stderr: str, stdout: str) -> tuple[str, str, str] | None:
    text = (stderr or "") + "\n" + (stdout or "")
    for pattern, code, cause, fix in _KNOWN_FAILURES:
        if pattern.search(text):
            return code, cause, fix
    if not text.strip():
        return "no_output", "No output captured from certbot", "Run a manual dry-run to capture output."
    return None


def explain_failure(db: Session, execution_id: int) -> dict[str, Any]:
    """Root-cause analysis for a failed execution (local engine)."""
    execution = db.query(JobExecution).filter(JobExecution.id == execution_id).first()
    if execution is None:
        return {"error": "execution not found"}

    match = _match_failure(execution.stderr or "", execution.stdout or "")
    if match is None:
        return {
            "execution_id": execution_id,
            "job_type": execution.job_type,
            "category": "unknown",
            "cause": "Failure does not match a known signature",
            "recommendation": "Review the raw log below; retry with --dry-run --verbose to isolate.",
            "confidence": 0.3,
            "raw_tail": (execution.stderr or execution.stdout or "")[-2000:],
        }
    code, cause, fix = match
    return {
        "execution_id": execution_id,
        "job_type": execution.job_type,
        "category": code,
        "cause": cause,
        "recommendation": fix,
        "confidence": 0.85,
        "raw_tail": (execution.stderr or execution.stdout or "")[-2000:],
    }


def summarize_renewal_logs(db: Session, certificate_id: int) -> dict[str, Any]:
    rows = (
        db.query(JobExecution)
        .filter(JobExecution.certificate_id == certificate_id,
                JobExecution.job_type.in_([JobType.RENEW.value, JobType.ISSUE.value]))
        .order_by(JobExecution.created_at.desc())
        .limit(10)
        .all()
    )
    outcomes = Counter(r.status for r in rows)
    last_error = next((r.error_message for r in rows if r.status == JobStatus.FAILED.value), None)
    match = _match_failure(last_error, "") if last_error else None
    return {
        "certificate_id": certificate_id,
        "executions_analyzed": len(rows),
        "outcomes": dict(outcomes),
        "last_failure": last_error,
        "recommendation": match[2] if match else "No recurring issues detected.",
        "summary": _summarize(rows),
    }


def _summarize(rows: list[JobExecution]) -> str:
    if not rows:
        return "No execution history available."
    recent = rows[0]
    if recent.status == JobStatus.SUCCESS.value:
        return f"Last run succeeded in {recent.execution_time_ms or '?'}ms."
    if recent.status == JobStatus.FAILED.value:
        return f"Last run failed: {(recent.error_message or 'unknown error')[:300]}"
    return f"Last run status: {recent.status}."


def detect_recurring_failures(db: Session, days: int = 30) -> list[dict[str, Any]]:
    from datetime import datetime, timedelta

    since = datetime.now(UTC) - timedelta(days=days)
    rows = (
        db.query(JobExecution)
        .filter(JobExecution.status == JobStatus.FAILED.value,
                JobExecution.created_at >= since)
        .all()
    )
    grouped: dict[str, dict[str, Any]] = {}
    for row in rows:
        match = _match_failure(row.stderr or "", row.stdout or "")
        category = match[0] if match else "unknown"
        key = f"{row.job_type}:{category}"
        entry = grouped.setdefault(key, {
            "job_type": row.job_type, "category": category,
            "count": 0, "certificate_ids": set(), "cause": match[1] if match else "Unknown",
            "recommendation": match[2] if match else "Inspect raw logs.",
        })
        entry["count"] += 1
        if row.certificate_id:
            entry["certificate_ids"].add(row.certificate_id)
    return [
        {**entry, "certificate_ids": sorted(entry["certificate_ids"])}
        for entry in sorted(grouped.values(), key=lambda e: -e["count"])
    ]


def predict_renewal_failures(db: Session) -> list[dict[str, Any]]:
    """Heuristic: certificates whose last 2 renewals failed + expiring soon."""
    from app.models.certificate import Certificate

    risky: list[dict[str, Any]] = []
    certs = db.query(Certificate).filter(Certificate.auto_renew.is_(True)).all()
    for cert in certs:
        failures = (
            db.query(JobExecution)
            .filter(JobExecution.certificate_id == cert.id,
                    JobExecution.job_type == JobType.RENEW.value,
                    JobExecution.status == JobStatus.FAILED.value)
            .count()
        )
        days = cert.days_remaining
        if failures >= 2 and days is not None and days <= 60:
            risky.append({
                "certificate_id": cert.id,
                "domain": cert.domain,
                "days_remaining": days,
                "recent_failures": failures,
                "risk": "high",
            })
    return risky


# ── Optional LLM enhancement ────────────────────────────────────────────────
def llm_enhance(context: dict[str, Any]) -> dict[str, Any] | None:
    if not settings.ai_enabled or not settings.ai_api_key:
        return None
    try:
        headers = {"Authorization": f"Bearer {settings.ai_api_key}", "Content-Type": "application/json"}
        url = settings.ai_base_url or "https://api.openai.com/v1/chat/completions"
        prompt = (
            "You are a PKI operations assistant. Based on this certificate-management "
            f"context, give a concise root-cause explanation and recommended fix:\n{context}"
        )
        resp = httpx.post(
            url,
            headers=headers,
            json={"model": settings.ai_model, "messages": [{"role": "user", "content": prompt}],
                  "max_tokens": 400},
            timeout=20,
        )
        if resp.status_code == 200:
            content = resp.json()["choices"][0]["message"]["content"]
            return {"llm_explanation": content}
    except Exception as exc:  # noqa: BLE001
        logger.warning("LLM enhancement failed: %s", exc)
    return None


def troubleshoot(db: Session, execution_id: int) -> dict[str, Any]:
    base = explain_failure(db, execution_id)
    if base.get("error"):
        return base
    enhanced = llm_enhance(base)
    if enhanced:
        base["enhanced"] = enhanced["llm_explanation"]
    base["suggestions"] = _suggestions(base.get("category", "unknown"))
    return base


def _suggestions(category: str) -> list[str]:
    table = {
        "dns_nxdomain": ["Check DNS records with `dig +short <domain>`", "Confirm the record at the authoritative NS"],
        "dns_servfail": ["Verify DNSSEC and NS health", "Try a public resolver"],
        "http_conn_refused": ["Open port 80", "Use dns-01 validation instead"],
        "rate_limited": ["Test against staging", "Merge SANs into one certificate"],
        "hook_failed": ["Inspect hook logs under /var/log/certmgr", "Test the hook manually with `--debug-challenges`"],
        "standalone_bind": ["Stop the service on :80 during issuance", "Use webroot mode"],
    }
    return table.get(category, ["Retry with `--dry-run --verbose` and inspect the full log."])
