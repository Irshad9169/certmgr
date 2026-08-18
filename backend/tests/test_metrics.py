"""Prometheus metrics: regression coverage for metrics that were defined
in app/core/metrics.py but never actually incremented/set anywhere —
certmgr_certbot_executions_total, certmgr_jobs_total,
certmgr_certificates_total, certmgr_certificate_days_to_expiry. The
Grafana dashboard (infra/grafana/dashboards/certmgr.json) has panels
querying all four; without this wiring those panels render permanently
empty.

Note: the test app is created with CERTMGR_PROMETHEUS_ENABLED=false (see
conftest.py), so /metrics isn't registered as a route in tests — these
exercise the underlying collectors/refresh function directly instead."""

from __future__ import annotations

from conftest import _generate_self_signed

from app.core.metrics import (
    CERTBOT_EXECUTIONS,
    CERTIFICATE_DAYS_TO_EXPIRY,
    CERTIFICATE_GAUGE,
    JOBS_TOTAL,
    refresh_certificate_gauges,
)
from app.services.certificate_service import (
    delete_certificate,
    import_certificate,
    issue_certificate,
    revoke_certificate,
)
from app.services.providers.base import IssueResult


def _counter_value(counter, **labels) -> float:
    return counter.labels(**labels)._value.get()  # noqa: SLF001 — test-only introspection


def _gauge_sample(gauge, **labels):
    """Read a Gauge's *current* sample for `labels` without the
    auto-vivification side effect of calling .labels(...) directly — that
    lazily creates the child (defaulting to 0.0) if it doesn't already
    exist, which would silently defeat a "was this cleared" assertion."""
    for metric in gauge.collect():
        for sample in metric.samples:
            if all(sample.labels.get(k) == v for k, v in labels.items()):
                return sample.value
    return None


def test_issue_increments_certbot_executions(db, admin_user, monkeypatch, tmp_path):
    """Mocks at the run_command level (not the provider's .issue()) so the
    real CertbotExecutor.execute() — where the metric actually lives —
    still runs."""
    import app.services.certbot as certbot_module
    from app.services.command import CommandResult

    def fake_run_command(argv, **kwargs):
        return CommandResult(argv=argv, returncode=0, stdout="ok", stderr="", duration_ms=5)

    monkeypatch.setattr(certbot_module, "run_command", fake_run_command)

    before = _counter_value(CERTBOT_EXECUTIONS, result="success")
    issue_certificate(
        db, payload={"domains": ["metrics-certbot.example.com"], "validation_method": "http-01",
                     "key_type": "rsa2048", "email": "ops@corp.com"},
        user=admin_user,
    )
    assert _counter_value(CERTBOT_EXECUTIONS, result="success") == before + 1


def test_issue_increments_jobs_total(db, admin_user, monkeypatch, tmp_path):
    from app.services.providers.letsencrypt import LetsEncryptProvider

    cert_obj, cert_pem, key_pem = _generate_self_signed(["metrics-issue.example.com"])
    cert_file = tmp_path / "cert.pem"
    cert_file.write_bytes(cert_pem)

    def fake_issue(self, request):
        return IssueResult(success=True, cert_path=str(cert_file), cert_name="metrics-issue.example.com",
                           exit_code=0, stdout="", stderr="")

    monkeypatch.setattr(LetsEncryptProvider, "issue", fake_issue)

    before = _counter_value(JOBS_TOTAL, type="issue", status="success")
    issue_certificate(
        db, payload={"domains": ["metrics-issue.example.com"], "validation_method": "http-01",
                     "key_type": "rsa2048", "email": "ops@corp.com"},
        user=admin_user,
    )
    assert _counter_value(JOBS_TOTAL, type="issue", status="success") == before + 1


def test_revoke_increments_jobs_total(db, admin_user, monkeypatch, tmp_path):
    from app.services.providers.letsencrypt import LetsEncryptProvider

    cert_obj, cert_pem, key_pem = _generate_self_signed(["metrics-revoke.example.com"])
    cert_file = tmp_path / "cert.pem"
    cert_file.write_bytes(cert_pem)

    def fake_issue(self, request):
        return IssueResult(success=True, cert_path=str(cert_file), cert_name="metrics-revoke.example.com",
                           exit_code=0, stdout="", stderr="")

    def fake_revoke(self, cert_path, *, reason="unspecified"):
        from app.services.providers.base import RevokeResult

        return RevokeResult(success=True, stdout="revoked")

    monkeypatch.setattr(LetsEncryptProvider, "issue", fake_issue)
    monkeypatch.setattr(LetsEncryptProvider, "revoke", fake_revoke)

    cert = issue_certificate(
        db, payload={"domains": ["metrics-revoke.example.com"], "validation_method": "http-01",
                     "key_type": "rsa2048", "email": "ops@corp.com"},
        user=admin_user,
    )

    before = _counter_value(JOBS_TOTAL, type="revoke", status="success")
    revoke_certificate(db, cert.id, user=admin_user)
    assert _counter_value(JOBS_TOTAL, type="revoke", status="success") == before + 1


def test_refresh_certificate_gauges_reflects_current_state(db, sample_certificate):
    cert = import_certificate(db, cert_data=sample_certificate["cert_pem"], key_data=sample_certificate["key_pem"])

    refresh_certificate_gauges(db)

    assert _gauge_sample(CERTIFICATE_GAUGE, status="active") >= 1
    assert _gauge_sample(CERTIFICATE_DAYS_TO_EXPIRY, certificate_id=str(cert.id)) is not None


def test_refresh_certificate_gauges_clears_deleted_certificates(db, sample_certificate):
    """Regression test: Gauge.clear() must run before repopulating, or a
    deleted certificate's days-to-expiry series lingers at its last value
    forever instead of disappearing."""
    cert = import_certificate(db, cert_data=sample_certificate["cert_pem"], key_data=sample_certificate["key_pem"])
    cert_id = cert.id
    refresh_certificate_gauges(db)
    assert _gauge_sample(CERTIFICATE_DAYS_TO_EXPIRY, certificate_id=str(cert_id)) is not None

    cert.status = "revoked"
    db.commit()
    delete_certificate(db, cert_id)

    refresh_certificate_gauges(db)
    assert _gauge_sample(CERTIFICATE_DAYS_TO_EXPIRY, certificate_id=str(cert_id)) is None
