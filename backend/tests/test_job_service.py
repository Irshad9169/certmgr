"""Job execution retry: same `.delay()`-on-a-plain-function bug as bulk
actions (see test_certificate_service.py), on a different code path."""

from __future__ import annotations

from conftest import _generate_self_signed  # noqa: F401

from app.core.config import settings
from app.models.certificate import Certificate
from app.models.enums import (
    CertificateStatus,
    CertificateType,
    JobStatus,
    RenewalStatus,
    ValidationMethod,
)
from app.models.job import JobExecution
from app.services.job_service import retry_execution


def test_retry_execution_non_eager_dispatches_without_calling_delay_on_a_plain_function(
    db, admin_user, monkeypatch,
):
    """Regression test: retry_execution() called run_job_async.delay(...),
    but run_job_async is a plain Python function (not a Celery task) — it
    has no .delay attribute. Retrying any failed issuance in a real
    (non-eager) deployment hit `'function' object has no attribute
    'delay'`; never caught because the test suite always runs eager."""
    cert = Certificate(
        domain="retry.example.com", cert_name="retry.example.com", sans=["retry.example.com"],
        cert_type=CertificateType.SINGLE.value, validation_method=ValidationMethod.HTTP_01.value,
        status=CertificateStatus.FAILED.value, renewal_status=RenewalStatus.FAILED.value,
    )
    db.add(cert)
    db.flush()
    execution = JobExecution(job_type="issue", certificate_id=cert.id, status=JobStatus.FAILED.value)
    db.add(execution)
    db.commit()

    calls = []

    def fake_run_job_async(job_type, certificate_id, user_id, execution_id=None):
        calls.append((job_type, certificate_id, user_id, execution_id))

    monkeypatch.setattr("app.tasks.celery_app.run_job_async", fake_run_job_async)
    monkeypatch.setattr(settings, "celery_task_always_eager", False)

    row = retry_execution(db, execution.id, user=admin_user)

    assert row.status == JobStatus.QUEUED.value
    assert calls == [("issue", cert.id, admin_user.id, execution.id)]
