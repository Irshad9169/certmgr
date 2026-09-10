"""Shared DiscoveryRun lifecycle safety net — _tracked_run(), mark_stale_run_failed(),
and cancel_run() apply identically across filesystem/network/CT scans. A real CT
monitor run got stuck at "running" for days with zero progress this session (a
hung crt.sh call with no timeout protection at the DNS layer), requiring manual
DB cleanup — these tests cover the fixes that make that self-heal instead."""

from __future__ import annotations

from datetime import timedelta

import pytest

from app.core.exceptions import ValidationAppError
from app.core.timeutils import utcnow
from app.models.job import DiscoveryRun
from app.services.discovery_service import cancel_run, mark_stale_run_failed, run_ct_monitor


def test_run_body_exception_marks_run_failed_not_stuck_running(db, monkeypatch):
    from app.services import ct_monitor

    def _boom(*a, **k):
        raise RuntimeError("simulated crt.sh client failure")

    monkeypatch.setattr(ct_monitor, "fetch_crtsh_entries", _boom)

    run = run_ct_monitor(db, domains=["example.com"])

    assert run.status == "failed"
    assert run.finished_at is not None
    assert "simulated crt.sh client failure" in run.log


def test_mark_stale_run_failed_leaves_recent_running_run_alone(db):
    run = DiscoveryRun(started_at=utcnow(), status="running", scan_type="ct_log", scan_domains=["example.com"])
    db.add(run)
    db.commit()

    mark_stale_run_failed(db, run)

    assert run.status == "running"


def test_mark_stale_run_failed_fails_an_old_running_run(db):
    run = DiscoveryRun(
        started_at=utcnow() - timedelta(hours=3), status="running",
        scan_type="ct_log", scan_domains=["example.com"],
    )
    db.add(run)
    db.commit()

    mark_stale_run_failed(db, run)

    assert run.status == "failed"
    assert run.finished_at is not None
    assert "crashed" in run.log or "restarted" in run.log or "stuck" in run.log


def test_cancel_run_marks_cancelled(db):
    run = DiscoveryRun(started_at=utcnow(), status="running", scan_type="ct_log", scan_domains=["example.com"])
    db.add(run)
    db.commit()

    cancel_run(db, run)

    assert run.status == "cancelled"
    assert run.finished_at is not None


def test_cancel_run_rejects_a_non_running_run(db):
    run = DiscoveryRun(
        started_at=utcnow(), status="completed", scan_type="ct_log", scan_domains=["example.com"],
        finished_at=utcnow(),
    )
    db.add(run)
    db.commit()

    with pytest.raises(ValidationAppError):
        cancel_run(db, run)
