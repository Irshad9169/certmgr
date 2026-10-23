"""cleanup_stale_metrics only removes shard files for provably-dead PIDs —
this is what's safe to run from either certmgr-api.service or
certmgr-worker.service without racing the other, since a live sibling's
own shard is never a candidate for removal."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "cleanup_stale_metrics.py"
_spec = importlib.util.spec_from_file_location("cleanup_stale_metrics", _SCRIPT)
cleanup_stale_metrics = importlib.util.module_from_spec(_spec)
sys.modules["cleanup_stale_metrics"] = cleanup_stale_metrics
_spec.loader.exec_module(cleanup_stale_metrics)


def test_removes_shard_for_dead_pid(tmp_path, monkeypatch):
    (tmp_path / "gauge_livesum_99999.db").write_bytes(b"")
    monkeypatch.setattr(cleanup_stale_metrics, "_pid_is_alive", lambda pid: False)

    removed = cleanup_stale_metrics.cleanup(str(tmp_path))

    assert removed == 1
    assert not (tmp_path / "gauge_livesum_99999.db").exists()


def test_keeps_shard_for_live_pid(tmp_path, monkeypatch):
    (tmp_path / "gauge_livesum_1.db").write_bytes(b"")
    monkeypatch.setattr(cleanup_stale_metrics, "_pid_is_alive", lambda pid: True)

    removed = cleanup_stale_metrics.cleanup(str(tmp_path))

    assert removed == 0
    assert (tmp_path / "gauge_livesum_1.db").exists()


def test_ignores_non_db_and_unparseable_files(tmp_path, monkeypatch):
    (tmp_path / "notes.txt").write_bytes(b"")
    (tmp_path / "no_pid_suffix.db").write_bytes(b"")
    monkeypatch.setattr(cleanup_stale_metrics, "_pid_is_alive", lambda pid: False)

    removed = cleanup_stale_metrics.cleanup(str(tmp_path))

    assert removed == 0
    assert (tmp_path / "notes.txt").exists()
    assert (tmp_path / "no_pid_suffix.db").exists()


def test_missing_directory_is_a_noop(tmp_path):
    assert cleanup_stale_metrics.cleanup(str(tmp_path / "does-not-exist")) == 0
