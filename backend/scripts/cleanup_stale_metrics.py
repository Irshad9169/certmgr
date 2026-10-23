"""Remove orphaned Prometheus multiprocess shard files.

Every uvicorn/Celery worker process writes its own `<metric>_<pid>.db`
file under PROMETHEUS_MULTIPROC_DIR. When a process exits (restart,
crash, --max-tasks-per-child recycling) nothing ever deletes its file,
so the CERTIFICATE_GAUGE/CERTIFICATE_DAYS_TO_EXPIRY snapshots — which
are fully recomputed and .clear()'d on every /metrics scrape, but only
within the *one* process handling that scrape — keep contributing a
long-dead process's last-written values forever under `mostrecent`
multiprocess aggregation. That's what produces labels (e.g. a
"discovered" status count) that no longer match the live database at
all, as opposed to the CertMgr UI's own dashboard, which always queries
the database directly.

Run this before each worker generation starts (see
deploy/systemd/certmgr-api.service / certmgr-worker.service). It only
ever removes files belonging to a PID that is provably no longer
running, so it's safe to run from either unit without coordinating with
the other — a live sibling process's shard is never touched.
"""

from __future__ import annotations

import os
import re
import sys

_PID_RE = re.compile(r"_(\d+)\.db$")


def _pid_is_alive(pid: int) -> bool:
    return os.path.exists(f"/proc/{pid}")


def cleanup(directory: str) -> int:
    if not os.path.isdir(directory):
        return 0
    removed = 0
    for name in os.listdir(directory):
        if not name.endswith(".db"):
            continue
        match = _PID_RE.search(name)
        if not match:
            continue
        pid = int(match.group(1))
        if _pid_is_alive(pid):
            continue
        try:
            os.remove(os.path.join(directory, name))
            removed += 1
        except FileNotFoundError:
            pass  # removed concurrently by the other service's own sweep
    return removed


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("PROMETHEUS_MULTIPROC_DIR", "")
    if not target:
        sys.exit(0)
    n = cleanup(target)
    print(f"cleanup_stale_metrics: removed {n} orphaned shard file(s) from {target}")
