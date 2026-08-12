"""Jobs / execution history API."""


from fastapi import APIRouter, Query

from app.api.deps import CurrentUser, DbSession
from app.services import job_service

router = APIRouter(prefix="/jobs", tags=["Jobs"])


@router.get("")
def list_jobs(db: DbSession, user: CurrentUser, job_type: str | None = None,
              status: str | None = None, certificate_id: int | None = None,
              page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=200)):
    rows, total = job_service.list_executions(
        db, certificate_id=certificate_id, job_type=job_type, status=status,
        page=page, page_size=page_size,
    )
    return {"items": [_serialize(e) for e in rows], "total": total,
            "page": page, "page_size": page_size}


@router.get("/{execution_id}")
def get_job(execution_id: int, db: DbSession, user: CurrentUser):
    row = job_service.get_execution(db, execution_id)
    return _serialize(row)


@router.post("/{execution_id}/retry")
def retry_job(execution_id: int, db: DbSession, user: CurrentUser):
    return job_service.retry_execution(db, execution_id, user=user)


def _serialize(e) -> dict:
    return {
        "id": e.id, "job_type": e.job_type, "certificate_id": e.certificate_id,
        "server_id": e.server_id, "task_id": e.task_id, "trigger": e.trigger,
        "status": e.status, "exit_code": e.exit_code,
        "stdout": (e.stdout or "")[-10000:], "stderr": (e.stderr or "")[-10000:],
        "error_message": e.error_message, "execution_time_ms": e.execution_time_ms,
        "retry_count": e.retry_count,
        "started_at": e.started_at.isoformat() if e.started_at else None,
        "finished_at": e.finished_at.isoformat() if e.finished_at else None,
        "log_path": e.log_path,
        "created_at": e.created_at.isoformat() if e.created_at else None,
    }
