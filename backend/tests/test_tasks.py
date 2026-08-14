"""Celery task-layer plumbing: session_scope() and the db_task decorator.

No existing test exercised this layer at all — every other test calls
service functions directly, never through an actual @db_task-wrapped
Celery task — which is exactly how session_scope() shipped without the
@contextmanager decorator it needs and broke every single Celery task in
the app (`with session_scope() as db:` raised
"'generator' object does not support the context manager protocol")."""

from __future__ import annotations

import pytest

from app.core.database import session_scope
from app.models.user import User
from app.tasks.base import db_task


def test_session_scope_is_a_real_context_manager():
    """Regression test for the exact bug: session_scope() must be usable
    with `with ... as ...:`, not just as a bare generator."""
    with session_scope() as db:
        assert db.query(User).count() >= 0


def test_session_scope_commits_on_success(db):
    with session_scope() as scoped_db:
        user = scoped_db.query(User).filter(User.username == "admin").first()
        assert user is not None
        user.full_name = "Changed By Session Scope"

    db.expire_all()
    refreshed = db.query(User).filter(User.username == "admin").first()
    assert refreshed.full_name == "Changed By Session Scope"


def test_session_scope_rolls_back_on_exception(db):
    with pytest.raises(RuntimeError):
        with session_scope() as scoped_db:
            user = scoped_db.query(User).filter(User.username == "admin").first()
            user.full_name = "Should Not Persist"
            raise RuntimeError("boom")

    db.expire_all()
    refreshed = db.query(User).filter(User.username == "admin").first()
    assert refreshed.full_name != "Should Not Persist"


def test_db_task_decorator_provides_a_working_session(db):
    """Exercises the actual composition every Celery task uses
    (@celery_app.task + @db_task), not just session_scope() in isolation."""
    @db_task
    def _count_users(db) -> int:
        return db.query(User).count()

    result = _count_users()
    assert result >= 1
