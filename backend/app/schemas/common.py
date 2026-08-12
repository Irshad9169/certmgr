"""Generic pagination envelope."""

from __future__ import annotations

from typing import Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class PageMeta(BaseModel):
    page: int = Field(ge=1)
    page_size: int = Field(ge=1, le=500)
    total: int = 0
    pages: int = 0


class Page(BaseModel, Generic[T]):
    items: list[T]
    meta: PageMeta
