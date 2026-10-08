"""Shared list-endpoint behaviour: full search, sorting, pagination.

Every list endpoint takes the same four params (q, sort, order, limit/offset)
and returns the same Page envelope, so the UI has one code path for all grids.
"""
from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from fastapi import HTTPException
from sqlalchemy import Select, asc, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

MAX_LIMIT = 100_000


def apply_search(stmt: Select, q: str | None, columns: Sequence[Any]) -> Select:
    """Case-insensitive substring match across every listed column (OR).

    Numeric columns are cast to text so searching "443" matches a port as well
    as a banner mentioning 443 -- "full search" means the user should not have
    to know which column a value lives in.
    """
    if not q:
        return stmt
    needle = f"%{q.strip().lower()}%"
    clauses = [func.lower(func.cast(c, __import__("sqlalchemy").String)).like(needle)
               for c in columns]
    return stmt.where(or_(*clauses))


def apply_sort(stmt: Select, sort: str | None, order: str, allowed: dict[str, Any]) -> Select:
    if not sort:
        return stmt
    col = allowed.get(sort)
    if col is None:
        raise HTTPException(422, f"cannot sort by {sort!r}; allowed: {sorted(allowed)}")
    return stmt.order_by(desc(col) if order.lower() == "desc" else asc(col))


async def paginate(session: AsyncSession, stmt: Select,
                   limit: int, offset: int) -> tuple[list, int]:
    """Returns (rows, total). total is computed before limit/offset is applied."""
    if limit < 0 or limit > MAX_LIMIT:
        raise HTTPException(422, f"limit must be between 0 and {MAX_LIMIT}")
    count_stmt = select(func.count()).select_from(stmt.order_by(None).subquery())
    total = (await session.execute(count_stmt)).scalar_one()
    rows = (await session.execute(stmt.limit(limit).offset(offset))).all()
    return rows, int(total)
