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


def apply_search(stmt: Select, q: str | None, columns: Sequence[Any],
                 extra=None) -> Select:
    """Case-insensitive substring match across every listed column (OR).

    Numeric columns are cast to text so searching "443" matches a port as well
    as a banner mentioning 443 -- "full search" means the user should not have
    to know which column a value lives in.

    `extra` is for the things that are no longer a column on the row
    being searched. It takes the prepared `%needle%` and returns one
    more clause to OR in — an EXISTS over a child table, typically.
    A target's addresses live in their own table now, and leaving them
    out of search would mean typing an address you can see in the grid
    and getting nothing back.
    """
    if not q:
        return stmt
    needle = f"%{q.strip().lower()}%"
    clauses = [func.lower(func.cast(c, __import__("sqlalchemy").String)).like(needle)
               for c in columns]
    if extra is not None:
        clauses.append(extra(needle))
    return stmt.where(or_(*clauses))


def apply_sort(stmt: Select, sort: str | None, order: str, allowed: dict[str, Any]) -> Select:
    if not sort:
        return stmt
    col = allowed.get(sort)
    if col is None:
        raise HTTPException(422, f"cannot sort by {sort!r}; allowed: {sorted(allowed)}")
    # NULLs last in both directions. Postgres' default puts them first for
    # ASC and (depending on the column) first or last for DESC, so a grid of
    # mostly-populated values with a handful of gaps reads as "the sort is
    # broken" -- the gaps float to the top of an ascending country list.
    # Every list endpoint shares this helper, so the rule holds everywhere.
    if order.lower() == "desc":
        return stmt.order_by(desc(col).nulls_last())
    return stmt.order_by(asc(col).nulls_last())


async def paginate(session: AsyncSession, stmt: Select,
                   limit: int, offset: int) -> tuple[list, int]:
    """Returns (rows, total). total is computed before limit/offset is applied."""
    if limit < 0 or limit > MAX_LIMIT:
        raise HTTPException(422, f"limit must be between 0 and {MAX_LIMIT}")
    # The count runs the query's WHERE against the query's own tables.
    # The old form wrapped the whole select in a derived table to count
    # it, and that is what broke the Targets page on Postgres:
    # `apply_search` ORs in an EXISTS over target_address_links, and
    # re-correlating that EXISTS inside a derived table made SQLAlchemy
    # try to join the link table from nowhere — "Don't know how to join
    # to Table('target_address_links')". (SQLite tolerated the form,
    # which is why every test suite stayed green while live Postgres
    # 500'd.)
    #
    # The WHERE is passed through as-is rather than rebuilt: it carries
    # the join conditions and any EXISTS exactly as the list query used
    # them, so the count can only disagree with the rows if the database
    # does. A None whereclause means no filter — `select().where(None)`
    # would compile to a literal `WHERE NULL` and count nothing.
    count_stmt = select(func.count()).select_from(*stmt.get_final_froms())
    if stmt.whereclause is not None:
        count_stmt = count_stmt.where(stmt.whereclause)
    total = (await session.execute(count_stmt)).scalar_one()
    rows = (await session.execute(stmt.limit(limit).offset(offset))).all()
    return rows, int(total)
