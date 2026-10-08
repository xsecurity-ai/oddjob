"""Chained column filters, evaluated in the database.

A table that pages in SQL cannot filter in the browser: the browser
holds one page, so a filter applied there would hide rows from that
page and leave the total and the page count describing something else
entirely. The filters therefore have to travel with the query.

The wire format is the grid's own filter model, narrowed to what SQL
can answer:

    filters=[{"field":"status_code","op":">=","value":"500"},
             {"field":"url","op":"contains","value":"admin"}]
    logic=and

**An unusable filter is an error, never a silent pass.** If the field is
not filterable or the operator is unknown, this raises 400 and names
what it did not understand. The alternative — ignoring it and returning
rows — shows the operator a filtered-looking table that is not filtered,
which on a findings database is how something gets missed.
"""
from __future__ import annotations

import json
from typing import Any

from fastapi import HTTPException
from sqlalchemy import Boolean, Integer, and_, not_, or_
from sqlalchemy.sql.elements import ColumnElement

#: Operators that need no value — everything else is skipped when its
#: value is blank, matching the grid, where a half-typed filter row
#: should not yet do anything.
_NO_VALUE = {"isEmpty", "isNotEmpty"}

_TEXT_OPS = {
    "contains", "doesNotContain", "equals", "doesNotEqual", "startsWith",
    "endsWith", "isEmpty", "isNotEmpty", "isAnyOf", "is", "not",
}
_NUM_OPS = {"=", "!=", ">", ">=", "<", "<=", "isEmpty", "isNotEmpty", "isAnyOf"}


def _as_number(v: Any, field: str) -> float:
    try:
        return float(str(v).strip())
    except (TypeError, ValueError) as e:
        raise HTTPException(
            400, f"filter on {field!r} needs a number, got {v!r}") from e


def _clause(col: ColumnElement, op: str, value: Any, field: str):
    numeric = isinstance(getattr(col, "type", None), Integer)
    boolish = isinstance(getattr(col, "type", None), Boolean)

    if op == "isEmpty":
        return col.is_(None) if (numeric or boolish) else or_(col.is_(None), col == "")
    if op == "isNotEmpty":
        return col.isnot(None) if (numeric or boolish) else and_(col.isnot(None), col != "")

    if op == "isAnyOf":
        vals = value if isinstance(value, list) else [value]
        if not vals:
            return None
        if numeric:
            return col.in_([int(_as_number(v, field)) for v in vals])
        return col.in_([str(v) for v in vals])

    if boolish:
        truthy = str(value).strip().lower() in ("true", "1", "yes")
        return col.is_(truthy) if op in ("is", "equals", "=") else col.isnot(truthy)

    if numeric:
        n = _as_number(value, field)
        return {
            "=": col == n, "equals": col == n, "is": col == n,
            "!=": col != n, "doesNotEqual": col != n, "not": col != n,
            ">": col > n, ">=": col >= n, "<": col < n, "<=": col <= n,
        }.get(op) if op in _NUM_OPS | {"equals", "doesNotEqual", "is", "not"} else None

    s = str(value)
    esc = s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return {
        "contains": col.ilike(f"%{esc}%", escape="\\"),
        "doesNotContain": not_(col.ilike(f"%{esc}%", escape="\\")),
        "equals": col.ilike(esc, escape="\\"),
        "is": col.ilike(esc, escape="\\"),
        "doesNotEqual": not_(col.ilike(esc, escape="\\")),
        "not": not_(col.ilike(esc, escape="\\")),
        "startsWith": col.ilike(f"{esc}%", escape="\\"),
        "endsWith": col.ilike(f"%{esc}", escape="\\"),
    }.get(op)


def apply_filters(stmt, raw: str | None, allowed: dict[str, ColumnElement],
                  logic: str = "and"):
    """Add the filters in `raw` to `stmt`.

    `allowed` maps the names the client may use to real columns, so a
    caller cannot filter on a column the endpoint never meant to expose.
    """
    if not (raw or "").strip():
        return stmt
    try:
        items = json.loads(raw)
    except ValueError as e:
        raise HTTPException(400, f"filters is not valid JSON: {e}") from e
    if not isinstance(items, list):
        raise HTTPException(400, "filters must be a JSON array")

    clauses = []
    for item in items:
        if not isinstance(item, dict):
            raise HTTPException(400, f"each filter must be an object, got {item!r}")
        field = str(item.get("field") or "")
        op = str(item.get("op") or item.get("operator") or "contains")
        value = item.get("value")

        if field not in allowed:
            raise HTTPException(
                400, f"cannot filter on {field!r}. Filterable: "
                     f"{', '.join(sorted(allowed))}")
        if op not in _TEXT_OPS | _NUM_OPS:
            raise HTTPException(400, f"unknown filter operator {op!r}")
        # A row the user has added but not filled in yet is not a
        # filter. Matches the grid, which also waits for a value.
        if op not in _NO_VALUE and (value is None or value == ""
                                    or (isinstance(value, list) and not value)):
            continue

        c = _clause(allowed[field], op, value, field)
        if c is None:
            raise HTTPException(
                400, f"operator {op!r} does not apply to {field!r}")
        clauses.append(c)

    if not clauses:
        return stmt
    return stmt.where(or_(*clauses) if logic.lower() == "or" else and_(*clauses))
