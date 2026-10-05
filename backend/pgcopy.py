#!/usr/bin/env python3
"""Copy a Oddjob database into the customer's Postgres.

    uv run python pgcopy.py --to 'postgresql://user:pw@host:5432/db' [--dry-run]
    uv run python pgcopy.py --from-settings            # use the stored DSN

Then set `ODDJOB_DATABASE_URL` to the same string and restart. The switch
is a startup decision, not a runtime one: the settings table lives inside
the database, so a connection string stored there cannot be read until
after the connection it describes is already open.

**Everything goes through the models.** Tables are created from
`Base.metadata` and rows are copied as mapped objects in dependency order,
so foreign keys land after the rows they point at and nothing here has to
know a column name. A hand-written INSERT per table would need editing
every time a model gains a field — which is exactly how the old migrator
drifted.

Primary keys are preserved, because the data is full of integer references
(`target_id`, `service_id`, `parent` ids in events) and renumbering would
mean rewriting all of them. Postgres sequences are therefore re-synced at
the end, or the first insert after the copy collides with an existing id.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from sqlalchemy import create_engine, func, inspect, select
from sqlalchemy.orm import Session

from app.models import Base

BATCH = 500


def resolve_target(args) -> str:
    if args.to:
        return args.to
    if args.from_settings:
        src = create_engine(source_url(args), future=True)
        try:
            from app.models import Setting
            with Session(src) as s:
                row = s.get(Setting, "db.external_url")
                if row is None or not row.value:
                    sys.exit("no db.external_url stored in Site Config")
                return row.value
        finally:
            src.dispose()
    sys.exit("give --to URL or --from-settings")


def source_url(args) -> str:
    if args.source:
        return args.source
    path = Path(os.environ.get(
        "ODDJOB_DB", Path(__file__).resolve().parent / "oddjob.db"))
    if not path.exists():
        sys.exit(f"no source database at {path}")
    return f"sqlite:///{path}"



#: Rows already in SQLite can hold things Postgres will not take. The
#: importers scrub on the way in now, but a database that predates that
#: still carries them, and the copy is the last chance to notice.
_NUL_FIXED = 0


def _pg_safe(v):
    """A value Postgres will accept.

    SQLite stores a NUL byte inside a text column without complaint;
    PostgreSQL rejects the whole INSERT with "PostgreSQL text fields
    cannot contain NUL (0x00) bytes". Captured HTTP responses are the
    source -- a gzip or image body decoded leniently keeps its zero
    bytes -- and the failure lands part-way through a 200,000-row copy,
    naming one URL out of thousands.
    """
    global _NUL_FIXED
    if isinstance(v, str) and "\x00" in v:
        _NUL_FIXED += 1
        return v.replace("\x00", "\ufffd")
    return v


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--to", help="destination Postgres URL")
    ap.add_argument("--from-settings", action="store_true",
                    help="read the destination from Site Config")
    ap.add_argument("--source", help="source URL; defaults to the app's SQLite")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--allow-nonempty", action="store_true",
                    help="copy even though the destination already has rows")
    args = ap.parse_args()

    from app.dsn import BadDsn, mask
    from app.dsn import parse as parse_dsn

    raw_dest = resolve_target(args)
    try:
        dest_url = parse_dsn(raw_dest).url.replace("+asyncpg", "")
    except BadDsn as e:
        sys.exit(f"destination: {e}")

    src_url = source_url(args)
    print(f"source     : {src_url}")
    print(f"destination: {mask(raw_dest)}")

    src = create_engine(src_url, future=True)
    # Built only when we are actually going to write. A dry run should
    # tell you what would be copied without needing the destination to
    # exist, or a driver installed to reach it.
    dst = None

    # Dependency order: a table is created and filled only after everything
    # it points at. sorted_tables gives exactly that.
    ordered = Base.metadata.sorted_tables
    mapped = {m.local_table.name: m.class_ for m in Base.registry.mappers}

    try:
        with Session(src) as s_in:
            counts = {t.name: int(s_in.execute(
                select(func.count()).select_from(t)).scalar_one())
                for t in ordered if inspect(src).has_table(t.name)}
        total = sum(counts.values())
        print(f"\n{total} rows across {len([c for c in counts.values() if c])} "
              f"non-empty tables")
        for t in ordered:
            if counts.get(t.name):
                print(f"   {t.name:<20} {counts[t.name]:>8}")

        if args.dry_run:
            print("\n(dry run — the destination was not contacted)")
            return 0

        dst = create_engine(dest_url, future=True)
        print("\ncreating schema from the models…")
        Base.metadata.create_all(dst)

        with Session(dst) as s_out:
            existing = {t.name: int(s_out.execute(
                select(func.count()).select_from(t)).scalar_one()) for t in ordered}
        if any(existing.values()) and not args.allow_nonempty:
            full = {k: v for k, v in existing.items() if v}
            sys.exit(f"\ndestination is not empty: {full}\n"
                     f"Refusing to merge into it — the primary keys would "
                     f"collide and you would get a silent half-copy. Empty it "
                     f"first, or pass --allow-nonempty if you know better.")

        copied = 0
        for table in ordered:
            if not counts.get(table.name):
                continue
            model = mapped.get(table.name)

            if model is None:
                # An association table (user_groups) has no mapped class,
                # only a Table in the metadata. Skipping it silently is how
                # a copied database arrives with no site admins — the rows
                # are still model-derived, just via Core rather than the ORM.
                n = _copy_core(src, dst, table)
                copied += n
                print(f"   {table.name:<20} {n:>8} copied (association table)")
                continue

            n = 0
            with Session(src) as s_in, Session(dst) as s_out:
                # yield_per keeps a 3,500-row table and a 350,000-row one
                # the same amount of memory.
                for obj in s_in.execute(
                        select(model).execution_options(yield_per=BATCH)).scalars():
                    # Detach from the source identity map and hand the plain
                    # column values to the destination; merge() would issue a
                    # SELECT per row against a database we know is empty.
                    data = {c.name: _pg_safe(getattr(obj, c.name))
                            for c in table.columns}
                    s_out.add(model(**data))
                    n += 1
                    if n % BATCH == 0:
                        s_out.flush()
                s_out.commit()
            copied += n
            print(f"   {table.name:<20} {n:>8} copied")

        _resync_sequences(dst, ordered)
        print(f"\n{copied} rows copied")
        if _NUL_FIXED:
            print(f"{_NUL_FIXED} value(s) contained NUL bytes Postgres will "
                  f"not store; each was replaced with U+FFFD")
        print(f"\nNow set this and restart:\n"
              f"  export ODDJOB_DATABASE_URL='{mask(raw_dest)}'")
        print("  (with the real password, obviously — it is masked here on purpose)")
    finally:
        src.dispose()
        if dst is not None:
            dst.dispose()
    return 0


def _copy_core(src, dst, table) -> int:
    """Copy a table that has no ORM class, using its metadata definition."""
    from sqlalchemy import insert
    rows = []
    with src.connect() as c_in:
        for row in c_in.execute(select(table)).mappings():
            rows.append(dict(row))
    if rows:
        with dst.begin() as c_out:
            for i in range(0, len(rows), BATCH):
                c_out.execute(insert(table), rows[i:i + BATCH])
    return len(rows)


def _resync_sequences(engine, tables) -> None:
    """Point each identity sequence past the highest copied id.

    Skipping this is the classic Postgres import bug: the copy succeeds,
    and then the very first insert fails on a duplicate key because the
    sequence still starts at 1.
    """
    from sqlalchemy import text
    fixed = 0
    with Session(engine) as s:
        for table in tables:
            pk = list(table.primary_key.columns)
            if len(pk) != 1 or not str(pk[0].type).upper().startswith("INTEGER"):
                continue
            col = pk[0]
            top = s.execute(select(func.max(col))).scalar()
            if not top:
                continue
            # pg_get_serial_sequence resolves the real sequence name rather
            # than assuming the <table>_<col>_seq convention, which breaks
            # on a renamed table.
            seq = s.execute(
                text("SELECT pg_get_serial_sequence(:t, :c)"),
                {"t": table.name, "c": col.name}).scalar()
            if not seq:
                continue
            s.execute(text("SELECT setval(:s, :v)"), {"s": seq, "v": int(top)})
            fixed += 1
        s.commit()
    print(f"re-synced {fixed} sequence(s)")


if __name__ == "__main__":
    raise SystemExit(main())
