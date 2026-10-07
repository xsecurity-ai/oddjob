"""The migrations must build exactly what the models describe.

This exists because of a real failure: a column added to the database
out-of-band was invisible to `alembic revision --autogenerate`, which
diffs against whatever database it is pointed at. The resulting migration
worked on the machine it was authored on and produced a schema missing a
column everywhere else — precisely the failure Alembic was adopted to
prevent.

So: build a database from nothing but the migrations, and compare it to
the models. No server, no fixtures, no dev database.
"""

# Run from anywhere: the suites import `app`, which lives one level up.
import pathlib as _pathlib, sys as _sys
_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parents[1]))
import os, subprocess, sys, tempfile
from pathlib import Path

from sqlalchemy import create_engine, inspect

#: The backend root: where alembic.ini is, and what every subprocess
#: here has to run from. This file used to live there; it does not any
#: more, and "cwd=the directory I am in" quietly became the wrong
#: answer — alembic reported "No 'script_location' key".
BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
from app.models import Base  # noqa: E402

ok = fail = 0


def check(label, cond, extra=""):
    global ok, fail
    if cond: ok += 1; print(f"  PASS  {label} {extra}")
    else: fail += 1; print(f"  FAIL  {label} {extra}")


with tempfile.TemporaryDirectory() as tmp:
    db = Path(tmp) / "fromscratch.db"
    env = {**os.environ, "ODDJOB_DB": str(db), "ODDJOB_QUIET_ALEMBIC": "1"}

    print("== a database built from the migrations alone ==")
    r = subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"],
                       cwd=BACKEND, env=env,
                       capture_output=True, text=True, timeout=300)
    check("upgrade head succeeds", r.returncode == 0,
          (r.stderr or r.stdout)[-300:] if r.returncode else "")
    if r.returncode != 0:
        print(f"\n{'='*56}\n  {ok} passed, {fail} failed\n{'='*56}")
        raise SystemExit(1)

    engine = create_engine(f"sqlite:///{db}")
    insp = inspect(engine)
    have_tables = set(insp.get_table_names()) - {"alembic_version"}
    want_tables = set(Base.metadata.tables)

    check("every table exists", want_tables <= have_tables,
          f"missing {sorted(want_tables - have_tables)}" if want_tables - have_tables else "")
    extra_tables = have_tables - want_tables
    check("no tables the models do not define", not extra_tables,
          f"extra {sorted(extra_tables)}" if extra_tables else "")

    missing_cols, extra_cols, nullability = [], [], []
    for name, table in Base.metadata.tables.items():
        if name not in have_tables:
            continue
        live = {c["name"]: c for c in insp.get_columns(name)}
        for col in table.columns:
            if col.name not in live:
                missing_cols.append(f"{name}.{col.name}")
                continue
            # A column the model says is required but the schema lets be
            # null will fail on insert, not on startup — the worst kind.
            if not col.nullable and live[col.name]["nullable"] and not col.primary_key:
                nullability.append(f"{name}.{col.name}")
        for c in live:
            if c not in table.columns:
                extra_cols.append(f"{name}.{c}")

    check("every column exists", not missing_cols,
          ", ".join(missing_cols) if missing_cols else "")
    check("no columns the models dropped", not extra_cols,
          ", ".join(extra_cols) if extra_cols else "")
    check("NOT NULL matches the models", not nullability,
          ", ".join(nullability) if nullability else "")

    print("\n== the app agrees ==")
    r = subprocess.run(
        [sys.executable, "-c",
         "import asyncio; from app.db import init_db; asyncio.run(init_db())"],
        cwd=BACKEND, env=env, capture_output=True, text=True,
        timeout=300)
    check("the startup drift check passes against it", r.returncode == 0,
          (r.stderr or "")[-300:] if r.returncode else "")

    # `alembic check` compares the models against the schema the
    # migrations actually build. The startup check above does not catch
    # a differently-NAMED index, which is how a migration creating
    # ix_cve_modified shipped against models declaring index=True
    # (ix_cve_records_modified): every suite passed locally and CI
    # failed, which is the feedback loop backwards.
    print("\n== the models and the migrations agree ==")
    r = subprocess.run([sys.executable, "-m", "alembic", "check"],
                       cwd=BACKEND, env=env,
                       capture_output=True, text=True, timeout=300)
    check("alembic check finds no undeclared drift", r.returncode == 0,
          ((r.stdout or "") + (r.stderr or ""))[-400:] if r.returncode else "")

    print("\n== downgrading the newest migration is reversible ==")
    r = subprocess.run([sys.executable, "-m", "alembic", "downgrade", "-1"],
                       cwd=BACKEND, env=env,
                       capture_output=True, text=True, timeout=300)
    check("downgrade -1 succeeds", r.returncode == 0,
          (r.stderr or "")[-200:] if r.returncode else "")
    r = subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"],
                       cwd=BACKEND, env=env,
                       capture_output=True, text=True, timeout=300)
    check("and upgrading again succeeds", r.returncode == 0,
          (r.stderr or "")[-200:] if r.returncode else "")

    engine.dispose()

print(f"\n{'='*56}\n  {ok} passed, {fail} failed\n{'='*56}")
raise SystemExit(1 if fail else 0)
