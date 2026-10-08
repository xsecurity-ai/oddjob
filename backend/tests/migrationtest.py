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
import pathlib as _pathlib
import sys as _sys

_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parents[1]))
import os
import sqlite3
import subprocess
import sys
import tempfile
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


# ====================================== data carried across, with data
# The checks above prove the SHAPE the migrations build. This one
# proves the one that moves rows: `targets.ip_address` out of a column
# and into a table, over a database that already has content.
#
# Three things have to be true and none of them is structural:
#
#   * `host` is normalised first, and where normalising makes two rows
#     collide they are MERGED — children reparented, loser deleted —
#     rather than the migration dying on a unique constraint half-way
#     through, which would leave a database at neither revision.
#   * the collision is reported. An operator whose rows were combined
#     is entitled to know which, and what moved.
#   * a value that is not an address is named and dropped, not stored.
with tempfile.TemporaryDirectory() as tmp:
    db = Path(tmp) / "withdata.db"
    env = {**os.environ, "ODDJOB_DB": str(db), "ODDJOB_QUIET_ALEMBIC": "1"}
    BEFORE = "a81c5e4f2d60"       # the revision that still has the column
    # The migration under test, NAMED rather than reached with `head`
    # and left with `-1`. Those two mean "whatever is newest" and
    # "whatever that was", so this section quietly became about a
    # different migration the moment another one landed on top of it --
    # which is how adding an unrelated column to `projects` made it
    # fail.
    UNDER = "c41b7e9a2d08"        # addresses move out to their own table

    print("\n== the address migration, over a populated database ==")
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", BEFORE],
                   cwd=BACKEND, env=env, capture_output=True, text=True,
                   timeout=300)
    con = sqlite3.connect(db)
    con.execute("INSERT INTO projects (code,name,status,slack_delivery,"
                "created_at,updated_at) VALUES ('ACME','Acme','active',"
                "'site','2026-01-01','2026-01-01')")
    pid = con.execute("SELECT id FROM projects").fetchone()[0]
    for host, ip in (("Web01.Acme.Example", "203.0.113.9"),
                     ("web01.acme.example", "203.0.113.10"),
                     ("api.acme.example", "203.0.113.9"),
                     ("mail.acme.example.", " 2001:0DB8:0000::1 "),
                     ("junk.acme.example", "unknown")):
        con.execute("INSERT INTO targets (project_id,host,ip_address,kind,"
                    "hacked,created_at,updated_at) VALUES (?,?,?,'host',0,"
                    "'2026-01-01','2026-01-01')", (pid, host, ip))
    loser = con.execute(
        "SELECT id FROM targets WHERE host='web01.acme.example'").fetchone()[0]
    con.execute("INSERT INTO vulns (target_id,title,severity,status,"
                "remediation_attempts,created_at,updated_at) VALUES "
                "(?,'RCE on the loser','high','open',0,'2026-01-01',"
                "'2026-01-01')", (loser,))
    con.commit(); con.close()

    r = subprocess.run([sys.executable, "-m", "alembic", "upgrade", UNDER],
                       cwd=BACKEND, env=env, capture_output=True, text=True,
                       timeout=300)
    out = (r.stdout or "") + (r.stderr or "")
    check("the upgrade completes against existing rows", r.returncode == 0,
          out[-400:] if r.returncode else "")

    con = sqlite3.connect(db)
    hosts = sorted(h for (h,) in con.execute("SELECT host FROM targets"))
    check("every host is lowercase with no trailing dot",
          hosts == ["api.acme.example", "junk.acme.example",
                    "mail.acme.example", "web01.acme.example"], str(hosts))
    check("the case collision became one row, not an IntegrityError",
          hosts.count("web01.acme.example") == 1, str(hosts))
    check("and it is reported, naming both sides and what moved",
          "host collision on 'web01.acme.example'" in out
          and "moved 1 vulns" in out, out[-600:])

    moved = con.execute(
        "SELECT t.host FROM vulns v JOIN targets t ON t.id = v.target_id"
    ).fetchone()
    check("the loser's finding followed the survivor",
          moved == ("web01.acme.example",), str(moved))

    def addrs(host):
        return sorted(a for (a,) in con.execute(
            "SELECT a.address FROM target_addresses a "
            "JOIN target_address_links l ON l.address_id = a.id "
            "JOIN targets t ON t.id = l.target_id WHERE t.host = ?", (host,)))

    check("the survivor answers at BOTH addresses, its own and the loser's",
          addrs("web01.acme.example") == ["203.0.113.10", "203.0.113.9"],
          str(addrs("web01.acme.example")))
    check("the v6 address is stored in its canonical form",
          addrs("mail.acme.example") == ["2001:db8::1"],
          str(addrs("mail.acme.example")))
    # One address row for the project, two links: this is the whole
    # point of the join, and the shared-hosting case it exists for.
    shared = con.execute(
        "SELECT COUNT(*) FROM target_addresses WHERE address='203.0.113.9'"
    ).fetchone()[0]
    check("a shared address is ONE row with two targets on it",
          shared == 1 and addrs("api.acme.example") == ["203.0.113.9"],
          f"{shared} row(s); api has {addrs('api.acme.example')}")
    check("a value that was never an address is dropped and named",
          addrs("junk.acme.example") == []
          and "is not an IP literal" in out, out[-400:])
    con.close()

    # And what the downgrade cannot restore, said out loud rather than
    # discovered later. `web01` has two addresses and the column holds
    # one; the other is gone, and the migration says so.
    r = subprocess.run([sys.executable, "-m", "alembic", "downgrade", BEFORE],
                       cwd=BACKEND, env=env, capture_output=True, text=True,
                       timeout=300)
    back = (r.stdout or "") + (r.stderr or "")
    check("downgrading a populated database succeeds", r.returncode == 0,
          back[-300:] if r.returncode else "")
    check("and admits what it discarded rather than keeping the first "
          "quietly", "DISCARDED 1 address" in back, back[-400:])
    con = sqlite3.connect(db)
    kept = dict(con.execute("SELECT host, ip_address FROM targets"))
    check("the column comes back holding the earliest-observed address — "
          "the one the UI was showing",
          kept["web01.acme.example"] == "203.0.113.9", str(kept))
    con.close()

print(f"\n{'='*56}\n  {ok} passed, {fail} failed\n{'='*56}")
raise SystemExit(1 if fail else 0)
