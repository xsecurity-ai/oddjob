"""Sorting a findings listing by lifecycle, and the drift that invites.

`lifecycle` is not a column. It is `lifecycle.verdict`, a pure
function over a finding and the sweep that would speak for it, and
the Vulns grid shows its answer. Sorting the listing in the database
therefore needs the same rule expressed a second time, in SQL, as
`_LIFECYCLE_STATE`.

Two implementations of one rule drift. What makes that acceptable
here rather than reckless is which one is authoritative: the WORD on
screen is always the Python function's, and the SQL decides only
where the row sits. A drift mis-sorts a page and cannot mislabel a
finding.

This suite is the thing that stops the drift anyway. It builds a
finding for every branch of `verdict`, asks the database what state
it assigns, and fails when the two disagree — so "they still agree"
is a fact that is checked rather than a hope.
"""
import pathlib as _pathlib
import sys as _sys

_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parents[1]))
import asyncio
import json
import os
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta

BASE = os.environ.get("ODDJOB_TEST_BASE", "http://127.0.0.1:8013")
ok = fail = 0


def check(l, c, e=""):
    global ok, fail
    if c: ok += 1; print(f"  PASS  {l} {e}")
    else: fail += 1; print(f"  FAIL  {l} {e}")


def call(p, m="GET", b=None, token=None):
    r = urllib.request.Request(BASE + p, method=m)
    if b is not None:
        r.data = json.dumps(b).encode()
        r.add_header("Content-Type", "application/json")
    if token: r.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(r, timeout=60) as x:
            raw = x.read(); return x.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try: return e.code, json.loads(raw)
        except Exception: return e.code, raw[:300]


admin = call("/api/auth/setup", "POST",
             {"username": "root", "password": "root-password-1"})[1]["access_token"]
call("/api/projects", "POST", {"code": "LIFE", "name": "Lifecycle"},
     token=admin)
call("/api/targets?project=LIFE", "POST",
     {"host": "one.acme.example"}, token=admin)

from sqlalchemy import select  # noqa: E402

from app import pocwork  # noqa: E402
from app.db import SessionLocal  # noqa: E402
from app.lifecycle import verdict_for  # noqa: E402
from app.models import FindingSweep, Project, Target, Vuln  # noqa: E402

NOW = datetime(2026, 11, 2, 12, 0, tzinfo=UTC)
AGO = NOW - timedelta(days=7)
LATER = NOW + timedelta(days=1)

#: One finding per branch of `lifecycle.verdict`, named by the branch
#: it is there to reach. `sweep` is what the finding_sweeps row for
#: (this target, this scanner) should say, or None for no sweep.
CASES = [
    # title,            scanner,  first,  last,  sweep_at, found_by, swept_with
    ("no scanner",      None,     AGO,    NOW,   LATER,    None,     None),
    ("never seen",      "nmap",   AGO,    None,  LATER,    None,     None),
    ("never swept",     "nmap",   AGO,    NOW,   None,     None,     None),
    ("swept after",     "nmap",   AGO,    NOW,   LATER,    None,     None),
    ("swept, same cfg", "nmap",   AGO,    NOW,   LATER,    "a",      "a"),
    ("swept, diff cfg", "nmap",   AGO,    NOW,   LATER,    "a",      "b"),
    ("seen by sweep",   "nmap",   AGO,    NOW,   NOW,      None,     None),
    ("first is sweep",  "nmap",   NOW,    NOW,   NOW,      None,     None),
]


async def build():
    async with SessionLocal() as s:
        pr = (await s.execute(
            select(Project).where(Project.code == "LIFE"))).scalar_one()
        made = {}
        for i, (name, scanner, first, last, at, found, swept) in enumerate(CASES):
            # One target per case: the sweep table is unique on
            # (target, scanner), so two cases sharing a host would
            # fight over the one row that decides both.
            t = Target(project_id=pr.id, host=f"h{i}.acme.example",
                       kind="host")
            s.add(t)
            await s.flush()
            v = Vuln(target_id=t.id, title=name, severity="high",
                     scanner=scanner, first_seen_at=first, last_seen_at=last,
                     found_by_manifest=found)
            s.add(v)
            if at is not None and scanner:
                s.add(FindingSweep(project_id=pr.id, target_id=t.id,
                                   scanner=scanner, at=at, manifest=swept))
            await s.flush()
            made[name] = v.id
        await s.commit()
        return made


IDS = asyncio.run(build())
check("every branch has a finding", len(IDS) == len(CASES), len(IDS))


async def compare():
    """What Python says, against what the SQL CASE says."""
    from sqlalchemy import select as sel

    from app.lifecycle import sweeps_for_targets
    from app.routers.findings import _LIFECYCLE_STATE
    async with SessionLocal() as s:
        rows = (await s.execute(
            sel(Vuln).where(Vuln.id.in_(list(IDS.values()))))).scalars().all()
        sweeps = await sweeps_for_targets(s, [v.target_id for v in rows])

        # The SQL answer has to be read through the same join the
        # listing uses, or this tests a different query than ships.
        from app.routers.findings import _vulns_base
        got = {}
        for vid in IDS.values():
            stmt = (_vulns_base()
                    .with_only_columns(Vuln.id, _LIFECYCLE_STATE.label("st"))
                    .where(Vuln.id == vid))
            r = (await s.execute(stmt)).first()
            got[vid] = r.st if r else None

        for v in rows:
            want = verdict_for(v, sweeps).state
            check(f"{v.title!r}: SQL agrees with lifecycle.verdict",
                  got[v.id] == want, f"sql={got[v.id]} python={want}")


asyncio.run(compare())

print("\n--- and the listing will actually sort by it ---")
st, page = call("/api/vulns?project=LIFE&sort=lifecycle&order=asc&limit=50",
                token=admin)
check("sorting by lifecycle is accepted, not refused", st == 200,
      f"status={st} {str(page)[:160]}")

if st == 200:
    from app.routers.findings import _LIFECYCLE_ORDER
    seen = [r["lifecycle"] for r in page["items"] if r.get("lifecycle")]
    rank = {s: i for i, s in enumerate(_LIFECYCLE_ORDER)}
    ranks = [rank.get(x, 99) for x in seen]
    check("and the rows come back in the ranked order",
          ranks == sorted(ranks), seen)
    check("new first, resolved last — the order an operator reads in",
          (not seen) or (seen[0] == "new" and seen[-1] == "resolved"),
          f"{seen[:1]}..{seen[-1:]}")

st, desc = call("/api/vulns?project=LIFE&sort=lifecycle&order=desc&limit=50",
                token=admin)
check("and descending is accepted too", st == 200, f"status={st}")

print("\n--- every column the grid offers to sort, the server can sort ---")
# The bug this catches, in the words it arrived in:
#
#   cannot sort by 'lifecycle'; allowed: [...]
#
# Paging and sorting moved into the database, and `lifecycle` stayed
# a column the grid let you click. Nothing connected the two, so the
# mismatch was a 400 the moment somebody clicked the header. It will
# happen again the next time a column is added, unless something
# compares the two lists — which is what this does.
import re  # noqa: E402

from app.routers.findings import SORTABLE  # noqa: E402

GRID = (_pathlib.Path(__file__).resolve().parents[2]
        / "frontend" / "src" / "views" / "VulnsView.tsx")
src = GRID.read_text()
check("the Vulns grid source is where this expects it", GRID.exists(), GRID)

# A column object runs from `field:` to the next `field:`, which is
# enough to see whether it opted out with `sortable: false`.
chunks = re.split(r"(?=\bfield:\s*')", src)
offered = []
for c in chunks:
    m = re.match(r"field:\s*'([a-z_]+)'", c)
    if not m:
        continue
    if re.search(r"sortable:\s*false", c):
        continue
    offered.append(m.group(1))

missing = sorted(set(offered) - set(SORTABLE))
check("no sortable column is one the server would refuse",
      not missing,
      f"the grid offers {missing} which SORTABLE does not have — either "
      f"add it to SORTABLE in routers/findings.py or mark the column "
      f"`sortable: false`" if missing else f"{len(offered)} columns")

print("\n--- a column is SORTED by a rank and FILTERED by its value ---")
# Reported as:
#
#   filter on 'poc_state' needs a number, got 'Available, Confirmed'
#
# `FILTERABLE` is built from `SORTABLE`, and `severity` and
# `poc_state` are sorted by an integer CASE — alphabetical would put
# `critical` before `high` by luck. Filtering inherited the rank and
# then compared it against the label the UI sends.
from app.routers.findings import FILTERABLE, SORTABLE  # noqa: E402


def sql(expr):
    """The expression WITH its literals.

    Plain `str()` renders them as `:param_1`, which makes a CASE
    returning 0/1/2 and a CASE returning three labels look identical
    — the first version of this test compared those strings and
    passed against the bug.
    """
    return str(expr.compile(compile_kwargs={"literal_binds": True}))


for col in ("severity", "poc_state"):
    check(f"{col} sorts by a rank and filters by a value — not the same",
          sql(SORTABLE[col]) != sql(FILTERABLE[col]),
          "sort and filter share one expression")

# The ranks really are numeric, which is what the filter was
# comparing a label against.
# The rank is numeric — which is exactly what the filter was
# comparing a label against. `else_` renders as ELSE, not THEN.
_r = sql(SORTABLE["poc_state"])
check("the poc_state SORT is a numeric rank",
      "THEN 2" in _r and "THEN 0" in _r and "ELSE 1" in _r, _r[:60])
check("and carries none of the labels",
      pocwork.CONFIRMED not in _r, _r[:60])

# And the filter really does produce the strings the UI sends.
_f = sql(FILTERABLE["poc_state"])
for label in (pocwork.NOT_AVAILABLE, pocwork.CONFIRMED, pocwork.UNCONFIRMED):
    check(f"the poc_state filter can match {label!r}", label in _f, _f[:70])
check("the severity filter is the column, not a CASE",
      "CASE" not in sql(FILTERABLE["severity"]).upper(),
      sql(FILTERABLE["severity"]))

st, r = call("/api/vulns?project=LIFE&limit=5&filters="
             + __import__("urllib.parse").parse.quote(
                 json.dumps([{"field": "poc_state", "op": "is",
                              "value": pocwork.CONFIRMED}])),
             token=admin)
check("and the server accepts that filter instead of 422-ing",
      st == 200, f"status={st} {str(r)[:120]}")

print(f"\n{ok} passed, {fail} failed")
_sys.exit(1 if fail else 0)
