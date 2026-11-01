"""What a Ghost's verdict on a proof does to the row that records it.

No server: `pocwork` is a function over a `Poc` and a JSON payload,
and the thing worth asserting is which verdict survives contact with
which payload.
"""
import asyncio
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.models import Poc  # noqa: E402
from app.pocwork import (  # noqa: E402
    CONFIRMED,
    NOT_AVAILABLE,
    UNCONFIRMED,
    apply_result,
    availability,
    why_unconfirmed,
)

passed = failed = 0


def check(label_, cond, got=None):
    global passed, failed
    if cond:
        passed += 1
        print(f"  PASS  {label_}" + (f" {got}" if got is not None else ""))
    else:
        failed += 1
        print(f"  FAIL  {label_}" + (f" {got}" if got is not None else ""))


class FakeSession:
    """Enough of a session for `apply_result`: one row, fetched by id."""

    def __init__(self, poc):
        self.poc = poc

    async def get(self, _model, pid):
        return self.poc if pid == self.poc.id else None


def payload(code, hits=None, why="", target="https://acme.example/"):
    return json.dumps({"poc": {
        "target": target, "exit_code": code,
        "verdict": {0: "reproduced", 1: "not reproduced",
                    2: "could not test"}[code],
        "hits": hits or [], "why": why}})


def run(code=None, raw=None, **kw):
    poc = Poc(id=1, target_id=1, title="t")
    out = asyncio.run(apply_result(
        FakeSession(poc), 1,
        raw if raw is not None else payload(code, **kw)))
    return out


print("== the three verdicts ==")
r = run(0, hits=[{"matched-at": "https://acme.example/x",
                  "template-id": "poc-1"}])
check("a reproduction is exit 0", r.exit_code == 0, r.exit_code)
check("...and is confirmed", r.status == "confirmed", r.status)
check("...and the verdict carries the evidence",
      "reproduced" in r.verdict and "acme.example/x" in r.verdict, r.verdict)

r = run(1, why="the template ran and matched nothing")
check("no reproduction is exit 1", r.exit_code == 1, r.exit_code)
check("...and says so without claiming a fix",
      "not reproduced" in r.verdict and "fixed" not in r.verdict.lower(),
      r.verdict)

r = run(2, why="the host did not answer")
check("could-not-test is exit 2", r.exit_code == 2, r.exit_code)
check("...and keeps the reason, which is the whole point",
      "did not answer" in r.verdict, r.verdict)

print("\n== nothing here closes a finding ==")
# "The check we wrote did not fire today" and "this is fixed" are
# different claims, and only the first is ours to make.
r = run(1)
check("a PoC that did not reproduce leaves the finding alone",
      r.status == "not_reproduced", r.status)
check("...and the PoC's own status is not 'fixed' or 'closed'",
      r.status not in ("fixed", "closed", "resolved"), r.status)

print("\n== the three words the PoC column says ==")
# Available means there is a SCRIPT. Confirmed means it ran here and
# worked. Every other case is the middle state, which is the one the
# column exists to be able to say.
_val = Poc(id=1, target_id=1, title="t", template="id: x")
asyncio.run(apply_result(FakeSession(_val), 1, payload(0)))
check("a proof that ran and worked is confirmed",
      availability(_val) == CONFIRMED, availability(_val))
check("...and has nothing to qualify", why_unconfirmed(_val) is None)

_built = Poc(id=2, target_id=1, title="t", template="id: x")
check("one that has never run is available, not confirmed",
      availability(_built) == UNCONFIRMED, availability(_built))
check("...and says it has not run, which is where the operator goes next",
      why_unconfirmed(_built) == "written, not run yet",
      why_unconfirmed(_built))

# A run happened and settled nothing. Reading `exit_code` alone would
# call that confirmed and show a verdict nobody should act on.
_untested = Poc(id=3, target_id=1, title="t", template="id: x")
asyncio.run(apply_result(FakeSession(_untested), 3, payload(
    2, why="the host did not answer")))
check("one that ran but could not test is not confirmed",
      availability(_untested) == UNCONFIRMED, availability(_untested))
check("...and keeps the reason it could not",
      "did not answer" in (why_unconfirmed(_untested) or ""),
      why_unconfirmed(_untested))

# It ran and matched nothing. That is a proof which did not work,
# which is exactly "not confirmed" -- and it must not read as a
# missing proof, because somebody wrote it.
_missed = Poc(id=4, target_id=1, title="t", template="id: x")
asyncio.run(apply_result(FakeSession(_missed), 4, payload(1)))
check("one that ran and matched nothing is still AVAILABLE",
      availability(_missed) == UNCONFIRMED, availability(_missed))

check("no proof at all is not available",
      availability(None) == NOT_AVAILABLE, availability(None))
# The row `auto_poc` writes when the model's answer was refused. It
# records that a proof was attempted and could not be written -- if
# this read "available" the column would advertise a script that
# does not exist.
_refused = Poc(id=5, target_id=1, title="t", template=None,
               verdict="no proof was written — no matcher")
check("a row recording a refused build is NOT available",
      availability(_refused) == NOT_AVAILABLE, availability(_refused))
check("...and nor is one whose template is blank",
      availability(Poc(id=6, target_id=1, title="t", template="  "))
      == NOT_AVAILABLE)

print("\n== a payload it cannot read is 'could not test' ==")
# Never an exception: this runs inside the result handler, and
# raising would fail the import of a task that otherwise succeeded.
for bad in ("", "not json", "{}", '{"poc": null}', '{"poc": {}}',
            '{"poc": {"exit_code": 7}}', '{"poc": {"exit_code": "0"}}'):
    r = run(raw=bad)
    check(f"{bad[:28]!r} -> could not test",
          r.exit_code == 2, r.exit_code)

print("\n== and the run is dated, which is what 'validated' means ==")
r = run(0)
check("validated_at is set by a run", r.validated_at is not None)
check("...and the target it was pointed at is recorded",
      r.target_url == "https://acme.example/", r.target_url)
check("a row that does not exist is None, not an error",
      asyncio.run(apply_result(FakeSession(Poc(id=1, target_id=1, title="t")),
                               999, payload(0))) is None)

print("\n== the worker picks the worst finding with no proof ==")
from app.agent.pocworker import PRIORITY, _url_for  # noqa: E402

# Worst first, so a worker switched off after twenty findings proved
# the twenty that mattered.
from app.models import SEVERITIES  # noqa: E402

check("severity order is worst first",
      SEVERITIES[0] == "critical" and SEVERITIES[-1] == "info",
      str(SEVERITIES))
# Above every sweep in the queue: a proof is a question somebody is
# waiting on, everything else is a sweep.
check("a proof outranks a sweep", PRIORITY > 0, PRIORITY)


class _V:
    def __init__(self, port):
        self.port = port


print("\n== where a proof is pointed ==")
# The scheme is a guess from the port and is the one thing here that
# can be wrong undetectably. A wrong guess reports "could not test"
# rather than a wrong verdict, because the runner proves
# reachability before it runs anything.
for port, want in [(443, "https://h.acme.example"),
                   (80, "http://h.acme.example"),
                   (8443, "https://h.acme.example:8443"),
                   (8080, "http://h.acme.example:8080"),
                   (None, "http://h.acme.example")]:
    got = _url_for(_V(port), "h.acme.example")
    check(f"port {port} -> {want}", got == want, got)


# ===================================================================
# What the findings table actually receives
# ===================================================================
#
# The three states are only useful if they reach the client, and
# `VulnOut` is built in TWO places -- the findings list and the
# target detail. The second derives its field list from the schema
# (`_keys` in routers/targets.py), so a field added here that is not
# a column on `Vuln` is a 500 on every target page until it is
# excluded and filled in. That is not hypothetical: it is what these
# three fields did, and only an unrelated import test noticed.
print("\n== the state reaches the client, from both places ==")
import os  # noqa: E402
import urllib.error  # noqa: E402
import urllib.request  # noqa: E402

BASE = os.environ.get("ODDJOB_TEST_BASE", "http://127.0.0.1:8035")


def call(path, m="GET", b=None, token=None):
    r = urllib.request.Request(BASE + path, method=m)
    if b is not None:
        r.data = json.dumps(b).encode()
        r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(r, timeout=60) as x:
            raw = x.read()
            return x.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw[:300].decode("utf-8", "replace")


admin = call("/api/auth/setup", "POST",
             {"username": "root", "password": "root-password-1"})[1]["access_token"]
call("/api/projects", "POST", {"code": "POCT", "name": "poc"}, token=admin)
call("/api/projects/POCT/scope", "POST",
     {"lines": ["web.acme.example"]}, token=admin)
call("/api/targets?project=POCT", "POST",
     {"host": "web.acme.example"}, token=admin)
st, v = call("/api/vulns?project=POCT", "POST",
             {"host": "web.acme.example", "title": "Exposed admin panel",
              "severity": "high"}, token=admin)
VID = (v or {}).get("id")
check("a finding to hang a proof off", st in (200, 201) and VID, f"{st} {v}")

st, page = call("/api/vulns?project=POCT&limit=10", token=admin)
row = (page or {}).get("items", [{}])[0]
check("a finding with no proof reads Not Available",
      row.get("poc_state") == "Not Available", row.get("poc_state"))
check("...and offers no proof to open", row.get("poc_id") is None)

# The place that broke. A field on VulnOut that is not a column on
# Vuln has to be excluded from `_keys` AND filled in, or this 500s.
st, detail = call("/api/targets/POCT/web.acme.example/detail", token=admin)
check("the target detail renders at all with the new fields",
      st == 200, f"{st} {str(detail)[:120]}")
dv = (detail or {}).get("vulns", [{}])[0] if st == 200 else {}
check("...and carries the same state the list does",
      dv.get("poc_state") == "Not Available", dv.get("poc_state"))

TEMPLATE = """id: poc-admin-panel
info:
  name: Exposed admin panel
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
    matchers:
      - type: status
        status:
          - 200
"""


async def attach(template):
    async with SessionLocal() as s_:
        pr = (await s_.execute(select(Project).where(
            Project.code == "POCT"))).scalar_one()
        t = (await s_.execute(select(Target).where(
            Target.project_id == pr.id))).scalars().first()
        row_ = Poc(target_id=t.id, vuln_id=VID, title="Proof: admin panel",
                   status="unconfirmed", template=template,
                   target_url="https://web.acme.example/")
        s_.add(row_)
        await s_.commit()
        return row_.id


import asyncio as _asyncio  # noqa: E402

from sqlalchemy import func, select  # noqa: E402

from app.db import SessionLocal  # noqa: E402
from app.models import Project, Target  # noqa: E402

PID = _asyncio.run(attach(TEMPLATE))

st, page = call("/api/vulns?project=POCT&limit=10", token=admin)
row = (page or {}).get("items", [{}])[0]
check("a written proof reads Available, Not Confirmed",
      row.get("poc_state") == "Available, Not Confirmed", row.get("poc_state"))
check("...and says it has not run yet",
      row.get("poc_detail") == "written, not run yet", row.get("poc_detail"))
check("...and points at the proof to open",
      row.get("poc_id") == PID, f"{row.get('poc_id')} != {PID}")

print("\n== reading, editing and running one ==")
st, got = call(f"/api/pocs/{PID}?project=POCT", token=admin)
check("the proof hands back its script", st == 200 and "matchers" in
      (got or {}).get("template", ""), f"{st}")
check("...and its state", (got or {}).get("state") == "Available, Not Confirmed")

st, r = call(f"/api/pocs/{PID}?project=POCT", "PATCH",
             {"template": "id: x\ninfo:\n  name: y\n"}, token=admin)
check("a script with no http block is refused, with the reason",
      st == 422 and "http" in str(r), f"{st} {r}")
st, r = call(f"/api/pocs/{PID}?project=POCT", "PATCH",
             {"template": "id: x\nhttp:\n  - method: GET\n"}, token=admin)
check("...and so is one with no matcher, which would read as FIXED",
      st == 422 and "matcher" in str(r), f"{st} {r}")

st, r = call(f"/api/pocs/{PID}?project=POCT", "PATCH",
             {"template": TEMPLATE.replace("/admin", "/manage")}, token=admin)
check("a good edit saves", st == 200 and "/manage" in r.get("template", ""),
      f"{st}")

# Nothing to run it on. The refusal has to say that rather than
# leaving a proof queued against a fleet that is not there.
st, r = call(f"/api/pocs/{PID}/run?project=POCT", "POST", {}, token=admin)
check("running with no ghost online is refused, and says why",
      st == 409 and "Ghost" in str(r), f"{st} {r}")

st, r = call("/api/pocs/999999/run?project=POCT", "POST", {}, token=admin)
check("a proof that does not exist is a 404", st == 404, st)
st, r = call(f"/api/pocs/{PID}?project=OTHERP", token=admin)
check("another engagement cannot read it by id", st in (403, 404), st)


print("== sorting a findings page in the database ==")
# The grid ranked `severity` and `poc_state` in the browser, which only
# ever ordered the rows it had been handed. Paging the listing in the
# database makes that wrong -- it would rank one page -- so both ranks
# are SQL now, and these say they mean the same thing they used to.
call("/api/projects", "POST", {"code": "SORTV", "name": "Sort"}, token=admin)
call("/api/targets?project=SORTV", "POST", {"host": "s1.acme.example"},
     token=admin)
for _t, _sev in (("info one", "info"), ("critical one", "critical"),
                 ("medium one", "medium"), ("high one", "high"),
                 ("low one", "low")):
    call("/api/vulns?project=SORTV", "POST",
         {"host": "s1.acme.example", "title": _t, "severity": _sev},
         token=admin)

_st, _pg = call("/api/vulns?project=SORTV&sort=severity&order=asc&limit=10",
                token=admin)
_order = [i["severity"] for i in (_pg or {}).get("items", [])]
check("severity ascending is worst first, not alphabetical",
      _order == ["critical", "high", "medium", "low", "info"], _order)
_st, _pg = call("/api/vulns?project=SORTV&sort=severity&order=desc&limit=10",
                token=admin)
check("...and descending is the exact reverse",
      [i["severity"] for i in (_pg or {}).get("items", [])]
      == ["info", "low", "medium", "high", "critical"], _pg)

# A finding can carry several proofs -- one written by auto_poc and one
# written by hand after it was rejected. Joining them straight to the
# listing would return that finding once per proof, and a table that
# silently triples some of its rows is a worse bug than the one the
# join is there to fix.
_st, _v = call("/api/vulns?project=SORTV", "POST",
               {"host": "s1.acme.example", "title": "many proofs",
                "severity": "high"}, token=admin)
_MV = (_v or {}).get("id")


async def _three_proofs():
    # Inserted, not asked for. `POST /vulns/{id}/poc` asks a MODEL to
    # write one and creates nothing without one configured, so a test
    # built on it would assert against zero proofs and pass whatever
    # the join did -- which is exactly what the first version of this
    # did, checked by breaking the join and watching it still pass.
    from app.models import Vuln as _V
    async with SessionLocal() as s_:
        tid = (await s_.execute(
            select(_V.target_id).where(_V.id == _MV))).scalar_one()
        assert tid is not None
        for n in range(3):
            s_.add(Poc(vuln_id=_MV, target_id=tid, title=f"proof {n}",
                       template="id: t\ninfo:\n  name: t\n",
                       status="draft"))
        await s_.commit()
        return int((await s_.execute(
            select(func.count()).select_from(Poc)
            .where(Poc.vuln_id == _MV))).scalar_one())


_np = asyncio.run(_three_proofs())
check("three proofs really exist to join against", _np == 3, f"{_np}")
_st, _pg = call("/api/vulns?project=SORTV&limit=50", token=admin)
_ids = [i["id"] for i in (_pg or {}).get("items", [])]
check("a finding with three proofs appears exactly once",
      _ids.count(_MV) == 1, f"{_ids.count(_MV)} times")
check("...and the page total counts it once too",
      (_pg or {}).get("total") == len(_ids), _pg and _pg.get("total"))

# Sorting by the proof column is now a database question as well.
_st, _pg = call("/api/vulns?project=SORTV&sort=poc_state&order=asc&limit=50",
                token=admin)
_states = [i["poc_state"] for i in (_pg or {}).get("items", [])]
check("poc_state ascending puts evidence first",
      _states == sorted(_states,
                        key=lambda x: {"Available, Confirmed": 0,
                                       "Available, Not Confirmed": 1,
                                       "Not Available": 2}[x]), _states)

# And a chained filter, which this endpoint had no way to take before.
_st, _pg = call('/api/vulns?project=SORTV&limit=50&filters='
                '[{"field":"severity_name","op":"equals","value":"critical"}]',
                token=admin)
check("a column filter is applied in SQL", _st == 200, f"{_st} {_pg}")
check("...and returns only that severity",
      {i["severity"] for i in (_pg or {}).get("items", [])} == {"critical"},
      _pg)
_st, _ = call('/api/vulns?project=SORTV&filters='
              '[{"field":"notacolumn","op":"equals","value":"x"}]', token=admin)
check("...while a column the endpoint never exposed is refused",
      _st in (400, 422), _st)

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
