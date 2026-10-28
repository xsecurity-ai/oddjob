"""The rules of engagement, enforced rather than filed.

An authorisation letter says three things. Oddjob could read one:

    hosts        -> app/scope.py, enforced since the beginning
    dates        -> nothing
    techniques   -> nothing

So an engagement that ended on the 14th went on scanning on the
20th, and a client who wrote "no intrusive testing" got nuclei
templates that send payloads, because nothing in the system knew
those sentences existed.

The tests that matter most here are the ones about the DEFAULT. This
arrived after engagements were already running, so it is permissive
unless a project says otherwise — and a safety feature that is off
by default is only honest if it is off in a way somebody can see.
"""

import pathlib as _pathlib
import sys as _sys

_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parents[1]))
import json
import os
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta

BASE = os.environ.get("ODDJOB_TEST_BASE", "http://127.0.0.1:8033")
ok = fail = 0


def check(label, cond, extra=""):
    global ok, fail
    if cond: ok += 1; print(f"  PASS  {label}")
    else: fail += 1; print(f"  FAIL  {label} {extra}")


def call(p, m="GET", b=None, token=None, key=None):
    r = urllib.request.Request(BASE + p, method=m)
    if b is not None:
        r.data = json.dumps(b).encode()
        r.add_header("Content-Type", "application/json")
    if token: r.add_header("Authorization", f"Bearer {token}")
    if key: r.add_header("X-Agent-Key", key)
    try:
        with urllib.request.urlopen(r, timeout=60) as x:
            raw = x.read(); return x.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try: return e.code, json.loads(raw)
        except Exception: return e.code, raw[:300]


print("== every task kind is classified ==")
from app import roe
from app.models import IMPACT_CHOICES
from app.routers.agents import TASK_KINDS

# The assertion this file exists for. A kind absent from `IMPACT` is
# a kind the ceiling does not apply to, and it would be absent
# SILENTLY -- which is the exact shape of the scope-gate hole where
# six argument names were checked and nine were not. Adding a runner
# has to force a decision about what it does to a client.
_gap = roe.missing(TASK_KINDS)
check("no task kind is missing an impact classification",
      _gap == [], f"unclassified: {_gap}")
check("every classification is a rank this tool orders",
      all(v in roe.RANK for v in roe.IMPACT.values()),
      sorted(set(roe.IMPACT.values()) - set(roe.RANK)))
check("every classification has a label a sentence can use",
      all(v in roe.LABEL for v in roe.RANK))
# Two vocabularies that can drift is the same bug waiting to happen.
check("the project's choices are the ranks an engagement can set",
      set(IMPACT_CHOICES) == set(roe.RANK) - {"internal"},
      (IMPACT_CHOICES, sorted(roe.RANK)))

# The classification itself, where it is load-bearing.
check("a SYN sweep is read-only", roe.impact_of("masscan") == "read_only")
check("a connect scan is read-only too -- being seen is not being "
      "changed", roe.impact_of("portscan") == "read_only")
check("technology fingerprinting is read-only",
      roe.impact_of("nuclei_tech") == "read_only")
# The two judgement calls, classified upward on purpose.
check("nmap is state-changing, because `vuln` is outside nmap's own "
      "`safe` category", roe.impact_of("nmap") == "state_changing")
check("a crawl is state-changing, because a link can be /logout",
      roe.impact_of("katana") == "state_changing")
# The judgement this one turns on: a headless browser does not fetch
# the page, it RUNS it. Whatever the author wrote to happen on load
# happens -- beacons, sockets, an XHR that writes a row. "It is only
# a screenshot" is how a read-only engagement would end up running a
# browser over a client's estate.
check("a screenshot is state-changing, because the browser executes "
      "the page's JavaScript",
      roe.impact_of("screenshot") == "state_changing")
check("...so a read-only engagement refuses it",
      roe.impact_refusal("screenshot", "read_only") is not None)
check("nuclei is state-changing", roe.impact_of("nuclei") == "state_changing")
check("confirming a CVE is state-changing, because confirming means "
      "sending the trigger",
      roe.impact_of("nuclei_confirm") == "state_changing")
check("an operator's shell is destructive, because it is unbounded",
      roe.impact_of("shell") == "destructive")

# An unknown kind must not come back read-only. A kind nobody
# classified is a kind nobody thought about, and guessing downward
# turns the oversight into permission.
check("an unknown kind is treated as destructive, not read-only",
      roe.impact_of("some_future_exploit_runner") == "destructive")
check("...so a read-only engagement refuses it",
      roe.impact_refusal("some_future_exploit_runner", "read_only") is not None)

print("\n== the ceiling ==")
check("read-only permits masscan",
      roe.impact_refusal("masscan", "read_only") is None)
check("read-only refuses nuclei",
      roe.impact_refusal("nuclei", "read_only") is not None)
check("...and the refusal says what the task is AND what is permitted",
      "state-changing" in roe.impact_refusal("nuclei", "read_only")
      and "read-only" in roe.impact_refusal("nuclei", "read_only"))
check("state-changing permits nuclei",
      roe.impact_refusal("nuclei", "state_changing") is None)
check("state-changing refuses a shell",
      roe.impact_refusal("shell", "state_changing") is not None)
check("destructive permits everything",
      all(roe.impact_refusal(k, "destructive") is None for k in roe.IMPACT))
check("an unset ceiling permits everything, which is the documented "
      "default", roe.impact_refusal("shell", None) is None)
# A typo must not open the gate.
check("a ceiling nothing recognises refuses everything",
      roe.impact_refusal("masscan", "readonly") is not None)
check("...and says the value is the problem, not the task",
      "not a value this tool knows"
      in roe.impact_refusal("masscan", "readonly"))

print("\n== the window ==")
_now = datetime(2026, 6, 15, 12, 0, tzinfo=UTC)
check("inside the window is allowed",
      roe.window_refusal(_now - timedelta(days=5), _now + timedelta(days=5),
                         _now) is None)
check("before it starts is refused",
      roe.window_refusal(_now + timedelta(days=1), None, _now) is not None)
check("...and says when authorisation begins",
      "has not started"
      in roe.window_refusal(_now + timedelta(days=1), None, _now))
_over = roe.window_refusal(None, _now - timedelta(days=1), _now)
check("after it ends is refused", _over is not None)
check("...and says the authorisation expired, not that it is 'invalid'",
      "expired" in _over, _over)
check("no dates at all is unbounded, which is what every project had "
      "before this existed",
      roe.window_refusal(None, None, _now) is None)
# Naive datetimes come back from SQLite. Treating one as local time
# would move an engagement boundary by hours.
check("a naive timestamp is read as UTC, not as local time",
      roe.window_refusal(None, datetime(2026, 6, 15, 11, 0), _now) is not None)
check("...on the start side too",
      roe.window_refusal(datetime(2026, 6, 15, 13, 0), None, _now) is not None)

# The dates are reported before the ceiling: an operator told "that
# technique is not permitted" for a task queued after the engagement
# ended will go and widen the ceiling, which fixes nothing.
class _P:
    engagement_starts_at = None
    engagement_ends_at = _now - timedelta(days=1)
    max_impact = "read_only"

check("when both refuse, the expiry is the sentence given",
      "expired" in (roe.refusal(_P, "nuclei", _now) or ""),
      roe.refusal(_P, "nuclei", _now))


print("\n== end to end ==")
admin = call("/api/auth/setup", "POST",
             {"username": "root", "password": "root-password-1"})[1]["access_token"]
st, _ = call("/api/projects", "POST", {"code": "ROE", "name": "ROE test"},
             token=admin)
check("project created", st in (200, 201), st)

st, p = call("/api/projects/ROE", token=admin)
_p = (p or {}).get("project", p) or {}
check("a new project's ceiling is permissive, and SAYS so",
      _p.get("max_impact") == "destructive", _p.get("max_impact"))
check("...with no dates, meaning unbounded",
      _p.get("engagement_starts_at") is None
      and _p.get("engagement_ends_at") is None, _p)

print("\n-- the technique ceiling refuses a task --")
st, _ = call("/api/projects/ROE", "PATCH", {"max_impact": "read_only"},
             token=admin)
check("the ceiling can be set", st == 200, st)
st, p2 = call("/api/projects/ROE", token=admin)
check("...and comes back from the API, not just into the database",
      ((p2 or {}).get("project", p2) or {}).get("max_impact") == "read_only",
      p2)

st, r = call("/api/ghosts/tasks/bulk?project=ROE", "POST",
             {"kind": "nuclei", "subjects": ["https://acme.example/"]},
             token=admin)
check("a state-changing task is refused under a read-only ceiling",
      st == 403, (st, r))
check("...and the refusal explains which rule, not just 'forbidden'",
      "read-only" in str(r), r)

st, r = call("/api/ghosts/tasks/bulk?project=ROE", "POST",
             {"kind": "masscan", "subjects": ["198.51.100.1"]},
             token=admin)
check("a read-only task is still permitted", st in (200, 201), (st, r))

print("\n-- an expired engagement refuses everything --")
_past = (datetime.now(UTC) - timedelta(days=1)).isoformat()
st, _ = call("/api/projects/ROE", "PATCH",
             {"max_impact": "destructive", "engagement_ends_at": _past},
             token=admin)
check("the end date can be set", st == 200, st)

st, r = call("/api/ghosts/tasks/bulk?project=ROE", "POST",
             {"kind": "masscan", "subjects": ["198.51.100.1"]},
             token=admin)
check("even a read-only task is refused once the engagement has ended",
      st == 403, (st, r))
check("...and the reason is the date, not the technique",
      "expired" in str(r), r)

print("\n-- clearing the window --")
# A PATCH must NOT be able to clear it by accident: None means
# "leave alone" for every other field here and consistency is what
# makes that safe.
st, _ = call("/api/projects/ROE", "PATCH", {"engagement_ends_at": None},
             token=admin)
st, p3 = call("/api/projects/ROE", token=admin)
check("a null in a PATCH does not remove the expiry",
      ((p3 or {}).get("project", p3) or {}).get("engagement_ends_at")
      is not None, p3)

st, _ = call("/api/projects/ROE/engagement-window", "DELETE", token=admin)
check("the explicit DELETE clears it", st == 204, st)
st, p4 = call("/api/projects/ROE", token=admin)
check("...and the project is unbounded again",
      ((p4 or {}).get("project", p4) or {}).get("engagement_ends_at") is None,
      p4)
st, r = call("/api/ghosts/tasks/bulk?project=ROE", "POST",
             {"kind": "masscan", "subjects": ["198.51.100.2"]},
             token=admin)
check("...and tasks run again", st in (200, 201), (st, r))

# Who removed the bound is a question asked after the fact.
st, a = call("/audit/json?limit=500", token=admin)
_acts = [e.get("action") for e in ((a or {}).get("entries") or [])]
check("clearing the window is audited",
      "project.engagement_window.clear" in _acts, _acts[:8])
check("changing the ceiling is audited too",
      "project.max_impact" in _acts, _acts[:8])

print("\n-- the dispatch gate, not only the queue gate --")
# A task queued inside the window and handed out a week later runs
# OUTSIDE it, and nothing at queue time could have seen that coming.
import inspect as _inspect

from app.routers import agents as _ag

_hb = _inspect.getsource(_ag.heartbeat)
check("the dispatch gate consults the rules of engagement",
      "roe.refusal" in _hb, "heartbeat() never calls it")
check("...before returning early on an undefined scope list",
      _hb.index("roe.refusal") < _hb.index("if not idx.defined"),
      "a project with no scope list would skip the window and ceiling")
check("the queue gate does too",
      "roe.refusal" in _inspect.getsource(_ag.queue_per_host)
      and "roe.refusal" in _inspect.getsource(_ag._assert_task_in_scope))
# The failure message must not send an operator to the wrong setting.
check("a dispatch refusal no longer blames the scope list alone",
      "refused by the project's scope at dispatch" not in _hb, _hb[:0])

print(f"\n{'='*56}\n  {ok} passed, {fail} failed\n{'='*56}")
_sys.exit(1 if fail else 0)
