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


print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
