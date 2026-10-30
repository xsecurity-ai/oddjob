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
from app.pocwork import CREATED, UNVALIDATED, apply_result, label  # noqa: E402

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

print("\n== the label the operator reads ==")
_val = Poc(id=1, target_id=1, title="t")
asyncio.run(apply_result(FakeSession(_val), 1, payload(0)))
check("a validated proof reads 'PoC created'",
      label(_val) == CREATED, label(_val))
_built = Poc(id=2, target_id=1, title="t", template="id: x")
check("one that has never run reads 'PoC created, not validated'",
      label(_built) == UNVALIDATED, label(_built))
# The case the two strings in the spec cannot express on their own: a
# run happened and settled nothing. Reading `exit_code` alone would
# call that validated and show a verdict nobody should act on.
_untested = Poc(id=3, target_id=1, title="t")
asyncio.run(apply_result(FakeSession(_untested), 3, payload(2)))
check("...and so does one that ran but could not test",
      label(_untested) == UNVALIDATED, label(_untested))

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

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
