"""Turning a Ghost's verdict on a proof into the row that records it.

The exit contract is `Poc.exit_code`, which predates all of this:

    0  reproduced        the matchers fired; the finding is still real
    1  not reproduced    it ran and matched nothing: fixed, or moved
    2  could not test    no answer, so this proves nothing either way

**One and two are the distinction the feature turns on.** A template
that could not reach the host also matches nothing, and reporting
that as "fixed" would close a live finding on the strength of a
network error. The runner establishes reachability separately for
exactly this reason -- nuclei exits 0 when it cannot connect -- and
this module must not undo that by treating a missing verdict as a
clean one.

Nothing here closes a finding. A proof that does not reproduce is
recorded as not reproducing and the finding's own triage is left to a
person: "the check we wrote did not fire today" and "this is fixed"
are different claims, and only the first is ours to make.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession

from .models import Poc

#: What each exit code means, in the words the UI shows.
VERDICTS = {
    0: "reproduced",
    1: "not reproduced",
    2: "could not test",
}

#: What the operator reads in the PoC column of the findings table.
#:
#: Three states because there are three answers, and the middle one
#: is the reason the first two are not enough: a proof that needs a
#: credential nobody has, or a person to click a link, is a real
#: proof that cannot be run from here. Calling that "not available"
#: would throw away work somebody did; calling it "confirmed" would
#: claim a result nobody has seen.
NOT_AVAILABLE = "Not Available"
CONFIRMED = "Available, Confirmed"
UNCONFIRMED = "Available, Not Confirmed"


def availability(poc: Poc | None) -> str:
    """What the PoC column says for a finding. `poc` may be None.

    **Available means there is a script.** A `Rejected` build writes
    a row with no template, to record that a proof was attempted and
    could not be written -- that row must read "Not Available", or
    the column would advertise a proof that does not exist.

    **Confirmed means it ran here and worked**: exit 0, and a run
    that actually happened. `validated_at` and not `exit_code` alone,
    because a row that has never run has no exit code and a run that
    could not test settled nothing. Exit 1 -- it ran and matched
    nothing -- is also unconfirmed: that is a proof which did not
    work, which is exactly not confirmed.
    """
    if poc is None or not (poc.template or "").strip():
        return NOT_AVAILABLE
    if poc.validated_at is not None and poc.exit_code == 0:
        return CONFIRMED
    return UNCONFIRMED


def why_unconfirmed(poc: Poc | None) -> str | None:
    """The sentence behind "Not Confirmed", or None.

    A state word without its reason is a state word the reader has to
    take on trust, and this is the one that most deserves not to be:
    "never run", "the host did not answer" and "it ran and matched
    nothing" send an operator to three different places.
    """
    if availability(poc) != UNCONFIRMED or poc is None:
        return None
    if poc.validated_at is None:
        return "written, not run yet"
    return poc.verdict or VERDICTS.get(poc.exit_code or 2, "could not test")


async def apply_result(session: AsyncSession, poc_id: int,
                       output: str) -> Poc | None:
    """Record what a `poc` task reported. -> the row, or None.

    Tolerant of a payload it does not recognise, and deliberately so:
    the alternative is an exception inside the result handler, which
    would fail the whole import for a task that otherwise succeeded.
    An unreadable verdict is recorded as "could not test", which is
    the honest reading of it.
    """
    poc = await session.get(Poc, poc_id)
    if poc is None:
        return None
    try:
        body = (json.loads(output) or {}).get("poc") or {}
    except (ValueError, TypeError):
        body = {}

    code = body.get("exit_code")
    if code not in (0, 1, 2):
        code = 2
    poc.exit_code = code
    poc.validated_at = datetime.now(UTC)
    if t := body.get("target"):
        poc.target_url = str(t)[:2000]

    why = str(body.get("why") or "").strip()
    hits = body.get("hits") or []
    # The verdict, then the evidence or the reason there is none. A
    # reader who sees "reproduced" and nothing else has to take it on
    # trust, which is the one thing a proof is supposed to remove.
    parts = [VERDICTS[code]]
    if hits:
        at = [str(h.get("matched-at") or "") for h in hits
              if isinstance(h, dict) and h.get("matched-at")]
        parts.append(f"{len(hits)} match(es)"
                     + (f" at {', '.join(at[:3])}" if at else ""))
    if why:
        parts.append(why)
    poc.verdict = " — ".join(parts)[:4000]

    # `status` is the PoC's own lifecycle and is not the finding's.
    # Nothing here triages the vuln: "the check we wrote did not fire
    # today" and "this is fixed" are different claims.
    poc.status = {0: "confirmed", 1: "not_reproduced",
                  2: "unconfirmed"}[code]
    return poc
