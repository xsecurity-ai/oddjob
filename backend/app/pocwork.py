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

#: What the operator reads on a finding. The spec for this feature
#: named these two strings; the third is what the three-state
#: contract needs and the other two cannot say.
CREATED = "PoC created"
UNVALIDATED = "PoC created, not validated"


def label(poc: Poc) -> str:
    """The one line a table cell shows for a proof.

    `validated_at` and not `exit_code`, because a proof that ran and
    could not test is still an unvalidated proof -- the run happened
    and settled nothing. Reading the exit code alone would call that
    validated and show a verdict nobody should act on.
    """
    if poc.validated_at is None or poc.exit_code == 2:
        return UNVALIDATED
    return CREATED


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
