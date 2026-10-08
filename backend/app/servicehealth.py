"""What each subsystem last actually did, and whether it worked.

Configuration does not answer "is Slack working". A token can be present
and valid while the workspace refuses every message, and the first
anybody hears of it is a finding that quietly never arrived. SMTP is
worse: a magic link that is never delivered looks, from this side,
exactly like one nobody clicked.

So nothing here is a synthetic probe. Probes test the probe, and a probe
that passes while real traffic fails is an alibi rather than a check.
Every record below is the outcome of a real send that something actually
wanted to make.

`note()` is called from INSIDE `slack.post` and `mailer.send_mail`, not
from their call sites. There are fourteen call sites between the two,
and a health page that silently misses one is worse than no health page
at all — it reports green for a path nobody is watching.

`fleet_versions()` at the bottom is the one thing here that is not a
record of an attempt. It lives in this module rather than in the router
because it is a pure function of a list of strings — no session, no
request — which makes it the only part of the ghost-version summary a
test can hold still and assert on. routers/health.py stays an assembler
that fetches rows and calls things; the judgement about what a split
fleet means belongs somewhere it can be exercised directly.
"""
from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta

from .models import ServiceHealth

log = logging.getLogger("oddjob.health")

#: Past this, "it worked once" stops being reassuring. Used only to
#: label a row, never to hide one.
STALE_AFTER = timedelta(days=7)


async def note(service: str, ok: bool, detail: str = "",
               error: str = "") -> None:
    """Record one real attempt. Never raises, and never blocks the caller.

    Opens its own session deliberately. The callers are `slack.post` and
    `send_mail`, which are reached from request handlers, background
    workers and the Slack socket loop alike — some hold a session, some
    hold one mid-transaction, and joining whichever happens to be open
    would make a health write able to roll back a user's actual work.
    """
    try:
        from .db import SessionLocal
        async with SessionLocal() as s:
            row = await s.get(ServiceHealth, service)
            if row is None:
                row = ServiceHealth(service=service)
                s.add(row)
            now = datetime.now(UTC)
            if ok:
                row.last_ok_at = now
                row.ok_count = (row.ok_count or 0) + 1
            else:
                row.last_error_at = now
                row.error_count = (row.error_count or 0) + 1
                # Kept after a later success on purpose. "Working now,
                # but it broke an hour ago" is usually the more useful
                # of the two facts, and clearing it on the next success
                # is how an intermittent fault stays invisible.
                row.last_error = (error or detail or "failed")[:500]
            if detail:
                row.last_detail = detail[:300]
            await s.commit()
    except Exception as e:                       # noqa: BLE001
        # A failure to record a failure must not become a third failure.
        # The caller is usually something that has promised not to raise.
        log.warning("could not record %s health: %s", service, e)


def _aware(dt: datetime | None) -> datetime | None:
    """UTC-stamp a timestamp the driver handed back naive.

    Postgres returns these aware and SQLite returns them naive, from the
    same column and the same model. Comparing a naive one to `now()`
    raises, so the health page worked against Postgres and crashed
    against the default deployment — which is the wrong way round for a
    page whose whole job is to be available when things are broken.
    """
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


def describe(row: ServiceHealth | None, *,
             never_used: str = "has never been used") -> dict:
    """One subsystem's row as the health page reads it.

    Three states, never two. "Working", "broken", and "nothing has ever
    tried" are different answers, and collapsing the third into either
    of the others is how a page comes to report green for something that
    has never run at all.
    """
    if row is None or (row.last_ok_at is None and row.last_error_at is None):
        return {"state": "unused", "note": never_used,
                "last_ok": None, "last_error_at": None, "last_error": None,
                "ok_count": 0, "error_count": 0}

    now = datetime.now(UTC)
    ok_at, err_at = _aware(row.last_ok_at), _aware(row.last_error_at)
    if ok_at is not None and (err_at is None or ok_at >= err_at):
        state = "ok"
        if now - ok_at > STALE_AFTER:
            state = "idle"          # worked, but not lately
    else:
        state = "failing"
    return {
        "state": state,
        "last_ok": ok_at.isoformat() if ok_at else None,
        "last_error_at": err_at.isoformat() if err_at else None,
        # Shown even when the state is ok: an error an hour ago that has
        # since recovered is exactly what somebody debugging wants.
        "last_error": row.last_error,
        "last_detail": row.last_detail,
        "ok_count": row.ok_count or 0,
        "error_count": row.error_count or 0,
    }


# ---------------------------------------------------------- versions
#
# What the fleet is actually running, which is a different question
# from what the newest ghost is running. A site admin chasing "this
# task behaves differently depending on which ghost takes it" needs to
# see the split; "the newest one is 0.1.0" tells them nothing, because
# the ghost that misbehaved is one of the other two.

#: `X.Y.Z`, with semver's optional pre-release and build-metadata
#: tails. Anchored, so a version that is merely version-shaped — an
#: old agent reporting `dev`, or a `git describe` string from before
#: VERSION existed — does not half-match and sort as though it parsed.
_SEMVER = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z.-]+))?"
    r"(?:\+[0-9A-Za-z.-]+)?$"
)


def semver_key(v: str) -> tuple:
    """Sort key putting the newest version first under `reverse=True`.

    Semver's own precedence rules, which differ from a string sort in
    two ways that both matter here:

    * `0.10.0` is newer than `0.9.0`. A lexical sort says the opposite,
      and this is the classic way a "which is newest" column starts
      lying somewhere around the tenth minor release.
    * `0.0.1-dev-1759900000` is OLDER than `0.0.1`. A pre-release
      precedes the release it leads to, so a developer's build of a
      version sorts below the release of it rather than above — which
      is what you want when the question is "is anything out here
      ahead of the server".

    Build metadata (`+...`) is matched and then ignored, because semver
    says it does not participate in precedence.

    Anything that does not parse sorts below everything that does. It
    is not a lower version — it is a thing we cannot order at all — and
    the only safe place to put an unorderable value in a "newest first"
    list is the end, where it is visibly not being claimed as newest.
    """
    m = _SEMVER.match(v or "")
    if not m:
        return (0, 0, 0, 0, 0, ())
    major, minor, patch, pre = m.groups()
    if pre is None:
        # The `1` outranks the `0` below: 1.0.0 beats 1.0.0-rc1.
        return (1, int(major), int(minor), int(patch), 1, ())
    # Dot-separated identifiers, compared left to right. A numeric
    # identifier is lower than an alphanumeric one, and numerics
    # compare numerically — so `rc.2` beats `rc.10` on a string sort
    # and loses here, correctly.
    ids = tuple(
        (0, int(part), "") if part.isdigit() else (1, 0, part)
        for part in pre.split(".")
    )
    return (1, int(major), int(minor), int(patch), 0, ids)


def fleet_versions(versions: Iterable[str | None], *,
                   server_version: str | None = None) -> dict:
    """Which versions the ghosts are running, and how many on each.

    `versions` is one entry per enrolled ghost, straight off
    `Agent.version` — including the Nones. A ghost that has never told
    us its version is counted separately and never folded into a
    bucket: "we do not know what that one is running" is a third
    answer, and quietly dropping those rows would make a fleet of ten
    with four silent ones look like a tidy fleet of six.

    `server_version` is Oddjob's own, so each row can say whether it
    matches. The common real question is not "are they all the same"
    but "are they the same as me", because that is the pair whose
    protocol has to line up.
    """
    counts: dict[str, int] = {}
    unreported = 0
    for raw in versions:
        v = (raw or "").strip()
        if not v:
            unreported += 1
            continue
        counts[v] = counts.get(v, 0) + 1

    rows = [
        {
            "version": v,
            "count": n,
            "matches_server": bool(server_version) and v == server_version,
            # Surfaced per row rather than inferred in the UI from a
            # substring: the marker is defined in one place
            # (version.DEV_MARKER) and the view should not be the
            # second place that knows what a dev build looks like.
            "dev": "-dev-" in v,
            # So the UI can grey out a row it cannot order rather than
            # presenting the end of the list as "oldest".
            "parsed": bool(_SEMVER.match(v)),
        }
        for v, n in counts.items()
    ]
    # Name as the tie-break, so two unparseable versions come out in a
    # stable order rather than in whatever order the rows arrived.
    rows.sort(key=lambda r: (semver_key(str(r["version"])), str(r["version"])),
              reverse=True)

    reported = sum(counts.values())
    total = reported + unreported
    if total == 0:
        state = "unused"
    elif unreported or len(rows) > 1:
        # Yellow, not red. A split fleet and a silent ghost are both
        # things to go and look at, and neither is an outage — calling
        # them failing is how a page teaches people to ignore it.
        state = "idle"
    else:
        state = "ok"

    if total == 0:
        note = "no ghosts are enrolled"
    elif unreported and len(rows) > 1:
        note = (f"{len(rows)} versions in use, and {unreported} ghost(s) have "
                f"not reported one")
    elif unreported:
        note = f"{unreported} ghost(s) have not reported a version"
    elif len(rows) > 1:
        note = f"the fleet is split across {len(rows)} versions"
    else:
        note = None

    return {
        "state": state,
        "note": note,
        "versions": rows,
        "distinct": len(rows),
        "reported": reported,
        "unreported": unreported,
        # The highest version anybody is running, or None when nobody
        # has reported a parseable one. Deliberately None rather than
        # the server's version: this field answers "what is out there",
        # and defaulting it to our own would answer a question nobody
        # asked with data we do not have.
        "newest": next((str(r["version"]) for r in rows if r["parsed"]), None),
        "matching_server": counts.get(server_version or "", 0),
        "server_version": server_version,
    }
