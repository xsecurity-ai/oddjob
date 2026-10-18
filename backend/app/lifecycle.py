"""What happened to a finding between one scan and the next.

Oddjob could say a finding existed. It could never say one had gone
away. A `Vuln` row written in March sat at `open` for ever, through
nine re-scans that no longer saw it, because nothing recorded that
anybody had looked again.

That is the half of recurring scanning a client actually buys. "What
is new since last month, what is still there, what did we fix" is
the question; a list that only ever grows cannot answer any of it.

# The rule this is built around

**A finding missing from a new scan is not evidence it was fixed.**

It is evidence of nothing at all unless the new scan COULD have
found it. A nuclei run with a narrower template set, a scan that
errored half way, an nmap of a different port range, a host that was
down that day -- each produces an absence, and none of them is a
remediation. Treating absence as a fix is how a client is told a
vulnerability is closed while it is listening on the same port.

So resolution is never inferred from silence. It requires a
positive record that a tool which reports this kind of finding
looked at this host and came back without it:

    finding_sweeps       scanner X looked at target T at time A
    vulns.last_seen_at   a scan reported this finding at time B

    A > B  ->  a look that could have found it, did not  -> resolved
    A = B  ->  the last look found it                    -> present
    no A   ->  nobody has looked since                   -> unconfirmed

`unconfirmed` is the answer that matters most and the one a simpler
design would have thrown away. It is not a weaker "present" and not
a hedged "resolved": it is the tool saying it does not know, which
is the truth whenever the last word on a host is months old.

# Per scanner, deliberately

The sweep is recorded per `(target, scanner)` and matched the same
way. An nmap run says nothing about whether a Burp finding is still
there, and letting any scan resolve any finding would make a port
sweep close a web vulnerability.

A finding with no scanner -- one somebody typed in, or one from an
import whose format predates this -- is never resolved by a sweep.
Nobody is responsible for looking for it again, and a person's
finding is not something a tool gets to close.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import FindingSweep, RunManifest, Vuln

#: What a finding is doing, as of the last time anybody looked.
#:
#: Four answers, not three. The report vocabulary everyone asks for
#: is new/present/resolved, and the fourth is the one that keeps the
#: other three honest.
NEW = "new"
PRESENT = "present"
RESOLVED = "resolved"
UNCONFIRMED = "unconfirmed"

STATES = (NEW, PRESENT, RESOLVED, UNCONFIRMED)

#: How each one reads to somebody who has to act on it.
MEANING: dict[str, str] = {
    NEW: "reported for the first time by the most recent scan",
    PRESENT: "reported again by the most recent scan",
    RESOLVED: "a scan that reports this kind of finding has looked "
              "since and did not report it",
    UNCONFIRMED: "nothing that reports this kind of finding has looked "
                 "since it was last seen, so whether it is still there "
                 "is not known",
}


@dataclass(frozen=True)
class Verdict:
    state: str
    #: The sentence behind the state. A lifecycle shown without one
    #: is a claim the reader has to take on trust, and "resolved" is
    #: the claim that most deserves not to be.
    why: str
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    last_looked: datetime | None = None
    #: The run manifests behind the comparison, so a UI can show
    #: WHICH part of the configuration changed rather than only that
    #: something did. See `app/manifest.differences`.
    found_by: str | None = None
    looked_with: str | None = None


def _aware(d: datetime | None) -> datetime | None:
    """SQLite hands back naive datetimes. Everything here is UTC."""
    if d is None:
        return None
    from datetime import UTC
    return d if d.tzinfo else d.replace(tzinfo=UTC)


def verdict(scanner: str | None, first_seen: datetime | None,
            last_seen: datetime | None,
            last_looked: datetime | None,
            found_by: str | None = None,
            looked_with: str | None = None) -> Verdict:
    """One finding's state. Pure, so it can be tested without a database.

    `last_looked` is the most recent sweep by THIS finding's scanner
    over THIS finding's target, or None if there has never been one.

    `found_by` and `looked_with` are the run manifests of the scan
    that reported it and the scan that swept afterwards — see
    `app/manifest.py`. They close the hole in `resolved`:

        nuclei -severity critical,high   found CVE-2021-44228
        nuclei -severity critical        did not

    Same tool, same host, later timestamp, and nothing about any of
    those says the second run was configured not to look. When both
    manifests are known and they differ, the sweep proves nothing
    and the answer is `unconfirmed`.

    When either is NULL the configuration was not recorded — every
    scan imported before manifests existed, and every file somebody
    uploads by hand. That is not the same as "configured
    differently", so it still resolves; the sentence says the claim
    is the weaker one.
    """
    first_seen, last_seen = _aware(first_seen), _aware(last_seen)
    last_looked = _aware(last_looked)

    if not scanner:
        # Nobody is responsible for looking for it again. A person's
        # finding is not something a tool gets to close, and an
        # import format that never recorded its scanner cannot be
        # matched to a sweep either.
        return Verdict(UNCONFIRMED,
                       "recorded without a scanner, so no sweep can "
                       "confirm or clear it", first_seen, last_seen, None)
    if last_seen is None:
        return Verdict(UNCONFIRMED,
                       "no scan has been recorded as reporting this",
                       first_seen, None, last_looked)
    if last_looked is None:
        return Verdict(UNCONFIRMED,
                       f"no {scanner} scan of this host has been recorded "
                       f"since this was last seen", first_seen, last_seen,
                       None)
    if last_looked > last_seen:
        if found_by and looked_with and found_by != looked_with:
            # A sweep that was configured differently has not looked
            # for this. The absence is a fact about the command line,
            # not about the client's estate.
            return Verdict(UNCONFIRMED,
                           f"{scanner} did look at this host on "
                           f"{last_looked:%Y-%m-%d %H:%M} UTC, but it was "
                           f"configured differently from the run that "
                           f"found this, so not reporting it proves "
                           f"nothing", first_seen, last_seen, last_looked,
                           found_by, looked_with)
        same = bool(found_by and looked_with)
        why = (f"{scanner} looked at this host on "
               f"{last_looked:%Y-%m-%d %H:%M} UTC and did not report it; "
               f"it was last seen on {last_seen:%Y-%m-%d %H:%M} UTC")
        # The weaker claim, said as the weaker claim. A `resolved`
        # established two different ways must not read identically,
        # or the word stops meaning one thing.
        why += (" (the sweep ran the same configuration that found it)"
                if same else
                " — though the configuration of one or both runs was not "
                "recorded, so they cannot be shown to be comparable")
        return Verdict(RESOLVED, why, first_seen, last_seen, last_looked,
                       found_by, looked_with)
    # Seen by the most recent sweep. New if that sweep is also the
    # first time it was ever seen.
    if first_seen is not None and first_seen >= last_looked:
        return Verdict(NEW, f"first reported by the {scanner} scan of "
                            f"{last_looked:%Y-%m-%d %H:%M} UTC",
                       first_seen, last_seen, last_looked)
    return Verdict(PRESENT,
                   f"still reported by {scanner} as of "
                   f"{last_seen:%Y-%m-%d %H:%M} UTC",
                   first_seen, last_seen, last_looked)


async def record_sweep(session: AsyncSession, project_id: int,
                       target_id: int, scanner: str,
                       at: datetime, manifest: str | None = None) -> None:
    """Note that `scanner` looked at this host. Caller commits.

    One row per (target, scanner), carrying the LAST time rather than
    every time. An append log over months of recurring scanning would
    be enormous and would answer no question this does not: nothing
    here asks "how many times", only "when last".
    """
    scanner = (scanner or "").strip()[:64]
    if not scanner or not target_id:
        return
    row = (await session.execute(select(FindingSweep).where(
        FindingSweep.target_id == target_id,
        FindingSweep.scanner == scanner))).scalar_one_or_none()
    if row is None:
        session.add(FindingSweep(project_id=project_id, target_id=target_id,
                                 scanner=scanner, at=at, manifest=manifest))
        return
    # Never backwards. Importing a file from last week must not make
    # the tool believe nobody has looked since -- that would turn
    # every present finding on the host into `unconfirmed`.
    if _aware(row.at) is None or at > _aware(row.at):
        row.at = at
        # The manifest travels with the timestamp. They describe one
        # event, and a row carrying March's configuration beside
        # May's timestamp would answer "was it comparable" about a
        # run that never happened.
        #
        # Except when the caller has none to give. `None` means "this
        # caller cannot say what the run was configured to do", which
        # is true of the backlog sweep -- it reads a stored column,
        # not a command line -- and is not a statement that the
        # configuration was unknown at the time. Overwriting on it
        # would make every restart degrade what the imports knew.
        if manifest:
            row.manifest = manifest


async def remember_manifest(session: AsyncSession, scanner: str,
                            manifest: str, detail: dict,
                            at: datetime) -> None:
    """Store what a manifest hash MEANS, once. Caller commits.

    A hash that cannot be explained is a hash nobody will trust when
    it says two runs differ, and "the configuration changed" is only
    actionable if somebody can see which part.
    """
    if not manifest:
        return
    if await session.get(RunManifest, manifest) is not None:
        return
    session.add(RunManifest(manifest=manifest, scanner=(scanner or "")[:64],
                            detail=json.dumps(detail, sort_keys=True),
                            first_seen_at=at))


#: What a sweep lookup answers with: when, and with what
#: configuration. One tuple rather than two tables, because the two
#: are read together every time and keeping them apart would be one
#: more pair of things to hold in step.
Sweep = tuple[datetime | None, str | None]


async def sweeps_for(session: AsyncSession,
                     project_id: int) -> dict[tuple[int, str], Sweep]:
    """(target_id, scanner) -> (when it was last looked at, with what).

    Loaded whole for a project rather than queried per finding: a
    report over 4,000 findings would otherwise be 4,000 queries, and
    the sweep table has one row per host per tool.
    """
    rows = (await session.execute(select(
        FindingSweep.target_id, FindingSweep.scanner, FindingSweep.at,
        FindingSweep.manifest)
        .where(FindingSweep.project_id == project_id))).all()
    return {(t, s): (_aware(a), m) for t, s, a, m in rows}


async def sweeps_for_targets(
        session: AsyncSession, target_ids) -> dict[tuple[int, str], Sweep]:
    """The same table, for an arbitrary set of hosts.

    What a listing needs: a page of findings can span projects, and
    it is bounded by the page rather than by the engagement. An empty
    set asks nothing rather than selecting the table.
    """
    ids = {int(t) for t in target_ids if t}
    if not ids:
        return {}
    rows = (await session.execute(select(
        FindingSweep.target_id, FindingSweep.scanner, FindingSweep.at,
        FindingSweep.manifest)
        .where(FindingSweep.target_id.in_(ids)))).all()
    return {(t, s): (_aware(a), m) for t, s, a, m in rows}


def verdict_for(v: Vuln, sweeps: dict[tuple[int, str], tuple]) -> Verdict:
    """One `Vuln` row against a project's sweep table.

    `sweeps` maps (target, scanner) to (when, manifest). The tuple
    rather than a bare timestamp because the two are read together
    every time and a second lookup table would be a second thing to
    keep in step.
    """
    hit = sweeps.get((v.target_id, v.scanner)) if v.scanner else None
    at, with_ = hit if hit else (None, None)
    return verdict(v.scanner, v.first_seen_at, v.last_seen_at, at,
                   getattr(v, "found_by_manifest", None), with_)


def summarise(verdicts) -> dict[str, int]:
    """How many findings are in each state.

    Every state is present in the answer even at zero. A summary that
    omits `resolved` because nothing was resolved reads as a tool
    that cannot answer the question, and the whole point of this is
    that it can.
    """
    out = dict.fromkeys(STATES, 0)
    for v in verdicts:
        out[v.state] = out.get(v.state, 0) + 1
    return out
