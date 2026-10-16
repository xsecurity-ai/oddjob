"""Re-scan the hosts whose port scan never asked what was listening.

`profile: quick` used to build `-T4 -F -sS` and no `-sV`, so it
reported which ports were open and nothing whatever about them. On
the production estate that was 993 of 1,997 nmap runs, and the result
was a Services view holding 2,033 services with 11 versions and 49
banners between them -- every SSH service on the estate with a blank
product, despite SSH announcing itself in its first packet.

The flag is fixed, but that only helps scans not yet run. These hosts
are recorded as covered, so nothing will revisit them on its own:
the standing orders are "one attempt per subject, ever", and they are
right to be. Catching up is a deliberate act, which is this script.

**It asks the application what is owed rather than deciding.**
`_unscanned_by_technique` is the same function behind
`GET /api/targets/unscanned?technique=version`, which is what the
Scan dialog calls. Coverage is per (host, port range, technique), so
a host swept with `-sS` on the top 100 owes `version` on exactly
those ports and not on the 65,435 nobody has touched. Queueing the
gap rather than the range is the difference between one short scan
per host and a full re-sweep of the estate.

**Queued through `queue_per_host`**, which is the same path the UI
and the assistant use. That matters for three reasons and each one
has been a bug somewhere: every subject is scope-checked
individually, a host already in flight is not queued twice, and the
timeline records who asked. Writing tasks straight into the table
would skip all three.

`technique: "version"` rather than `profile: "quick"` because the
agents in the field are still running the old binary -- the one whose
quick profile omits `-sV`. `version` maps to `-sV` on both the old
build and the new one, so the rescan does not depend on a deploy
having landed first.

Nothing is sent by this script. It queues; a Ghost asks for work when
it is ready, and the client-facing rate is set at dispatch by
`max_parallel` and the memory clamp, exactly as for any other task.

Usage, from the backend directory or with PYTHONPATH set to it:

    python scripts/rescan-for-versions.py FALCON            # dry run
    python scripts/rescan-for-versions.py FALCON --apply

In production the image is distroless and has no shell:

    docker exec -w /app/backend -e PYTHONPATH=/app/backend \
        oddjob-app python /tmp/rescan-for-versions.py FALCON --apply
"""
import asyncio
import json
import sys

from sqlalchemy import select

from app.db import SessionLocal
from app.models import SITE_ADMIN_GROUP, AgentTask, Group, Project, Target
from app.routers.agents import queue_per_host
from app.routers.targets import _unscanned_by_technique

#: What the audit log records as the origin of these tasks.
#:
#: `audit_events.source` is varchar(16) and an over-long value does
#: not truncate -- Postgres refuses the INSERT, which rolls back the
#: session mid-run and takes the uncommitted tasks with it. Asserted
#: rather than counted by eye.
SOURCE = "rescan-versions"
assert len(SOURCE) <= 16

#: How many to queue in one run. Not a rate limit -- queueing is not
#: scanning, and the client-facing rate is set at dispatch -- but a
#: ceiling on how wrong one invocation can be. Re-run to take more.
BATCH = 2000


async def main(code: str, apply: bool, batch: int) -> int:
    async with SessionLocal() as s:
        pr = (await s.execute(
            select(Project).where(Project.code == code.upper()))
        ).scalar_one_or_none()
        if pr is None:
            print(f"no project {code!r}")
            return 2

        rows = (await s.execute(
            select(Target).where(Target.project_id == pr.id,
                                 Target.kind != "mobile")
            .order_by(Target.host))).scalars().unique().all()

        owed = await _unscanned_by_technique(s, pr, rows, "version", "")

        # Hosts this script has already asked about, excluded.
        #
        # Coverage is the right question but it cannot answer this
        # one on its own: it is recorded against a TARGET, and a scan
        # that found the host down has no target to record anything
        # against. On production 373 of 830 completed scans saw zero
        # hosts, so the owed list does not shrink when they finish
        # and a second run would send every one of them again.
        #
        # "Has this already been asked" is the honest floor, and it
        # is the same distinction the module docstring in
        # app/automation.py draws: having been TRIED is what counts,
        # not having succeeded.
        prior: set[str] = set()
        for (raw,) in (await s.execute(
                select(AgentTask.args).where(
                    AgentTask.project_id == pr.id,
                    AgentTask.kind == "nmap"))).all():
            try:
                a = json.loads(raw or "{}")
            except ValueError:
                continue
            if a.get("technique") != "version":
                continue
            for t in a.get("targets") or []:
                prior.add(str(t).lower())

        skipped = [g for g in owed["gaps"] if g["host"].lower() in prior]
        gaps = [g for g in owed["gaps"]
                if g["host"].lower() not in prior][:batch]

        print(f"{owed['considered']} target(s) considered")
        print(f"{owed['count']} still owe a version scan "
              f"on the ports a quick scan covers")
        print(f"{owed['out_of_scope']} owed it but are out of scope "
              f"and are NOT queued")
        print(f"{len(skipped)} have already been asked once and are skipped; "
              f"{len(gaps)} to queue")
        if not gaps:
            print("nothing to do")
            return 0
        for g in gaps[:10]:
            print(f"  {g['host']}  ports {g['ports']}  ({g['count']})")
        if len(gaps) > 10:
            print(f"  …and {len(gaps) - 10} more")

        if not apply:
            print("\ndry run — pass --apply to queue")
            return 0

        # An existing admin, so the timeline says a person asked and
        # the ACL checks inside the queue path have someone to check.
        # Never a user this script creates: minting an account to do
        # its own work would put a credential in the database that
        # nobody decided to add.
        # Site-wide authority here is membership of the reserved
        # group, not a per-user flag -- one mechanism, see models.py.
        grp = (await s.execute(
            select(Group).where(Group.name == SITE_ADMIN_GROUP))
        ).scalar_one_or_none()
        who = sorted(grp.users, key=lambda u: u.id)[0] if grp and grp.users else None
        if who is None:
            print(f"no member of {SITE_ADMIN_GROUP} to attribute the queue to")
            return 2

        queued = refused = 0
        # Per host, because the port gap differs per host and the
        # whole point is to ask each one only about its own gap.
        for g in gaps:
            r = await queue_per_host(
                s, pr, "nmap", [g["host"]],
                {"technique": "version", "ports": g["ports"]},
                who, source=SOURCE)
            # `queued` is a count and `ids` is the list; the two have
            # been confused before, so read the one that is a number.
            queued += int(r.get("queued", 0))
            refused += len(r.get("refused", {}) or {})
            if (queued + refused) % 100 == 0:
                await s.commit()
                print(f"  {queued} queued, {refused} refused", flush=True)
        await s.commit()
        print(f"done: {queued} queued, {refused} refused by the scope gate")
        return 0


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    if not args:
        print(f"usage: {sys.argv[0]} <PROJECT> [--apply] [--batch N]")
        raise SystemExit(2)
    n = BATCH
    for a in sys.argv[1:]:
        if a.startswith("--batch="):
            n = int(a.split("=", 1)[1])
    raise SystemExit(asyncio.run(main(args[0], "--apply" in sys.argv, n)))
