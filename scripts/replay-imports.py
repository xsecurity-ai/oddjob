"""Import tool output that was delivered while no importer existed.

A task kind registered in `TASK_KINDS` with `None` has its findings
thrown away: the agent runs the tool at a client, posts the result
back, and the server stores the blob on the task and files nothing.
The Web view reads `web_addresses`; nothing writes there. Nothing
errors, because nothing is asked to.

This has now happened twice, which is why the script is
parameterised rather than written again:

* **2026-10-12** -- `katana` and `gospider`. 1,219 finished crawls
  holding 294,157 URLs, which became 24,937 distinct addresses
  across 576 hosts.
* **2026-10-13** -- `gobuster`. 1,128 finished content-discovery
  runs holding 36,540 paths, of which 25,361 were a 401 or a 403:
  the path exists and is protected, which is frequently the more
  useful answer than a 200.

Kept in the repository rather than thrown away because between them
these wrote most of the web inventory and that should be auditable.

Usage, from the backend directory or with PYTHONPATH set to it:

    python scripts/replay-imports.py gobuster               # dry run
    python scripts/replay-imports.py gobuster --apply
    python scripts/replay-imports.py crawl --apply          # katana

The deployed image is distroless and has no shell, so in production
it is:

    docker exec -w /app/backend -e PYTHONPATH=/app/backend \
        oddjob-app python /tmp/replay-imports.py gobuster --apply

Deliberately the SAME path a live delivery takes: `scans._run` with
`mode="strict"` and no decisions, which is exactly what
`deliver_result` does. A replay that imported more permissively than
the real thing would put rows in the inventory that a normal run
would have surveyed and held.

Resumable and idempotent-ish: only tasks with no `import_result` are
touched, and each is committed on its own, so a failure partway
leaves the work done so far done. Re-running picks up where it
stopped.

Read-only on the agents. Nothing is re-queued and no packets are sent.
"""
import asyncio
import json
import sys

from sqlalchemy import select

from app.db import SessionLocal
from app.models import Agent, AgentTask, Project
from app.routers.scans import _run

#: format -> the task kinds whose output that format reads.
#:
#: Keyed by FORMAT rather than by kind because that is what `_run` is
#: given, and because one format can read several kinds: `crawl`
#: reads katana's output and the gospider runner's, which wrote the
#: same shape.
REPLAYABLE: dict[str, tuple[str, ...]] = {
    "crawl": ("katana", "gospider"),
    "gobuster": ("gobuster",),
}


def _count(fmt: str, output: str) -> int:
    """How many findings a stored result holds, for the dry run."""
    try:
        doc = json.loads(output)
    except ValueError:
        return 0
    if not isinstance(doc, dict):
        return 0
    if fmt == "gobuster":
        for key in ("hits", "found"):
            if isinstance(v := doc.get(key), list) and v:
                return len(v)
        return 0
    for key in ("pages", "urls"):
        if isinstance(v := doc.get(key), list) and v:
            return len(v)
    return 0


async def main(fmt: str, apply: bool) -> int:
    kinds = REPLAYABLE[fmt]
    async with SessionLocal() as s:
        rows = (await s.execute(
            select(AgentTask).where(
                AgentTask.kind.in_(kinds),
                AgentTask.status == "done",
                AgentTask.import_result.is_(None),
            ).order_by(AgentTask.id))).scalars().all()

        usable = [t for t in rows if (t.output or "").strip()]
        print(f"{len(rows)} finished {'/'.join(kinds)} task(s) with no "
              f"import_result; {len(usable)} carry output")
        if not apply:
            total = sum(_count(fmt, t.output) for t in usable)
            print(f"they hold {total:,} finding(s) in total")
            print("dry run — pass --apply to import")
            return 0

        ok = failed = 0
        agents: dict[int, str] = {}
        for i, t in enumerate(usable, 1):
            pr = await s.get(Project, t.project_id)
            if pr is None:
                continue
            if t.agent_id and t.agent_id not in agents:
                a = await s.get(Agent, t.agent_id)
                agents[t.agent_id] = a.name if a else str(t.agent_id)
            src = f"ghost:{agents.get(t.agent_id, 'replay')}"
            try:
                res = await _run(s, pr, t.output, fmt, src,
                                 mode="strict", decisions={})
                t.import_as = fmt          # was NULL; record what read it
                t.import_result = res.model_dump_json()
                await s.commit()
                ok += 1
            except Exception as e:                      # noqa: BLE001
                await s.rollback()
                # Recorded on the task, exactly as a live failed import
                # is, so a result that could not be read says so rather
                # than looking untouched and being retried for ever.
                t.import_as = fmt
                t.import_result = json.dumps({"error": str(e)[:500]})
                await s.commit()
                failed += 1
            if i % 25 == 0:
                print(f"  {i}/{len(usable)}  ok={ok} failed={failed}",
                      flush=True)

        print(f"done: {ok} imported, {failed} could not be read")
        return 0


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    chosen = args[0] if args else ""
    if chosen not in REPLAYABLE:
        print(f"usage: {sys.argv[0]} {{{'|'.join(REPLAYABLE)}}} [--apply]")
        raise SystemExit(2)
    raise SystemExit(asyncio.run(main(chosen, "--apply" in sys.argv)))
