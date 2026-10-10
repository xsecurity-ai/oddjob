"""Standing orders: the four policies a project can leave running.

These queue scans against a client's estate with nobody watching, which
is the whole reason they exist and also the reason this suite is the
shape it is. Three properties matter more than the feature working:

  * **Nothing runs unless it was switched on.** All four default off,
    and an upgrade must not inherit one.
  * **Nothing is queued that the scope gate refuses.** Per candidate,
    every cycle — not per project and not per batch.
  * **Nothing is queued twice.** A lookup that comes back empty leaves
    the host exactly as it was, so a policy phrased as "anything
    missing X" would re-queue it forever. Having been TRIED is what
    counts, not having succeeded. This is the one that would only show
    up in production, a week later, as a client asking why they are
    being scanned every minute.

`plan` is pure, so most of this describes an estate and asks what would
happen, rather than driving a server and inferring it.
"""

# Run from anywhere: the suites import `app`, which lives one level up.
import pathlib as _pathlib
import sys as _sys

_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parents[1]))
import json
import os
import urllib.error
import urllib.request

BASE = os.environ.get("ODDJOB_TEST_BASE", "http://127.0.0.1:8013")
ok = fail = 0


def check(l, c, e=""):
    global ok, fail
    if c: ok += 1; print(f"  PASS  {l} {e}")
    else: fail += 1; print(f"  FAIL  {l} {e}")


def call(p, m="GET", b=None, token=None):
    r = urllib.request.Request(BASE + p, method=m)
    if b is not None:
        r.data = json.dumps(b).encode()
        r.add_header("Content-Type", "application/json")
    if token: r.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(r, timeout=60) as x:
            raw = x.read(); return x.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try: return e.code, json.loads(raw)
        except Exception: return e.code, raw[:300]


from app.automation import (  # noqa: E402
    BATCH,
    NMAP_PROFILES,
    Snapshot,
    plan,
)
from app.models import NMAP_CHOICES  # noqa: E402

# =====================================================================
# Part 1 — what the policies choose
# =====================================================================
print("\n--- nothing happens until something is switched on ---")

ESTATE = [("web.acme.example", True), ("bare.acme.example", False),
          ("203.0.113.5", True), ("api.acme.example", False)]

check("an untouched project plans nothing",
      plan(Snapshot(targets=ESTATE)) == [])
check("...and that is the default a project is created with",
      Snapshot().auto_nmap == "off" and not Snapshot().auto_amass)

print("\n--- each policy picks what it is for, and nothing else ---")

p = plan(Snapshot(auto_resolve_ips=True, targets=ESTATE))
check("resolve picks the names with no address",
      [c.subject for c in p] == ["api.acme.example", "bare.acme.example"],
      [c.subject for c in p])
check("...and never an address, which has nothing to resolve",
      all(not c.subject[0].isdigit() for c in p))
check("...as nslookup", {c.kind for c in p} == {"nslookup"})

p = plan(Snapshot(auto_reverse_dns=True, targets=ESTATE))
check("reverse picks only the address-named host",
      [c.subject for c in p] == ["203.0.113.5"], [c.subject for c in p])
check("...as reverse_ip", {c.kind for c in p} == {"reverse_ip"})

p = plan(Snapshot(auto_amass=True, targets=ESTATE))
check("amass picks the zone once, not once per host",
      [c.subject for c in p] == ["acme.example"], [c.subject for c in p])
check("...and passes the domain, not a target list",
      p[0].args.get("domain") == "acme.example", p[0].args)

p = plan(Snapshot(auto_nmap="top100", targets=ESTATE))
check("nmap picks every host including the address",
      len(p) == 4, [c.subject for c in p])
check("...top100 is nmap's own -F, not a port list of ours",
      p[0].args == {"profile": "quick"}, p[0].args)
p = plan(Snapshot(auto_nmap="full", targets=ESTATE))
check("...and full names the range, because -p- and -F are exclusive",
      p[0].args == {"ports": "1-65535"}, p[0].args)
check("an unknown nmap setting plans nothing rather than guessing",
      plan(Snapshot(auto_nmap="medium", targets=ESTATE)) == [])
check("off plans nothing", plan(Snapshot(auto_nmap="off", targets=ESTATE)) == [])

print("\n--- the vocabulary is not written down twice ---")
check("models.NMAP_CHOICES and automation's profiles agree",
      set(NMAP_CHOICES) == {"off", *NMAP_PROFILES},
      f"{NMAP_CHOICES} vs {sorted(NMAP_PROFILES)}")

# =====================================================================
# Part 2 — never twice. The one that matters.
# =====================================================================
print("\n--- a subject is attempted once, not every cycle ---")

# The failure this prevents: the lookup ran, came back with nothing, and
# the host still has no address. "Anything missing an address" matches
# it again next minute, and the minute after that, forever.
tried = Snapshot(auto_resolve_ips=True, targets=ESTATE,
                 tasked={("nslookup", "bare.acme.example")})
check("a name already tried is not tried again",
      [c.subject for c in plan(tried)] == ["api.acme.example"],
      [c.subject for c in plan(tried)])
check("an empty result does not make it eligible again",
      [c.subject for c in plan(Snapshot(
          auto_resolve_ips=True, targets=ESTATE,
          tasked={("nslookup", "bare.acme.example"),
                  ("nslookup", "api.acme.example")}))] == [])

# Per kind, though: having been nslookup'd says nothing about nmap.
both = Snapshot(auto_resolve_ips=True, auto_nmap="top100", targets=ESTATE,
                tasked={("nslookup", "api.acme.example")})
kinds = {(c.kind, c.subject) for c in plan(both)}
check("...but only for the kind that was tried",
      ("nmap", "api.acme.example") in kinds
      and ("nslookup", "api.acme.example") not in kinds, sorted(kinds))

check("a zone already handed to amass is not handed again",
      plan(Snapshot(auto_amass=True, targets=ESTATE,
                    searched={"acme.example"})) == [])
check("...whether it was recorded as a search or as a task",
      plan(Snapshot(auto_amass=True, targets=ESTATE,
                    tasked={("amass", "acme.example")})) == [])

# =====================================================================
# Part 3 — a cycle does the whole backlog
# =====================================================================
print("\n--- a cycle leaves nothing for the next one ---")

# This used to assert the opposite: at most PER_CYCLE per policy, with
# the rest deferred. That cap paced the QUEUE and not the client's
# network -- a Ghost only ever runs what its memory-clamped
# max_parallel and heavy_allowance permit, however deep the queue is --
# so all it achieved was leaving work undone after an operator had
# asked for all of it.
N = BATCH * 4 + 7          # deliberately not a multiple of the batch size
big = [(f"h{i:04d}.acme.example", False) for i in range(N)]
p = plan(Snapshot(auto_resolve_ips=True, targets=big))
check("every outstanding subject is planned, none deferred", len(p) == N, len(p))
check("the order is stable, so an interrupted cycle resumes",
      [c.subject for c in p] == [c.subject for c in
                                 plan(Snapshot(auto_resolve_ips=True,
                                               targets=big))])
check("it still starts at the beginning", p[0].subject == "h0000.acme.example",
      p[0].subject)
check("nothing is dropped at a batch boundary",
      len({c.subject for c in p}) == N, len({c.subject for c in p}))

# Each policy is planned in full, rather than policies sharing one
# allowance and starving each other.
p = plan(Snapshot(auto_resolve_ips=True, auto_nmap="top100", targets=big))
check("two policies are both planned in full, not half each",
      len(p) == N * 2, len(p))

# An explicit limit is still honoured for callers that want one.
p = plan(Snapshot(auto_resolve_ips=True, targets=big), limit=10)
check("an explicit limit still caps it", len(p) == 10, len(p))

# =====================================================================
# Part 4 — against a live server: the gate, and the API
# =====================================================================
print("\n--- the settings round-trip, and refuse nonsense ---")

admin = call("/api/auth/setup", "POST",
             {"username": "root", "password": "root-password-1"})[1]["access_token"]
call("/api/projects", "POST", {"code": "AUTO2", "name": "Standing orders"},
     token=admin)

st, pr = call("/api/projects/AUTO2", token=admin)
check("a new project has every standing order off",
      pr.get("auto_amass") is False and pr.get("auto_resolve_ips") is False
      and pr.get("auto_reverse_dns") is False and pr.get("auto_nmap") == "off",
      {k: v for k, v in (pr or {}).items() if k.startswith("auto_")})

st, pr = call("/api/projects/AUTO2", "PATCH",
              {"auto_amass": True, "auto_nmap": "full"}, token=admin)
check("they can be switched on", st == 200, st)
check("...and come back as set",
      (pr or {}).get("auto_amass") is True and (pr or {}).get("auto_nmap") == "full",
      {k: v for k, v in (pr or {}).items() if k.startswith("auto_")})

st, body = call("/api/projects/AUTO2", "PATCH", {"auto_nmap": "aggressive"},
                token=admin)
check("an unknown nmap setting is refused, not coerced to off", st == 422, st)
st, pr = call("/api/projects/AUTO2", token=admin)
check("...and the refusal left the previous value alone",
      (pr or {}).get("auto_nmap") == "full", (pr or {}).get("auto_nmap"))

# A non-admin must not be able to start scanning a client's estate.
call("/api/users", "POST",
     {"username": "hand", "password": "hand-password-1"}, token=admin)
call("/api/projects/AUTO2/acl", "POST", {"username": "hand", "role": "user"},
     token=admin)
hand = call("/api/auth/login", "POST",
            {"username": "hand", "password": "hand-password-1"}
            )[1]["access_token"]
st, _ = call("/api/projects/AUTO2", "PATCH", {"auto_nmap": "top100"}, token=hand)
check("a plain user cannot switch scanning on", st == 403, st)

print("\n--- the scope gate refuses a candidate the policy wanted ---")
# Narrow the scope so the estate contains something out of it, then ask
# `run_once` directly: the worker is what has to consult the gate, and
# asserting it on `plan` would be asserting the wrong layer.
import asyncio  # noqa: E402

from sqlalchemy import select  # noqa: E402

from app.automation import run_once, snapshot  # noqa: E402
from app.db import SessionLocal  # noqa: E402
from app.models import Agent, AgentTask, Project, Target  # noqa: E402

call("/api/projects/AUTO2/scope", "POST",
     {"lines": ["in.acme.example"]}, token=admin)
for host in ("in.acme.example", "out.somebody-else.example"):
    call("/api/targets?project=AUTO2", "POST", {"host": host}, token=admin)
call("/api/projects/AUTO2", "PATCH",
     {"auto_amass": False, "auto_nmap": "off", "auto_resolve_ips": True},
     token=admin)


async def drive():
    async with SessionLocal() as s:
        pr = (await s.execute(
            select(Project).where(Project.code == "AUTO2"))).scalar_one()

        # No ghost: nothing is queued at all, however much is outstanding.
        n = await run_once(s, pr)
        check("with no agent online nothing is queued", n == {}, n)

        s.add(Agent(project_id=pr.id, name="auto-test", status="online",
                    callback_key_hash="x" * 64))
        await s.commit()

        n = await run_once(s, pr)
        subs = []
        for raw in (await s.execute(
                select(AgentTask.args).where(
                    AgentTask.project_id == pr.id,
                    AgentTask.kind == "nslookup"))).scalars():
            subs += json.loads(raw).get("targets") or []
        check("the in-scope host is queued", "in.acme.example" in subs, subs)
        check("the out-of-scope host is NOT, though the policy wanted it",
              "out.somebody-else.example" not in subs, subs)
        check("and the count reports only what was queued",
              n.get("auto_resolve_ips") == 1, n)

        # Second cycle: the same estate, nothing new. This is the
        # runaway, and it is the reason for the `tasked` set.
        before = len(subs)
        await run_once(s, pr)
        after = len((await s.execute(
            select(AgentTask.id).where(
                AgentTask.project_id == pr.id,
                AgentTask.kind == "nslookup"))).scalars().all())
        check("a second cycle queues nothing further", after == before,
              f"{before} then {after}")


asyncio.run(drive())

print("\n--- the amass policy asks about a ZONE, the others about a host ---")
# `*.X` authorises enumerating X and does not authorise touching it.
# A standing order must honour that difference per candidate, or the
# automation becomes the way a wildcard quietly turns into a scan.
call("/api/projects", "POST", {"code": "ZONES", "name": "Zones"}, token=admin)
call("/api/projects/ZONES/scope", "POST",
     {"lines": ["*.zone.acme.example"]}, token=admin)
call("/api/targets?project=ZONES", "POST",
     {"host": "one.zone.acme.example"}, token=admin)


async def zones():
    async with SessionLocal() as s:
        pr = (await s.execute(
            select(Project).where(Project.code == "ZONES"))).scalar_one()
        s.add(Agent(project_id=pr.id, name="zone-ghost", status="online",
                    callback_key_hash="z" * 64))
        # The apex AS A TARGET. The API would refuse to create it --
        # `*.zone.acme.example` does not cover the apex -- so it is
        # inserted directly, which is the state a project reaches by
        # narrowing its scope after the host was added. Without it the
        # apex is never an nmap candidate and the assertion below
        # passes without testing anything: checked by stubbing the
        # distinction out and watching this still pass.
        s.add(Target(project_id=pr.id, host="zone.acme.example", kind="host"))
        pr.auto_amass = True
        pr.auto_nmap = "top100"
        await s.commit()

        await run_once(s, pr)
        got: dict[str, list[str]] = {}
        for kind, raw in (await s.execute(
                select(AgentTask.kind, AgentTask.args).where(
                    AgentTask.project_id == pr.id))).all():
            a = json.loads(raw)
            got.setdefault(kind, []).extend(
                [a["domain"]] if kind == "amass" else (a.get("targets") or []))

        # The apex is enumerable because the wildcard names it.
        check("amass is queued for the zone the wildcard names",
              got.get("amass") == ["zone.acme.example"], got.get("amass"))
        # ...and is still not a host anything may be done to.
        check("nmap is NOT queued for that apex",
              "zone.acme.example" not in got.get("nmap", []), got.get("nmap"))
        check("nmap is queued for the host that really is in scope",
              got.get("nmap") == ["one.zone.acme.example"], got.get("nmap"))
        check("...and the apex was a candidate, so that meant something",
              "zone.acme.example" in [h for h, _ in
                                      (await snapshot(s, pr)).targets])


asyncio.run(zones())

# =====================================================================
# The dialog and the standing order must see the same zones
# =====================================================================
print("\n--- auto_amass sees what the dialog offers ---")

# The bug: /domains/roots read scope of kind fqdn AND wildcard and
# mined every hostname the project had seen, while the standing order
# read only wildcard scope and only Target.host. A project scoped
# entirely by `fqdn` therefore had an EMPTY zone list in the
# automation -- which is the live case that prompted this -- and
# names learnt from TLS SANs were invisible to it either way.
call("/api/projects", "POST", {"code": "ROOTS", "name": "ROOTS"}, token=admin)
# fqdn scope, deliberately: no wildcard anywhere in this project.
# Apexes, as a real project has them: `mufg.jp` and friends are
# stored as kind `fqdn`, and registrable() returns them unchanged so
# the gate allows enumerating them. A scope of `www.scoped.example`
# would NOT authorise `scoped.example`, and the gate refusing that is
# correct rather than a bug — checked, by writing it that way first.
call("/api/projects/ROOTS/scope", "POST",
     {"lines": ["alpha.example", "beta.example"]}, token=admin)


async def roots_agree():
    from app.roots import enumerable_roots
    async with SessionLocal() as s:
        pr = (await s.execute(
            select(Project).where(Project.code == "ROOTS"))).scalar_one()
        s.add(Agent(project_id=pr.id, name="roots-ghost", status="online",
                    callback_key_hash="r" * 64))
        # A target whose ALTERNATE name is under a different zone. Only
        # the wider sweep reads `hostnames`, so this is the half of the
        # bug that is not about scope kinds.
        s.add(Target(project_id=pr.id, host="box.alpha.example", kind="host",
                     hostnames=json.dumps(["vhost.beta.example"])))
        pr.auto_amass = True
        await s.commit()

        found = await enumerable_roots(s, pr.id)
        check("an fqdn scope entry yields its zone",
              "alpha.example" in found and "beta.example" in found,
              sorted(found))
        check("a name learnt as an alternate yields its zone too",
              "beta.example" in found, sorted(found))

        await run_once(s, pr)
        queued = {json.loads(r)["domain"] for k, r in (await s.execute(
            select(AgentTask.kind, AgentTask.args).where(
                AgentTask.project_id == pr.id,
                AgentTask.kind == "amass"))).all()}
        # The actual complaint: with the toggle on, nothing should be
        # left for the dialog to offer.
        check("auto_amass queues the fqdn-scoped zone",
              "alpha.example" in queued, sorted(queued))
        check("auto_amass queues the zone from the alternate name",
              "beta.example" in queued, sorted(queued))
        check("...and the target's own zone", "alpha.example" in queued,
              sorted(queued))
        check("nothing the dialog would offer is left over",
              not (found - queued), sorted(found - queued))

        # And the dialog now offers only what may be enumerated. A
        # zone the gate refuses used to sit here for ever: picking it
        # queued nothing and the toggle never cleared it, so the
        # dialog reported work outstanding on every visit.
        from app.scopegate import index_for
        idx = await index_for(s, pr.id)
        offered = {d for d in found if idx.check_zone(d).allowed}
        check("every offered zone is one the gate allows",
              offered == found, sorted(found - offered))


asyncio.run(roots_agree())

print(f"\n{ok} passed, {fail} failed")
raise SystemExit(1 if fail else 0)
