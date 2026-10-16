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
    WEB_KINDS,
    Snapshot,
    plan,
)
from app.models import (
    NMAP_CHOICES,  # noqa: E402
    WEB_CHOICES,  # noqa: E402
)
from app.webtargets import MAX_SEEDS, crawlable_path, group_seeds  # noqa: E402

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
check("reverse picks the address-named host",
      [c.subject for c in p] == ["203.0.113.5"], [c.subject for c in p])
check("...as reverse_ip", {c.kind for c in p} == {"reverse_ip"})

# The case the policy existed for and could not see. An engagement
# scoped as hostnames and CIDRs creates NO address-named targets --
# production had 1,038 targets, zero of them address-named, and 1,857
# observed addresses -- so a switch that reads `targets` alone is
# correct, switched on, and permanently idle.
NAMED_ONLY = [("web.acme.example", True), ("api.acme.example", True)]
check("with no address-named target there is nothing to do from targets",
      plan(Snapshot(auto_reverse_dns=True, targets=NAMED_ONLY)) == [])

p = plan(Snapshot(auto_reverse_dns=True, targets=NAMED_ONLY,
                  addresses={"198.51.100.7", "198.51.100.8"}))
check("...but the addresses the estate answers on are asked about",
      [c.subject for c in p] == ["198.51.100.7", "198.51.100.8"],
      [c.subject for c in p])

# Both sources, one task each. An address that is ALSO a target by
# name must not be queued twice.
p = plan(Snapshot(auto_reverse_dns=True, targets=ESTATE,
                  addresses={"203.0.113.5", "198.51.100.7"}))
subs = [c.subject for c in p]
check("the two sources are merged, not concatenated",
      subs == ["198.51.100.7", "203.0.113.5"], subs)
check("...so a target that is also an observed address is asked once",
      subs.count("203.0.113.5") == 1, subs)

# "One attempt per subject, ever" has to hold for the new source too,
# or every cycle re-queues the whole address list for ever.
p = plan(Snapshot(auto_reverse_dns=True, targets=NAMED_ONLY,
                  addresses={"198.51.100.7", "198.51.100.8"},
                  tasked={("reverse_ip", "198.51.100.7")}))
check("an address already tried is not tried again",
      [c.subject for c in p] == ["198.51.100.8"], [c.subject for c in p])

check("addresses do nothing while the policy is off",
      plan(Snapshot(addresses={"198.51.100.7"})) == [])

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
      p[0].args.get("ports") == "1-65535", p[0].args)
# No profile names its own scripts any more, and this is the
# assertion that keeps it that way. The ghost adds `--script` with
# every -sV, nmap honours only the LAST --script on the line, and a
# profile naming its own set therefore SUPPRESSES the rest rather
# than adding to it. `full` carried `--script ssl-cert`, and `full`
# is what the production project runs -- so the whole script change
# reached nothing until that was removed. ssl-cert is still run; it
# is named in the ghost's set.
check("...and full does not name its own scripts, which would "
      "suppress the ghost's",
      "extra" not in p[0].args, p[0].args)
check("nor does top100",
      "extra" not in plan(Snapshot(auto_nmap="top100",
                                   targets=ESTATE))[0].args)
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
from app.models import Agent, AgentTask, Project, Target, WebAddress  # noqa: E402

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
# web discovery: crawl, gobuster, or both
# =====================================================================
print("\n--- the web policy queues per URL, not per host ---")

WEB = {"http://a.acme.example/", "https://b.acme.example/app"}

check("off plans nothing",
      plan(Snapshot(auto_web="off", web_urls=WEB)) == [])
check("an unknown value plans nothing rather than guessing",
      plan(Snapshot(auto_web="nonsense", web_urls=WEB)) == [])

p = plan(Snapshot(auto_web="crawl", web_urls=WEB))
check("crawl queues katana only",
      {c.kind for c in p} == {"katana"}, {c.kind for c in p})
check("...one task per url", len(p) == 2, len(p))
check("...addressed to the url, which is what a crawler needs",
      all(c.args["targets"] == [c.subject] for c in p))

p = plan(Snapshot(auto_web="gobuster", web_urls=WEB))
check("gobuster queues gobuster only",
      {c.kind for c in p} == {"gobuster"}, {c.kind for c in p})

p = plan(Snapshot(auto_web="both", web_urls=WEB))
check("both queues both kinds",
      {c.kind for c in p} == {"katana", "gobuster"}, {c.kind for c in p})
# They answer different questions, so `both` is two tasks per url and
# not one tool standing in for the other.
check("...two tasks per url", len(p) == 4, len(p))

# One attempt per subject, like every other standing order. A crawl
# that found nothing has still been run, and the packets still went.
tried = Snapshot(auto_web="both", web_urls=WEB,
                 tasked={("katana", "http://a.acme.example/"),
                         ("gobuster", "http://a.acme.example/")})
left = {(c.kind, c.subject) for c in plan(tried)}
check("a url already tasked is not queued again",
      left == {("katana", "https://b.acme.example/app"),
               ("gobuster", "https://b.acme.example/app")}, sorted(left))

# =====================================================================
# nuclei: templates at a client, so the flags are part of the contract
# =====================================================================
print("\n--- the nuclei policy sends two different runs ---")

check("off plans nothing",
      plan(Snapshot(auto_nuclei="off", web_urls=WEB)) == [])
check("an unknown value plans nothing rather than guessing",
      plan(Snapshot(auto_nuclei="nonsense", web_urls=WEB)) == [])

p = plan(Snapshot(auto_nuclei="vuln", web_urls=WEB))
check("vuln queues the CVE run only",
      {c.kind for c in p} == {"nuclei"}, {c.kind for c in p})
# The flags ARE the policy. Without them the run is every template
# nuclei has rather than critical/high CVEs, which is a different and
# much larger thing to do to a client.
flags = {c.args.get("extra") for c in p}
check("...carrying the severity, tag and exclusion filters",
      flags == {"-severity critical,high -tags cve -etags authenticated"},
      flags)

p = plan(Snapshot(auto_nuclei="tech", web_urls=WEB))
check("tech queues the fingerprint run only",
      {c.kind for c in p} == {"nuclei_tech"}, {c.kind for c in p})
check("...asking for the tech templates",
      {c.args.get("extra") for c in p} == {"-tags tech"},
      {c.args.get("extra") for c in p})

# A STRING, because the agent reads this with a helper that returns
# "" for anything else -- a list here would drop every flag with no
# error anywhere and send the unfiltered run.
check("the flags are a string, which is what the agent can read",
      all(isinstance(c.args.get("extra"), str) for c in p))

p = plan(Snapshot(auto_nuclei="both", web_urls=WEB))
check("both queues both runs",
      {c.kind for c in p} == {"nuclei", "nuclei_tech"}, {c.kind for c in p})
check("...two tasks per url", len(p) == 4, len(p))

# The reason `nuclei_tech` is its own KIND. Dedup is keyed on
# (kind, subject), so a shared name would mean whichever run went
# first marked the URL done and the other never ran at all.
tried = Snapshot(auto_nuclei="both", web_urls=WEB,
                 tasked={("nuclei", "http://a.acme.example/")})
left = {(c.kind, c.subject) for c in plan(tried)}
check("the CVE run being done does not suppress the fingerprint run",
      ("nuclei_tech", "http://a.acme.example/") in left, sorted(left))
check("...and the url is not queued for the CVE run twice",
      ("nuclei", "http://a.acme.example/") not in left, sorted(left))

# A host with no web address has nothing to crawl. Queueing the
# hostname would hand the agent something it cannot use.
check("no web addresses means nothing to do",
      plan(Snapshot(auto_web="both", targets=ESTATE)) == [])

check("the vocabulary is not written down twice",
      set(WEB_CHOICES) == {"off", *WEB_KINDS})

# ---------------------------------------------------------------------
# what content discovery found becomes where crawling starts
# ---------------------------------------------------------------------
print("\n--- gobuster's finds seed the crawler ---")

# gobuster asks for paths nothing links to; katana follows links. A
# path nothing links to is exactly the one a crawl cannot reach on its
# own, and is often the way into a whole unlinked subtree.
SEEDS = {"http://a.acme.example/": ["http://a.acme.example/admin",
                                    "http://a.acme.example/old"]}

p = plan(Snapshot(auto_web="crawl", web_urls=WEB, seeds=SEEDS))
seeded = [c for c in p if c.policy == "auto_web_seeded"]
check("a seeded crawl is queued", len(seeded) == 1, len(seeded))
check("...one task per origin, not one per path",
      seeded[0].args["targets"] == ["http://a.acme.example/admin",
                                    "http://a.acme.example/old"],
      seeded[0].args["targets"])
check("...with the origin as its subject, which is what the gate reads",
      seeded[0].subject == "http://a.acme.example/", seeded[0].subject)
check("...and it is a crawl", seeded[0].kind == "katana")

# `gobuster` alone is the operator asking for paths. Following them is
# crawling, and they did not ask for crawling.
check("a gobuster-only policy does not seed crawls",
      not [c for c in plan(Snapshot(auto_web="gobuster", web_urls=WEB,
                                    seeds=SEEDS))
           if c.policy == "auto_web_seeded"])
check("off still plans nothing",
      plan(Snapshot(auto_web="off", web_urls=WEB, seeds=SEEDS)) == [])

everything = plan(Snapshot(auto_web="both", web_urls=WEB, seeds=SEEDS))
check("both still queues the plain per-origin work as well",
      len([c for c in everything if c.policy == "auto_web"]) == 4,
      len([c for c in everything if c.policy == "auto_web"]))
check("...plus exactly one seeded crawl",
      len([c for c in everything if c.policy == "auto_web_seeded"]) == 1)

# An origin whose seeds have all been crawled already contributes
# nothing. `crawl_seeds` does that filtering against `tasked_subjects`
# before the snapshot is built, so an empty list must not become a
# task with no targets.
check("an origin with no seeds left is not a task",
      not [c for c in plan(Snapshot(auto_web="crawl", web_urls=WEB,
                                    seeds={"http://a.acme.example/": []}))
           if c.policy == "auto_web_seeded"])

# --- how the seed set itself is built -------------------------------
print("\n--- and the seed set has a fixed point ---")

g = group_seeds(["http://a.acme.example/admin",
                 "http://a.acme.example/old",
                 "https://b.acme.example/x"], set())
check("grouped by origin", sorted(g) == ["http://a.acme.example/",
                                         "https://b.acme.example/"], sorted(g))
check("...every seed under the origin it belongs to",
      g["http://a.acme.example/"] == ["http://a.acme.example/admin",
                                      "http://a.acme.example/old"],
      g["http://a.acme.example/"])

# THE FIXED POINT. Pointing a crawler at each URL the last run found
# is what took one project from 1,109 queued tasks to 97,959 in under
# an hour. An origin that seeded itself would do the same thing one
# step at a time: crawl `/`, find `/`, crawl `/` again, forever.
check("an origin is never its own seed",
      group_seeds(["http://a.acme.example/"], set()) == {},
      group_seeds(["http://a.acme.example/"], set()))
check("...including when it is spelled without the trailing slash",
      group_seeds(["http://a.acme.example"], set()) == {},
      group_seeds(["http://a.acme.example"], set()))

# Having been handed to a crawl is what counts, exactly as it does for
# every other standing order -- and it is what makes a seeded crawl
# self-cancelling, since `tasked_subjects` records each of its targets.
check("a seed already given to a crawl is dropped",
      group_seeds(["http://a.acme.example/admin",
                   "http://a.acme.example/old"],
                  {"http://a.acme.example/admin"})
      == {"http://a.acme.example/": ["http://a.acme.example/old"]})
check("...matched without regard to case, like `tasked_subjects` records it",
      group_seeds(["http://a.acme.example/Admin"],
                  {"http://a.acme.example/admin"}) == {})

# A host that answers 200 to everything is the normal failure of
# content discovery, not an exotic one: 182 of 1,128 runs came back
# with between 51 and 500 paths. The cap is what stops one of them
# becoming a sweep dressed as a crawl.
flood = [f"http://a.acme.example/p{i}" for i in range(500)]
check(f"a catch-all host is capped at {MAX_SEEDS} seeds",
      len(group_seeds(flood, set())["http://a.acme.example/"]) == MAX_SEEDS,
      len(group_seeds(flood, set())["http://a.acme.example/"]))
check("duplicates do not consume the cap",
      group_seeds(["http://a.acme.example/x"] * 50, set())
      == {"http://a.acme.example/": ["http://a.acme.example/x"]})

# Seeding is a strict subset of what gets imported, and the two must
# not be confused: `backup.zip` answering 200 is one of the better
# things content discovery can find and it goes in the inventory. It
# is simply not a place to start a crawl from, because there are no
# links in an archive.
check("an archive is imported but not seeded",
      group_seeds(["http://a.acme.example/backup.zip",
                   "http://a.acme.example/admin"], set())
      == {"http://a.acme.example/": ["http://a.acme.example/admin"]},
      group_seeds(["http://a.acme.example/backup.zip",
                   "http://a.acme.example/admin"], set()))
check("...case of the extension does not matter",
      not crawlable_path("http://a.acme.example/Logo.PNG"))

# A deny list, not an allow list. An extension nobody has catalogued
# is one we have not seen, which is not the same as one we know holds
# no links -- the third outcome, kept separate from the second.
check("an unrecognised extension is still crawlable",
      crawlable_path("http://a.acme.example/report.xyzzy"))
check("...so is no extension at all",
      crawlable_path("http://a.acme.example/admin"))
check("...and a dot in a directory is not an extension",
      crawlable_path("http://a.acme.example/v1.2/docs"))

# katana scrapes JS responses for endpoints, so these earn their
# request where an image does not.
check("javascript is worth crawling", crawlable_path("http://a/app.js"))
check("json is worth crawling", crawlable_path("http://a/data.json"))

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
# Apexes, as a real project has them: `acme.example` and friends are
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

# =====================================================================
# Cloud providers: approved is not the same as enumerable
# =====================================================================
print("\n--- a cloud zone is never enumerated ---")

from app import clouds  # noqa: E402

check("twenty providers", len(clouds.PROVIDERS) == 20, len(clouds.PROVIDERS))
check("the big four are there",
      all(k in clouds.PROVIDERS for k in ("aws", "azure", "gcp", "oracle")))

# Matched on a label boundary, like the scope index. A look-alike is
# somebody else's domain, and treating it as the provider's would
# quietly exclude a real target from enumeration.
for name, want in [
    ("amazonaws.com", True), ("s3.amazonaws.com", True),
    ("notamazonaws.com", False), ("mypages.dev", False),
    ("pages.dev", True), ("x.pages.dev", True),
    ("acme.example", False), ("", False), (None, False),
]:
    check(f"is_cloud_domain({name!r}) is {want}",
          clouds.is_cloud_domain(name) is want)

# Asserted as set membership rather than with `in`. These are exact
# entries in a list of domains, but CodeQL reads `"amazonaws.com" in
# <anything>` as a URL substring check and files it as a high-severity
# incomplete-sanitization alert. Saying it this way is unambiguous to
# both the reader and the scanner.
check("approving providers yields their domains",
      set(clouds.domains_for(["aws"])).issuperset({"amazonaws.com"})
      and set(clouds.domains_for(["azure"])).issuperset(
          {"azurewebsites.net"}))
check("an unknown provider key is ignored, not fatal",
      clouds.domains_for(["aws", "not-a-cloud"]) == clouds.domains_for(["aws"]))
check("nothing selected yields nothing", clouds.domains_for([]) == []
      and clouds.domains_for(None) == [])

print("\n--- auto_web starts from everywhere it could go, not just "
      "the URLs already recorded ---")
# The bug this replaces: `snapshot()` built `web_urls` from the
# `web_addresses` table alone. A project that has been port-scanned
# and never crawled has no rows there, so a switch set to `both`
# looked at an empty set and queued nothing — silently, for ever.
# That is the only situation the policy exists for.
#
# Every `plan()` test above passed against it, because they hand
# `Snapshot` its `web_urls` directly and so never exercise where the
# set comes from. This drives the real thing.
call("/api/projects", "POST",
     {"code": "AUTOWEB", "name": "Auto web", "scope": ["10.70.0.0/24"]},
     token=admin)
WEBSCAN = '''<?xml version="1.0"?><nmaprun scanner="nmap" version="7.94"
 args="nmap -sV -oX /t 10.70.0.1" start="1760000000">
<scaninfo type="connect" protocol="tcp" numservices="2" services="443,22"/>
<host><address addr="10.70.0.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="443"><state state="open"/>
<service name="https" tunnel="ssl"/></port></ports></host>
<host><address addr="10.70.0.2" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open"/>
<service name="ssh"/></port></ports></host>
<runstats><finished summary="done"/></runstats></nmaprun>'''
call("/api/scans/import?project=AUTOWEB", "POST",
     {"content": WEBSCAN, "format": "auto", "mode": "open"}, token=admin)
call("/api/projects/AUTOWEB", "PATCH",
     {"auto_web": "both", "auto_nmap": "off", "auto_amass": False,
      "auto_resolve_ips": False, "auto_reverse_dns": False}, token=admin)


async def webpolicy():
    async with SessionLocal() as s:
        pr = (await s.execute(
            select(Project).where(Project.code == "AUTOWEB"))).scalar_one()

        # Nothing has ever written a URL for this project.
        recorded = (await s.execute(
            select(WebAddress.url).join(
                Target, Target.id == WebAddress.target_id)
            .where(Target.project_id == pr.id))).scalars().all()
        check("no URL has been recorded for this project",
              list(recorded) == [], list(recorded))

        snap = await snapshot(s, pr)
        check("...and the policy still has somewhere to go, derived "
              "from the open web service",
              "https://10.70.0.1/" in snap.web_urls, sorted(snap.web_urls))
        check("the ssh host contributes nothing",
              not any("10.70.0.2" in u for u in snap.web_urls),
              sorted(snap.web_urls))

        s.add(Agent(project_id=pr.id, name="web-auto", status="online",
                    callback_key_hash="w" * 64))
        await s.commit()

        n = await run_once(s, pr)
        check("so the standing order queues the work nothing has started",
              n.get("auto_web") == 2, n)      # katana + gobuster, one URL
        kinds = sorted((await s.execute(
            select(AgentTask.kind).where(
                AgentTask.project_id == pr.id,
                AgentTask.kind.in_(("katana", "gobuster"))))).scalars().all())
        check("...one task per tool, because neither covers the other",
              kinds == ["gobuster", "katana"], kinds)

        # And it does not run away: the second cycle sees the same
        # estate with the work already attempted.
        await run_once(s, pr)
        again = len((await s.execute(
            select(AgentTask.id).where(
                AgentTask.project_id == pr.id,
                AgentTask.kind.in_(("katana", "gobuster"))))).scalars().all())
        check("a second cycle queues nothing further", again == 2, again)


asyncio.run(webpolicy())

print("\n--- a crawl's own results do not become more crawls ---")
# The incident this exists for. `auto_web` queued per URL, so every
# URL a crawl discovered became somewhere else to crawl: one site
# returned several hundred URLs, each was imported, each looked like
# a new target, and one project went from 1,109 queued tasks to
# 97,959 in under an hour. ~49,000 of those were gobuster runs at
# ~4,751 requests each, aimed at a client.
#
# Two things were wrong and both are tested here. The policy keyed on
# URLs rather than origins, so the set grew as it ran; and the
# "already tasked" check compared a case-preserving URL against a
# lowercased record, so anything with an uppercase character in its
# path never counted as done and was re-queued every cycle.
call("/api/projects", "POST",
     {"code": "NOLOOP", "name": "No loop", "scope": ["10.71.0.0/24"]},
     token=admin)
LOOPSCAN = '''<?xml version="1.0"?><nmaprun scanner="nmap" version="7.94"
 args="nmap -sV -oX /t 10.71.0.1" start="1760000000">
<scaninfo type="connect" protocol="tcp" numservices="1" services="443"/>
<host><address addr="10.71.0.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="443"><state state="open"/>
<service name="https" tunnel="ssl"/></port></ports></host>
<runstats><finished summary="done"/></runstats></nmaprun>'''
call("/api/scans/import?project=NOLOOP", "POST",
     {"content": LOOPSCAN, "format": "auto", "mode": "open"}, token=admin)
call("/api/projects/NOLOOP", "PATCH",
     {"auto_web": "crawl", "auto_nmap": "off", "auto_amass": False,
      "auto_resolve_ips": False, "auto_reverse_dns": False}, token=admin)


async def noloop():
    async with SessionLocal() as s:
        pr = (await s.execute(
            select(Project).where(Project.code == "NOLOOP"))).scalar_one()
        s.add(Agent(project_id=pr.id, name="loop-test", status="online",
                    callback_key_hash="l" * 64))
        await s.commit()

        n = await run_once(s, pr)
        check("one open web service is one crawl", n.get("auto_web") == 1, n)

        # What a crawl of that site returns: its own pages, including
        # one with an uppercase path, which is the spelling that
        # defeated the old check.
        t = (await s.execute(select(AgentTask).where(
            AgentTask.project_id == pr.id,
            AgentTask.kind == "katana"))).scalars().first()
        t.status = "done"
        t.output = json.dumps({
            "sites": ["https://10.71.0.1/"], "depth": 2, "by_type": {},
            "urls": ["https://10.71.0.1/",
                     "https://10.71.0.1/login",
                     "https://10.71.0.1/Admin/Index",     # uppercase
                     "https://10.71.0.1/api/v1/users"]})
        t.import_as = "crawl"
        await s.commit()

        from app.routers.scans import _run
        res = await _run(s, pr, t.output, "crawl", "ghost:loop-test",
                         mode="strict", decisions={})
        t.import_result = res.model_dump_json()
        await s.commit()

        rows = (await s.execute(select(WebAddress.url).join(
            Target, Target.id == WebAddress.target_id)
            .where(Target.project_id == pr.id))).scalars().all()
        check("the crawl's URLs were imported", len(rows) >= 3, len(rows))

        # The fixed point. Everything that crawl found lives on the
        # origin that was already crawled, so there is nothing new to
        # do -- including the uppercase one.
        snap = await snapshot(s, pr)
        check("...and they all collapse to the one origin already known",
              snap.web_urls == {"https://10.71.0.1/"}, sorted(snap.web_urls))

        n2 = await run_once(s, pr)
        check("so the next cycle queues nothing", not n2.get("auto_web"), n2)
        total = len((await s.execute(select(AgentTask.id).where(
            AgentTask.project_id == pr.id,
            AgentTask.kind == "katana"))).scalars().all())
        check("...and there is still exactly one crawl task", total == 1,
              total)


asyncio.run(noloop())

print("\n--- the seed query, against a real database ---")
# `group_seeds` above covers the grouping. This covers the WHERE
# clause, which is where the one-way edge actually lives and which no
# pure function can test: an `or_` of negations where an `and_` was
# meant passes every row and is invisible from the Python side.
call("/api/projects", "POST",
     {"code": "SEEDQ", "name": "Seed query", "scope": ["10.73.0.0/24"]},
     token=admin)
SEEDSCAN = '''<?xml version="1.0"?><nmaprun scanner="nmap" version="7.94"
 args="nmap -sV -oX /t 10.73.0.1" start="1760000000">
<scaninfo type="connect" protocol="tcp" numservices="1" services="443"/>
<host><address addr="10.73.0.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="443"><state state="open"/>
<service name="https" tunnel="ssl"/></port></ports></host>
<runstats><finished summary="done"/></runstats></nmaprun>'''
call("/api/scans/import?project=SEEDQ", "POST",
     {"content": SEEDSCAN, "format": "auto", "mode": "open"}, token=admin)


async def seedquery():
    from app.routers.scans import _run
    from app.webtargets import crawl_seeds

    async with SessionLocal() as s:
        pr = (await s.execute(
            select(Project).where(Project.code == "SEEDQ"))).scalar_one()

        # A content-discovery run holding one of each kind of answer.
        gob = json.dumps({
            "url": "https://10.73.0.1/", "wordlist": "common",
            "found": [], "hits": [
                {"path": "admin", "status": 200,
                 "content_type": "text/html; charset=utf-8"},
                {"path": "secret", "status": 403},          # not a 200
                {"path": "login", "status": 401},           # not a 200
                {"path": "backup.zip", "status": 200,       # by extension
                 "content_type": "application/zip"},
                {"path": "logo", "status": 200,             # by type only
                 "content_type": "image/png"},
                {"path": "export", "status": 200,
                 "content_type": "application/octet-stream"},
                {"path": "legacy", "status": 200},          # no type at all
            ]})
        res = await _run(s, pr, gob, "gobuster", "ghost:seed-test",
                         mode="strict", decisions={})
        await s.commit()
        check("every hit is imported regardless of whether it is crawlable",
              res.urls_created == 7, res.urls_created)

        rows = (await s.execute(select(WebAddress.url).join(
            Target, Target.id == WebAddress.target_id)
            .where(Target.project_id == pr.id))).scalars().all()
        check("...and all seven reach the web inventory as URLs",
              len([r for r in rows if r.startswith("https://10.73.0.1/")]) == 7,
              sorted(rows))

        seeds = await crawl_seeds(s, pr.id)
        got = sorted(seeds.get("https://10.73.0.1/", []))
        # Two different reasons to send the agent, both in this list.
        #
        # `admin` and `legacy` are 200s to be CRAWLED -- unlinked
        # entry points with possibly a subtree behind them. `legacy`
        # has no content type, and not knowing what a thing is is not
        # grounds for deciding it is a binary.
        #
        # `login` (401) and `secret` (403) have nothing behind them to
        # walk. They are here to be FETCHED once, because gobuster
        # kept no packet for them and the headers are the finding:
        # which WAF answered, what realm the 401 names, whether the
        # 403 came from the application or the edge.
        check("the crawlable ones and the protected ones are both seeded",
              got == ["https://10.73.0.1/admin", "https://10.73.0.1/legacy",
                      "https://10.73.0.1/login", "https://10.73.0.1/secret"],
              got)
        # The binaries stay out either way: a zip answering 403 is
        # still not somewhere worth spending a request.
        check("...and the ones no tool should fetch are still excluded",
              not any(u.endswith(("backup.zip", "logo", "export"))
                      for u in got), got)

        # The bound that matters. Without it every protected path on
        # the estate is re-fetched on every cycle, for ever, against
        # the client -- the exact shape of the bug that took one
        # project from 1,109 queued tasks to 97,959.
        _wa = (await s.execute(select(WebAddress).join(
            Target, Target.id == WebAddress.target_id)
            .where(Target.project_id == pr.id,
                   WebAddress.url == "https://10.73.0.1/login"))).scalar_one()
        _wa.response = "HTTP/1.1 401 Unauthorized\r\n\r\n"
        await s.commit()
        got2 = sorted((await crawl_seeds(s, pr.id)).get("https://10.73.0.1/", []))
        check("a protected path stops being seeded once its packet is kept",
              "https://10.73.0.1/login" not in got2, got2)
        check("...while one still missing its packet is not dropped with it",
              "https://10.73.0.1/secret" in got2, got2)
        # A 200 is seeded to be crawled, which is a different job from
        # capturing a packet, so having one must not stop it.
        _adm = (await s.execute(select(WebAddress).join(
            Target, Target.id == WebAddress.target_id)
            .where(Target.project_id == pr.id,
                   WebAddress.url == "https://10.73.0.1/admin"))).scalar_one()
        _adm.response = "HTTP/1.1 200 OK\r\n\r\n"
        await s.commit()
        got3 = sorted((await crawl_seeds(s, pr.id)).get("https://10.73.0.1/", []))
        check("a 200 with a packet is still seeded, because crawling it "
              "is a different question",
              "https://10.73.0.1/admin" in got3, got3)


asyncio.run(seedquery())

print("\n--- one cycle cannot queue an unbounded amount ---")
# A correct `already done` check is what keeps this bounded, and the
# cap is what bounds how wrong a single cycle can be when that check
# is next mistaken. It withholds nothing: the following cycle takes
# the next batch.
from app.automation import WEB_PER_CYCLE  # noqa: E402

many = {f"https://h{i}.example/" for i in range(WEB_PER_CYCLE * 3)}
p = plan(Snapshot(auto_web="both", web_urls=many))
per_kind = {}
for c in p:
    per_kind[c.kind] = per_kind.get(c.kind, 0) + 1
check(f"a cycle queues at most {WEB_PER_CYCLE} per kind",
      all(v <= WEB_PER_CYCLE for v in per_kind.values()), per_kind)
check("...and still queues both kinds", set(per_kind) == {"katana", "gobuster"},
      sorted(per_kind))
# Not vacuous: a small estate is still done in one go.
few = {f"https://s{i}.example/" for i in range(5)}
check("a small estate is not held back",
      len(plan(Snapshot(auto_web="crawl", web_urls=few))) == 5,
      len(plan(Snapshot(auto_web="crawl", web_urls=few))))

print("\n--- the tasked check ignores case ---")
# `tasked_subjects` lowercases what it records. A candidate whose
# spelling carries uppercase must still match, or it is re-queued for
# ever.
check("an already-tasked subject is not queued again whatever its case",
      plan(Snapshot(auto_web="crawl",
                    web_urls={"https://Mixed.Example/"},
                    tasked={("katana", "https://mixed.example/")})) == [],
      plan(Snapshot(auto_web="crawl",
                    web_urls={"https://Mixed.Example/"},
                    tasked={("katana", "https://mixed.example/")})))

print(f"\n{ok} passed, {fail} failed")
raise SystemExit(1 if fail else 0)
