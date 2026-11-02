"""Asking for proofs of a GROUP of findings, rather than a floor.

`auto_poc` is a standing order: "prove everything this bad or worse,
for ever". This is the other half -- "prove the findings on this
host", "prove this vulnerability wherever it is", "prove this
credential still works" -- and the two must not be confused, because
raising the floor to cover one host commits the engagement to every
finding at that severity across the estate.

Three things are worth asserting and none of them are the HTTP shape:

  the queue   a request has to jump the sweep, or asking for one
              low-severity credential behind 4,000 swept criticals
              means waiting hours and the button reads as broken.
  the counts  the rollup's proof column must not inflate the finding
              counts beside it. A finding can carry TWO proofs -- a
              refused one and a later written one -- and a naive join
              would make the rollup disagree with the findings list
              about how many findings exist.
  the gate    a project with `auto_poc` off still has to be drained
              when somebody asked.
"""
import pathlib as _pathlib
import sys as _sys

_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parents[1]))
import asyncio
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


admin = call("/api/auth/setup", "POST",
             {"username": "root", "password": "root-password-1"})[1]["access_token"]
call("/api/projects", "POST", {"code": "PRQ", "name": "Proof requests"},
     token=admin)
for host in ("one.acme.example", "two.acme.example"):
    call("/api/targets?project=PRQ", "POST", {"host": host}, token=admin)

# Two hosts, and a title that spans both at one severity -- which is
# what the by-vuln rollup groups on.
FINDINGS = [
    ("one.acme.example", "Shared TLS problem", "high"),
    ("one.acme.example", "Only here",          "critical"),
    ("one.acme.example", "A low thing",        "low"),
    ("two.acme.example", "Shared TLS problem", "high"),
]
for host, title, sev in FINDINGS:
    call("/api/vulns?project=PRQ", "POST",
         {"host": host, "title": title, "severity": sev}, token=admin)

from datetime import UTC, datetime  # noqa: E402

from sqlalchemy import select  # noqa: E402

from app.db import SessionLocal  # noqa: E402
from app.models import Agent, Poc, Project, Target, Vuln  # noqa: E402


async def ids_for(s, pr, title):
    return (await s.execute(
        select(Vuln.id).join(Target, Target.id == Vuln.target_id)
        .where(Target.project_id == pr.id, Vuln.title == title))).scalars().all()


print("\n--- the rollup counts proofs without inflating the findings ---")


async def counts():
    async with SessionLocal() as s:
        pr = (await s.execute(
            select(Project).where(Project.code == "PRQ"))).scalar_one()
        [vid] = await ids_for(s, pr, "Only here")
        tid = (await s.execute(
            select(Vuln.target_id).where(Vuln.id == vid))).scalar_one()
        # TWO proofs on ONE finding, which is the real shape: the
        # first was refused and recorded as refused, the second was
        # written. A join straight onto `pocs` counts this finding
        # twice and the host's `total` reads 4 instead of 3.
        s.add(Poc(target_id=tid, vuln_id=vid, title="refused",
                  status="unconfirmed", verdict="no proof was written"))
        s.add(Poc(target_id=tid, vuln_id=vid, title="written",
                  status="unconfirmed"))
        await s.commit()


asyncio.run(counts())

_, roll = call("/api/vulns/by-target?project=PRQ", token=admin)
by_host = {r["host"]: r for r in roll["items"]}
check("the host's finding total is unchanged by its two proofs",
      by_host["one.acme.example"]["total"] == 3,
      by_host["one.acme.example"]["total"])
check("severity counts are not inflated either",
      by_host["one.acme.example"]["critical"] == 1,
      by_host["one.acme.example"]["critical"])
check("and the proof column counts the FINDING once, not its proofs",
      by_host["one.acme.example"]["proofs"] == 1,
      by_host["one.acme.example"]["proofs"])

_, roll2 = call("/api/vulns/by-title?project=PRQ", token=admin)
shared = [r for r in roll2["items"] if r["title"] == "Shared TLS problem"][0]
check("by-vuln agrees: two hosts carry the shared finding",
      shared["hosts"] == 2, shared["hosts"])
check("and it has no proofs", shared["proofs"] == 0, shared["proofs"])


print("\n--- a request is refused when nothing could run it ---")
code, body = call("/api/vulns/poc/request?project=PRQ", "POST",
                  {"host": "one.acme.example"}, token=admin)
check("no model and no Ghost: refused, not silently queued", code == 409, code)
check("and the refusal says which half is missing",
      isinstance(body, dict) and "detail" in body
      and ("model" in body["detail"] or "Ghost" in body["detail"]),
      body)

code, body = call("/api/vulns/poc/request?project=PRQ", "POST",
                  {"host": "one.acme.example", "title": "Only here"},
                  token=admin)
check("two selectors at once is refused before anything else", code == 422,
      code)


print("\n--- the worker drains a request ahead of its floor sweep ---")


async def ordering():
    from app.agent.pocworker import _next, _projects
    async with SessionLocal() as s:
        pr = (await s.execute(
            select(Project).where(Project.code == "PRQ"))).scalar_one()
        s.add(Agent(project_id=pr.id, name="prq-ghost", status="online",
                    callback_key_hash="p" * 64))
        await s.commit()

        # `auto_poc` is OFF. Nothing but the request should make this
        # project appear at all.
        [low] = await ids_for(s, pr, "A low thing")
        got = await _projects()
        check("with auto_poc off and nothing asked, the project is idle",
              not any(p[1] == "PRQ" for p in got), [p[1] for p in got])

        await s.execute(
            Vuln.__table__.update().where(Vuln.id == low)
            .values(poc_requested_at=datetime(2026, 11, 2, 12, 0, tzinfo=UTC)))
        await s.commit()

        got = await _projects()
        check("one request is enough to make it due, floor or no floor",
              any(p[1] == "PRQ" for p in got), [p[1] for p in got])
        sev = [p[2] for p in got if p[1] == "PRQ"][0]
        check("and it carries an empty floor — requests only", sev == (), sev)

        # The sweep's own worst-first order would pick the CRITICAL.
        # The request is a `low`, and it still has to come first.
        nxt = await _next(s, pr.id, ("critical", "high", "medium", "low"))
        check("the asked-for low beats the swept critical",
              nxt is not None and nxt.id == low,
              f"picked {getattr(nxt, 'title', None)!r}")

        # Once it has a proof it leaves the queue, even though the
        # timestamp stays -- the timestamp records that a person
        # asked, `pocs.vuln_id` is what retires it.
        v = await s.get(Vuln, low)
        s.add(Poc(target_id=v.target_id, vuln_id=low, title="done",
                  status="unconfirmed"))
        await s.commit()
        nxt = await _next(s, pr.id, ("critical", "high", "medium", "low"))
        # `high`, not `critical`: the only critical here is the one
        # given two proofs above, so it is already out of the queue.
        # That is the point -- the sweep resumes at the worst finding
        # WITHOUT a proof, which is not the worst finding.
        check("proved, it drops out and the sweep resumes worst-unproved-first",
              nxt is not None and nxt.severity == "high",
              getattr(nxt, "severity", None))

        after = await s.get(Vuln, low)
        check("and the request timestamp is kept as the record of the ask",
              after.poc_requested_at is not None, after.poc_requested_at)


asyncio.run(ordering())

print("\n--- a proof for a credential is aimed at the asset, "
      "and the value never leaves ---")


async def credentials():
    """The prompt is the furthest-travelling copy of a finding.

    It goes to a third party and may be logged there, and a key found
    on a client's estate is still live after the engagement ends. So
    the one thing asserted here is that the VALUE is absent from what
    the model is sent, while the location -- which is what makes the
    check possible at all -- is present.
    """
    from app.agent.pocworker import _secret_brief, _target_url
    from app.models import FindingSecret

    sec = FindingSecret(
        # Deliberately not shaped like any real key: the secrets
        # hook refuses a committed credential, and a fixture that
        # looks like one is the thing it is there to catch.
        vuln_id=1, secret="<<not-a-real-key>>",
        detector="aws-access-key-id",
        asset_url="https://app.acme.example/static/main.js", line=412)
    brief = "\n".join(x for x in _secret_brief(sec) if x is not None)

    check("the credential value is NOT in what the model is told",
          "<<not-a-real-key>>" not in brief)
    check("but where it was seen IS, or no check could be written",
          "https://app.acme.example/static/main.js" in brief)
    check("and so is the kind of thing it is",
          "aws-access-key-id" in brief)
    check("the model is told not to authenticate with it",
          "withheld" in brief and "rather than testing" in brief)

    # Without this the proof is pointed at `https://host` and asks a
    # question the asset cannot answer.
    class V:
        port = 443
    check("a bare finding still targets the host",
          _target_url(V(), "app.acme.example", None)
          == "https://app.acme.example",
          _target_url(V(), "app.acme.example", None))
    check("a credential targets the ASSET it was found in, not the host",
          _target_url(V(), "app.acme.example", sec)
          == "https://app.acme.example/static/main.js",
          _target_url(V(), "app.acme.example", sec))

    # A secret whose origin was never recorded in columns. There is
    # nothing better than the host, and falling back to it beats
    # queueing a proof with no URL at all.
    bare = FindingSecret(vuln_id=2, secret="x", detector="generic")
    check("a credential with no recorded location falls back to the host",
          _target_url(V(), "app.acme.example", bare)
          == "https://app.acme.example",
          _target_url(V(), "app.acme.example", bare))


asyncio.run(credentials())

print(f"\n{ok} passed, {fail} failed")
_sys.exit(1 if fail else 0)
