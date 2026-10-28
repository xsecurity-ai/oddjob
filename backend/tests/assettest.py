"""Fetching a page's assets, recovering originals, and what is reported.

Driven against a REAL http server on loopback rather than a mocked
client. The thing most likely to be wrong in this pipeline is not
the parsing -- it is whether an asset is authorised, retrieved,
unpacked and attributed at all, and a mock proves none of that.

The scanners are not asserted on here. They are 79MB of binaries
that exist in the image and not in this suite, and a test that
quietly passes because nothing ran would be worse than no test:
`scan_project` is asserted to SAY it scanned nothing, which is the
behaviour that matters when a deployment is missing them.
"""
import http.server
import json
import os
import pathlib
import socket
import sys
import threading
import urllib.error
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

BASE = os.environ.get("ODDJOB_TEST_BASE", "http://127.0.0.1:8013")
passed = failed = 0


def check(label, cond, got=None):
    global passed, failed
    if cond:
        passed += 1
        print(f"  PASS  {label}" + (f" {got}" if got is not None else ""))
    else:
        failed += 1
        print(f"  FAIL  {label}" + (f" {got}" if got is not None else ""))


def call(p, m="GET", b=None, token=None):
    r = urllib.request.Request(BASE + p, method=m)
    if b is not None:
        r.data = json.dumps(b).encode()
        r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(r, timeout=60) as x:
            raw = x.read()
            return x.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw[:300]


# ---------------------------------------------------------- the estate
#
# A minified bundle that points at a source map, and the map, with
# the originals inside it. This is the shape the whole feature
# exists for: one URL in, several real files out.
BUNDLE = ('!function(){var t="x";function e(n){return n+t}'
          'window.q=e}();\n'
          '//# sourceMappingURL=app.min.js.map\n')
MAP = json.dumps({
    "version": 3,
    "sources": ["webpack:///src/auth/session.ts",
                "webpack:///../../../etc/passwd",
                "webpack:///src/omitted.ts"],
    "sourcesContent": [
        "export const LOGIN = '/api/v2/internal/login'\n",
        "root:x:0:0:root:/root:/bin/sh\n",
        None,
    ],
})
LONE = "var plain = 1;\n"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):                                 # noqa: N802
        body, ct = None, "application/javascript"
        if self.path.endswith("/app.min.js"):
            body = BUNDLE
        elif self.path.endswith("/app.min.js.map"):
            body, ct = MAP, "application/json"
        elif self.path.endswith("/plain.js"):
            body = LONE
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        raw = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):                        # noqa: A002
        pass


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


PORT = free_port()
srv = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
threading.Thread(target=srv.serve_forever, daemon=True).start()
ORIGIN = f"http://127.0.0.1:{PORT}"

admin = call("/api/auth/setup", "POST",
             {"username": "root", "password": "root-password-1"})[1]["access_token"]
call("/api/projects", "POST", {"code": "ASSET", "name": "ASSET"}, token=admin)
# 127.0.0.1 in scope: the PAGE must be in scope for its assets to be.
call("/api/projects/ASSET/scope", "POST", {"lines": ["127.0.0.1"]}, token=admin)
call("/api/targets?project=ASSET", "POST", {"host": "127.0.0.1"}, token=admin)

import asyncio  # noqa: E402
import hashlib  # noqa: E402

from sqlalchemy import select  # noqa: E402

from app.db import SessionLocal  # noqa: E402
from app.models import (  # noqa: E402
    Project,
    Target,
    TargetOrigin,
    Vuln,
    WebAddress,
    WebAsset,
    WebAssetFile,
    WebAssetRef,
)


async def seed():
    async with SessionLocal() as s:
        pr = (await s.execute(select(Project).where(
            Project.code == "ASSET"))).scalar_one()
        t = (await s.execute(select(Target).where(
            Target.project_id == pr.id))).scalars().first()
        for url, kind in ((f"{ORIGIN}/static/app.min.js", "script"),
                          (f"{ORIGIN}/static/plain.js", "script")):
            s.add(WebAsset(project_id=pr.id, target_id=t.id, url=url,
                           host="127.0.0.1", kind=kind,
                           first_page=f"{ORIGIN}/index.html", seen_on=1))
        # Referenced only by a page that is NOT in scope. Its own
        # host is the same; what differs is who asked for it.
        s.add(WebAsset(project_id=pr.id, target_id=None,
                       url=f"{ORIGIN}/static/outsider.js", host="127.0.0.1",
                       kind="script", first_page="http://nope.example/x.html",
                       seen_on=1))
        await s.commit()
        return pr.id


pid = asyncio.run(seed())

print("== fetching ==")
st, r = call("/api/web/assets/pending?project=ASSET", token=admin)
check("pending reports a backlog", (r or {}).get("unfetched") == 3,
      (r or {}).get("unfetched"))
check("...and says which scanners exist", "scanners" in (r or {}),
      (r or {}).get("scanners"))

st, r = call("/api/web/assets/fetch?project=ASSET", "POST", {}, token=admin)
check("the sweep answers", st == 200, st)
check("two assets were fetched", (r or {}).get("fetched") == 2, r)
# The ruling, as behaviour: authorisation comes from the PAGE. The
# third asset is on the same host as the other two and is still
# refused, because the only page referencing it is out of scope.
check("an asset whose only referrer is out of scope is NOT fetched",
      (r or {}).get("unauthorised") == 1, r)

print("\n== what came back ==")


async def files():
    async with SessionLocal() as s:
        rows = (await s.execute(select(WebAssetFile).where(
            WebAssetFile.project_id == pid))).scalars().all()
        return [(f.origin, f.path) for f in rows]


got = asyncio.run(files())
paths = {p for _, p in got}
origins = {o for o, _ in got}
check("the raw bundle is kept", ("raw", "app.min.js") in got, sorted(got)[:4])
check("originals are recovered from the source map",
      ("source", "src/auth/session.ts") in got, sorted(paths)[:5])
# The map names three sources; one has a null sourcesContent, which
# means "not included" rather than "empty". Inventing it would give
# the scanners a file to call clean.
check("a null sourcesContent entry is not invented as a file",
      "src/omitted.ts" not in paths, sorted(paths))
# `webpack:///../../../etc/passwd` is a legal sources entry.
check("a traversal path is neutralised, not stored raw",
      "etc/passwd" in paths and not any(".." in p for p in paths),
      sorted(paths))
# plain.js is not minified and has no map, so there is nothing to
# beautify and nothing to recover: one file only.
check("an unminified asset yields only its raw file",
      ("raw", "plain.js") in got and ("beautified", "plain.js.pretty") not in got,
      sorted(got))
check("origins are exactly the ones we produce",
      origins <= {"raw", "source", "beautified"}, origins)

print("\n== scanning ==")
st, r = call("/api/web/assets/scan?project=ASSET", "POST", {}, token=admin)
check("the scan sweep answers", st == 200, st)
# The binaries are in the image, not in this suite. The behaviour
# that matters here is that their ABSENCE is reported rather than
# read as "nothing found".
have = call("/api/web/assets/pending?project=ASSET",
            token=admin)[1].get("scanners", {})
# detect-secrets is a Python dependency, so a scanner is ALWAYS
# present -- there is no deployment of this that cannot look for
# secrets. The opengrep binary may be absent in a dev checkout;
# that is reported separately.
check("detect-secrets is always available, being a library",
      have.get("detect-secrets") is True, have)
check("files were examined", (r or {}).get("scanned", 0) > 0, r)
if not all(have.values()):
    check("...and a missing binary scanner is still reported",
          any("only some scanners" in n for n in (r or {}).get("notes", [])),
          (r or {}).get("notes"))


async def vulns():
    async with SessionLocal() as s:
        return (await s.execute(select(Vuln))).scalars().all()


rows = asyncio.run(vulns())
check("no finding stores a scanner's raw match",
      all("root:x:0:0" not in (v.description or "") for v in rows),
      len(rows))

print("\n== re-running is idempotent ==")
st, r2 = call("/api/web/assets/fetch?project=ASSET", "POST", {}, token=admin)
check("a second fetch finds nothing left to do",
      (r2 or {}).get("fetched") == 0, r2)
after = asyncio.run(files())
check("...and does not duplicate the files", len(after) == len(got),
      f"{len(got)} -> {len(after)}")

print("\n== it runs automatically ==")
# The point of the feature is that nobody has to press anything.
# Asserted on the WORKER rather than on the routes, because the
# routes being correct says nothing about whether they are ever
# called -- and "it runs automatically" resting on one unchecked
# line in main.py is exactly the drift that put ghost-debug behind
# a URL nothing routed to.
from app import assetwork as _aw  # noqa: E402
from app import main as _main  # noqa: E402

src = pathlib.Path(_main.__file__).read_text()
check("the asset worker is started at boot",
      "asset_worker.start()" in src)
check("...and it is the one from assetwork",
      "from .assetwork import worker as asset_worker" in src)
# No switch. The instruction was that this runs for all assets; a
# project flag would be a way to turn it off, so there is not one.
check("the worker takes no enable flag",
      "auto_assets" not in src and "auto_assets" not in
      pathlib.Path(_aw.__file__).read_text())
# FETCHING is what must stay small: every asset is a request at the
# client's estate. SCANNING is local and is ONE invocation of each
# tool over the whole batch -- almost all of its cost is startup, so
# a bigger batch is cheaper per file, and capping it would make the
# sweep slower for no benefit to anyone. The two are paced by
# different things and asserting one limit for both was wrong.
check("fetching is paced: it sends requests at the client",
      _aw.WORKER_FETCH <= 50 and _aw.CYCLE_SECS >= 60,
      f"fetch={_aw.WORKER_FETCH} cycle={_aw.CYCLE_SECS}")
check("scanning is batched into one run, so the batch is not tiny",
      _aw.WORKER_SCAN >= 50, f"scan={_aw.WORKER_SCAN}")


async def _one_cycle():
    """Drive one cycle by hand against the seeded project."""
    w = _aw.AssetWorker()
    await w._cycle()
    return w.last


# Everything is already fetched and scanned by this point, so the
# cycle must say so rather than redoing it -- which is also the
# proof that the worker is idempotent against a drained backlog.
said = asyncio.run(_one_cycle())
# Fetching really is drained: the unauthorised asset was stamped
# with its reason on the first sweep, so it is not reconsidered.
# Without that it stays in the backlog for ever and is re-examined
# every cycle, which the first run of this test caught.
check("the unauthorised asset is not retried for ever",
      "fetched 0" not in said or "unauthorised 1" not in said, said)
if any(have.values()):
    check("a cycle over a drained project reports nothing outstanding",
          said == "nothing outstanding", said)
else:
    # No scanners here, so the files stay unscanned and the cycle
    # keeps saying so -- which is correct, and is the behaviour that
    # stops a scanner-less deployment looking like a clean one.
    check("without scanners the cycle keeps saying it examined nothing",
          "not a clean result" in said, said)


async def _backlog():
    async with SessionLocal() as s:
        return await _aw.pending(s, pid)


owed = asyncio.run(_backlog())
check("nothing is left owed on the fetch side", owed["unfetched"] == 0, owed)

print("\n== a finding knows which file it came from ==")
# The bug this exists for. A batch scans many files in ONE run, so
# the caller cannot know which file a result belongs to -- it
# passes "" and the parser must read the path the SCANNER
# reported. Taking the argument instead meant every finding came
# back with an empty path, failed to map back to a file, and was
# dropped: the scanners ran, found things, and the sweep recorded
# nothing. 0 findings looked exactly like a clean estate.
from app import assetscan as _asx  # noqa: E402

_og = ('{"results":[{"check_id":"js.eval","path":"/tmp/d/7__a.js",'
       '"extra":{"severity":"ERROR","message":"m"},"start":{"line":3}}]}')
_f = _asx.parse_opengrep(_og, "")[0]
check("opengrep findings carry the reported path",
      _f.path == "/tmp/d/7__a.js" and _f.line == 3, (_f.path, _f.line))
# The caller's path is still the fallback, for a single-file call.
check("...and the caller's path is still used when none is reported",
      _asx.parse_opengrep(
          '{"results":[{"check_id":"r","extra":{},"start":{}}]}',
          "given.js")[0].path == "given.js")

print("\n== fetching is parallel across hosts, serial per host ==")
# The backlog is not spread evenly -- on the live estate 1,896 of
# 7,800 queued assets are on ONE host -- so plain global
# concurrency would point every slot at one server. Two properties
# matter and neither is visible from the sweep's totals.


async def _parallelism_probe():
    """Fetch a batch spanning several hosts, recording overlap."""
    import app.assetfetch as _af

    inflight: dict[str, int] = {}
    peak_per_host = 0
    peak_global = 0
    live = 0
    real = _af.fetch

    async def spy(client, url, *, user_agent):
        nonlocal peak_per_host, peak_global, live
        from urllib.parse import urlparse
        h = urlparse(url).hostname or ""
        inflight[h] = inflight.get(h, 0) + 1
        live += 1
        peak_per_host = max(peak_per_host, inflight[h])
        peak_global = max(peak_global, live)
        try:
            await asyncio.sleep(0.05)
            return await real(client, url, user_agent=user_agent)
        finally:
            inflight[h] -= 1
            live -= 1

    async with SessionLocal() as s:
        pr = (await s.execute(select(Project).where(
            Project.code == "ASSET"))).scalar_one()
        t = (await s.execute(select(Target).where(
            Target.project_id == pr.id))).scalars().first()
        # Six assets over two genuinely different URL HOSTNAMES,
        # both of which reach the loopback server. The first
        # version of this varied `web_assets.host` while every URL
        # pointed at 127.0.0.1 -- so there was really one host, and
        # it could not tell correct serialisation from no
        # parallelism. The lock keys on the URL, so the URL is what
        # has to differ.
        for i in range(6):
            origin = (ORIGIN if i % 2
                      else f"http://localhost:{PORT}")
            s.add(WebAsset(project_id=pr.id, target_id=t.id,
                           url=f"{origin}/static/plain.js?par={i}",
                           host="127.0.0.1" if i % 2 else "localhost",
                           kind="script",
                           first_page=f"{ORIGIN}/index.html", seen_on=1))
        await s.commit()
        _af.fetch = spy
        try:
            await _aw.fetch_project(s, pr.id, user_agent="t", limit=6)
        finally:
            _af.fetch = real
    return peak_per_host, peak_global


# Ordering, tested directly: the probe above cannot see it,
# because its fixture alternates hosts and so looks spread however
# the batch is chosen. A real queue arrives clustered.
class _A:
    def __init__(self, h):
        self.host = h


_clustered = [_A("a.example")] * 10 + [_A("b.example")] * 10
_picked = _aw.spread_by_host(_clustered, 6)
check("a clustered queue is spread across hosts, not taken in order",
      len({x.host for x in _picked}) == 2,
      [x.host for x in _picked])
check("...and the batch is still the size asked for", len(_picked) == 6)
check("a single-host queue still fills the batch",
      len(_aw.spread_by_host([_A("only.example")] * 10, 4)) == 4)

_pph, _pg = asyncio.run(_parallelism_probe())
check("never more than one request in flight at a host",
      _pph <= 1, f"peak per host = {_pph}")
check("but several hosts are fetched at once",
      _pg > 1, f"peak concurrent = {_pg}")
check("concurrency is bounded, not unlimited",
      _pg <= _aw.FETCH_CONCURRENCY, f"{_pg} <= {_aw.FETCH_CONCURRENCY}")

print("\n== endpoints out of JavaScript ==")
# A crawl finds what a page LINKS to; a bundle contains what it
# CALLS. Every case below is noise measured on real bundles from
# the estate -- the first version of this returned 2,732 hits over
# 400 files, nearly all of it rubbish, and each filter here is one
# category of that.
from app import assetlinks as _al  # noqa: E402

_js = """
  var a = "/api/v2/accounts/balance";
  fetch("/_nc_external/system/security/session/SessionTimeServlet");
  var svg = "http://www.w3.org/2000/svg";
  var enc = "/%3E%3C/svg%3E";
  var bot = "/0aiqGemfFwpl8/PK3qP/8DBQb6iLw/5it1";
  var lib = "node_modules/@popperjs/core/lib/index.js";
  var img = "/static/img/logo.png";
  var mime = "application/json";
  var date = "/2024/01/15";
  var one = "/x";
  var tpl = "/${a}/${b}";
  var host = "https://mpms-mufg.euwest01.umbraco.io/en/retirement/";
"""
_eps = _al.extract(_js)
_vals = {e.value for e in _eps}

check("a real API path is kept", "/api/v2/accounts/balance" in _vals, sorted(_vals))
check("a real servlet path is kept",
      "/_nc_external/system/security/session/SessionTimeServlet" in _vals)
check("a real host URL is kept",
      "https://mpms-mufg.euwest01.umbraco.io/en/retirement/" in _vals)
# Every one of these appeared in the live measurement.
# Checked on the HOST, not as a substring. `"w3.org" in url` is
# the shape CodeQL flags as incomplete URL sanitisation, and it is
# wrong for the same reason here as anywhere: `https://w3.org.evil
# .example/` contains it too. The assertion should say what it
# means -- no endpoint is SERVED BY that host.
check("an XML namespace is not an endpoint",
      "w3.org" not in _al.hosts_of(_eps)
      and not any(v.startswith(("http://www.w3.org/", "https://www.w3.org/"))
                  for v in _vals),
      sorted(_vals))
check("percent-encoded markup is not a path",
      not any("%3" in v.lower() for v in _vals))
check("a bot-manager token path is not a path",
      not any("0aiqGem" in v for v in _vals))
check("node_modules is not the application's surface",
      not any("node_modules" in v for v in _vals))
check("an image is an asset, not a route",
      not any(v.endswith(".png") for v in _vals))
check("a MIME type is not a path", "/json" not in _vals)
check("a date is not a path", "/2024/01/15" not in _vals)
check("a single segment is not a path (it is usually division)",
      "/x" not in _vals)
check("a template with nothing fixed names no route",
      not any(v.startswith("/${") for v in _vals))
check("hosts are reported separately from paths",
      _al.hosts_of(_eps) == ["mpms-mufg.euwest01.umbraco.io"],
      _al.hosts_of(_eps))
# Stability matters: these are upserted, so an unchanged file must
# produce an identical list or every sweep writes rows for ever.
# ReDoS. These patterns run over a client's minified JavaScript,
# which is hostile by construction, and Python's `re` holds the
# GIL while it backtracks -- so one bad string does not hang one
# task, it hangs the worker. CodeQL caught `^/(?:\\d+/?)+$` here
# (py/redos): 0.005s at 18 digits, 0.292s at 24.
import time as _time  # noqa: E402

# TWO segments, and no final match. The first version of this
# guard used one segment -- which `_QUOTED_PATH` never matches, so
# `_plausible` was never called and the vulnerable regex never
# ran. The guard passed with the exponential pattern restored,
# which is a guard that tests nothing. With two segments the bad
# pattern takes 2.3s at 2x14 digits and grows ~4x per 2 digits.
_bomb = 'var x = "/' + "9" * 16 + "/" + "9" * 16 + 'x";'
_t0 = _time.time()
_al.extract(_bomb)
_el = _time.time() - _t0
check("a digit run that reaches the matcher does not blow it up",
      _el < 1.0, f"{_el:.3f}s")
_t0 = _time.time()
_al.extract('var x = "/' + "a/" * 2000 + '";')
check("nor does a long run of segments",
      _time.time() - _t0 < 1.0)

check("extraction is stable for the same input",
      [e.value for e in _al.extract(_js)] == [e.value for e in _eps])

print("\n== a finding reads like something a client can act on ==")
# Both of these reached production. The title is the field somebody
# reads first, and it named a temporary directory that no longer
# exists, prefixed by wherever our container keeps its rule files.
check("the rules directory is not part of the rule name",
      _asx._rule_name("opt.opengrep-rules.javascript.lang.security.eval")
      == "javascript.lang.security.eval",
      _asx._rule_name("opt.opengrep-rules.javascript.lang.security.eval"))
check("...and a rule with no such prefix is left alone",
      _asx._rule_name("javascript.lang.security.eval")
      == "javascript.lang.security.eval")

_tmp = _asx.Finding("opengrep", "javascript.lang.security.eval",
                    "stale title in /tmp/oddjob-scan-abc/9__dropdown.js",
                    "high", "/tmp/oddjob-scan-abc/9__dropdown.js", 7,
                    "detail", "fp")
_fixed = _aw._reseat(_tmp, "js/src/dropdown.js")
check("the title names the developer's file, not our temp directory",
      _fixed.title == "javascript.lang.security.eval in js/src/dropdown.js",
      _fixed.title)
check("...and no trace of the temp path survives",
      "/tmp/" not in _fixed.title and "__" not in _fixed.title,
      _fixed.title)
# Re-seating must not drop the credential. `_reseat` REBUILDS the
# finding rather than mutating it, so a field left off the
# constructor call is silently lost -- which is what happened to
# `secret` until this check existed.
_sec = _aw._reseat(
    _asx.Finding("detect-secrets", "AWS", "x", "high",
                 "/tmp/oddjob-scan-abc/9__a.ts", 4, "d", "fp",
                 secret="planted-not-a-real-credential"),
    "src/aws.ts")
check("re-seating keeps the credential it was carrying",
      _sec.secret == "planted-not-a-real-credential", _sec.secret)

print("\n== a scanner that fails does not retire the files ==")
# The trap this closes, seen in production: every opengrep run hit
# the timeout, returned no output, and the file was stamped
# `scanned_at` anyway. 50 files were recorded as examined when
# nothing had looked at them -- and a stamped file is never picked
# up again, so the gap is permanent and silent.
from app import assetscan as _as  # noqa: E402

_real_run = _as._run


async def _fail(*a, **k):
    return -1, "", "timed out"


async def _with_failing_scanner():
    async with SessionLocal() as s:
        # Put some files back in the queue to be scanned.
        rows = (await s.execute(select(WebAssetFile).limit(3))).scalars().all()
        for r in rows:
            r.scanned_at = None
        await s.commit()
        ids = [r.id for r in rows]

        _as._run = _fail
        try:
            sw = await _aw.scan_project(s, pid, limit=10)
        finally:
            _as._run = _real_run

        still = (await s.execute(select(WebAssetFile).where(
            WebAssetFile.id.in_(ids),
            WebAssetFile.scanned_at.is_(None)))).scalars().all()
        return sw, len(still), len(ids)


# Gated on a SUBPROCESS scanner, not on any scanner: `_run` is how
# opengrep is invoked, and detect-secrets does not go through it --
# patching `_run` where the binary is absent would prove nothing.
if have.get("opengrep"):
    sw, still, n = asyncio.run(_with_failing_scanner())
    check("a timed-out scanner leaves the files unscanned",
          still == n, f"{still} of {n} still queued")
    check("...and says so rather than reporting a clean sweep",
          any("NOT marked scanned" in x for x in sw.notes), sw.notes)
else:
    # opengrep is not here, so `_run` is never reached and the
    # flag cannot be exercised. Saying that is better than a check
    # that passes because nothing happened.
    check("skipped: no subprocess scanner present to fail", True,
          "(the binary lives in the image, not in this suite)")

print("\n== secret precision ==")
# Every case here is a REAL false positive from the estate. The
# first production run produced 60 secret findings and an operator
# checked them: all false positives. These rules were derived from
# those 60 and remove 59 of them.
from app.assetscan import implausible_secret as _imp  # noqa: E402
from app.assetscan import shannon as _sh  # noqa: E402

for val, det, why in [
    # 43 of the 60: 20-character lowercase hex from one Microsoft
    # login bundle. Telemetry and flight ids, not keys.
    ("638ff95a0cb0f0d4a2b1", "Hex High Entropy String", "fixed-length hex"),
    # Windows HRESULTs out of a Constants.js.
    ("8004341E", "Secret Keyword", "too short"),
    # The literal `true`, assigned next to a credential-ish word.
    ("true", "Secret Keyword", "too short"),
    # English prose out of a localisation file: `password: "The
    # password you entered is incorrect"` is a message ABOUT a
    # password, which is what the keyword matched.
    ("The password you entered is incorrect",
     "Secret Keyword", "whitespace"),
    # Telemetry event names -- words joined by underscores.
    ("eOTT_NoPasswordAccountLoginCode", "Secret Keyword", "no digits"),
    # The next four classes come from the SECOND measurement, on
    # all 234 findings rather than the first 60. Each is a thing
    # published on purpose or generated by a build.
    #
    # Subresource Integrity: the page states the hash in public so
    # the browser can check it.
    ("sha384-" + "AbCdEf0123456789" * 4,
     "Base64 High Entropy String", "an SRI hash"),
    # A reCAPTCHA SITE key, rendered into the markup by design.
    # The secret half never leaves the server.
    ("6L" + "e-XampleSiteKey0123456789abcdefghijKLM",
     "Base64 High Entropy String", "a CAPTCHA site key"),
    # A build number joined to a 128-bit content digest. 25 of the
    # 234 were this exact shape.
    ("1456_" + "ExampleDigest0123456zz",
     "Base64 High Entropy String", "a cache-buster"),
    # 2,278 of 3,365 findings on the estate were 64-character hex
    # from ONE file: elliptic.min.js. This is the secp256k1
    # generator point Gx -- a published curve constant in every
    # implementation of that curve, reported as a secret 2,278
    # times.
    ("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
     "Hex High Entropy String", "a published curve constant"),
    # An MD5-length digest, same argument.
    ("b9d934e1aa7749a5ab171ce2d83a20f6",
     "Hex High Entropy String", "a digest-length hex string"),
    # ASP.NET Data Protection: antiforgery tokens and encrypted
    # cookies, issued to the browser on purpose and rotated per
    # request. 134 on the estate, every one distinct, every one a
    # brand new "secret" on the next sweep.
    ("CfDJ8" + "ExampleAntiforgeryPayload0123456789abcdef",
     "Base64 High Entropy String", "an ASP.NET Data Protection token"),
    # A base64 codec table. All-distinct by construction.
    ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
     "Base64 High Entropy String", "an alphabet table"),
]:
    check(f"rejected: {why}", _imp(val, det) is not None,
          f"{val[:28]!r} -> {_imp(val, det)}")

# And the one thing in those 60 worth a look: base64 that decodes
# towards JSON. It has digits, no whitespace, real entropy.
_jwt = "clienteyJ1aWQiOiJkMTdkMzcwNi0xZTRlLTQ0YWItOTkwMC1hYmNkZWYxMjM0NTYi"
check("kept: a base64 blob with real entropy",
      _imp(_jwt, "Base64 High Entropy String") is None,
      _imp(_jwt, "Base64 High Entropy String"))
# A vendor shape is evidence in itself, so the entropy floor must
# not apply to it -- an issuer's prefix means more than randomness.
check("kept: a vendor-shaped key is judged on its shape",
      _imp("npm_abcdefghij1234567890klmnopqrstuvwx", "NPM tokens") is None)
# Digest-length hex is dropped only for the ENTROPY detectors. A
# named vendor pattern matching a hex string means an issuer's shape
# was recognised, which is evidence in itself; entropy matching one
# means only that hex is varied, which every digest also satisfies.
check("kept: a vendor-named detector that matched hex is still judged on its shape",
      _imp("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
           "Generic High Entropy Secret") is None)
# What this rule gives up, stated rather than hidden: a 256-bit key
# written as bare hex is indistinguishable from a SHA-256 and goes
# with them. The trade is the right way round at a measured ratio of
# better than a thousand to one -- a reviewer who cannot see past
# 2,479 curve constants will not find the one key either.
check("dropped: so is a real 256-bit key written as bare hex",
      _imp("a3f1" + "0" * 60, "Hex High Entropy String") is not None)
# Not every long hex string is a digest. The rule names three exact
# lengths; anything else must survive, or it stops being a statement
# about digests and becomes "long hex is never a secret".
#
# Written `is None or True` first time, which is true whatever the
# code does -- a check that tests nothing and reads like one that
# does.
_odd = "0123456789abcdef" * 3 + "0123456789ab"   # 60: no digest is
check("kept: hex at a length no digest has",
      len(_odd) == 60 and _imp(_odd, "Hex High Entropy String") is None,
      f"{len(_odd)} chars -> {_imp(_odd, 'Hex High Entropy String')}")

# The all-distinct rule is the birthday bound, not a pattern, so
# its two edges are what need proving: it must not reach a SHORT
# string, where all-distinct is unremarkable, and it must not
# reach a long one that repeats a character -- which a generated
# value of that length does with probability ~0.9996.
#: 19 characters, every one different: over the length floor and
#: under MIN_ALPHABET_LEN, which is the only window where this
#: rule's threshold is what decides the answer. A shorter string
#: would be rejected by the length floor instead and the check
#: would pass without testing anything.
_SHORT_DISTINCT = "abc123XYZ_-+/defghi"
check("kept: a short all-distinct value is not an alphabet table",
      _imp(_SHORT_DISTINCT, "Base64 High Entropy String") is None,
      f"{len(_SHORT_DISTINCT)} chars, all distinct, under the threshold")
check("kept: a long generated value repeats, so the rule misses it",
      _imp("a1b2c3d4e5f6g7h8a1b2c3d4e5f6g7h8i9",
           "Base64 High Entropy String") is None)
# A cache-buster is anchored to a 22-character digest. A longer
# or shorter tail is not that scheme and must survive.
check("kept: an underscore alone does not make a cache-buster",
      _imp("1456_" + "ExampleDigest0123456zz" + "toolong",
           "Base64 High Entropy String") is None)
# What the entropy floor actually does, which is NOT what I first
# asserted: the English prose above scores 3.7 -- ABOVE the floor
# -- and is caught by the whitespace rule instead. Measured against
# the 60 real false positives, the entropy rule caught none of
# them. It is kept because repetitive placeholders are a real
# class, not because it did the work here.
check("entropy rejects repetitive filler",
      _sh("aaaaaaaaaaaaaaaa") < 3.2 and _sh("ABCD_ABCD_ABCD_ABCD") < 3.2,
      f"{_sh('aaaaaaaaaaaaaaaa'):.1f}, {_sh('ABCD_ABCD_ABCD_ABCD'):.1f}")
check("...and the prose was caught by whitespace, not entropy",
      _sh("The password you entered") > 3.2,
      f"{_sh('The password you entered'):.1f}")

print("\n== the credential behind a finding ==")
# Visible on purpose: a secret finding you cannot read is one you
# cannot verify, rotate or hand to the client. The handling is
# what makes that safe -- out of the description, behind a role,
# and written to the audit log before it is returned.
from app.models import FindingSecret as _FS  # noqa: E402

#: Distinctive, and deliberately NOT credential-shaped. A literal
#: that looks like a real key trips scripts/check-secrets.sh --
#: correctly, because a credential-shaped string in the tree is
#: what that check exists to catch, and it must not be weakened
#: to accommodate a fixture. Proving the value does not leak into
#: the description or the audit log needs it to be unique, not to
#: be realistic.
PLANTED = "planted-test-value-" + "not-a-real-credential"


async def _plant_secret():
    async with SessionLocal() as s:
        pr = (await s.execute(select(Project).where(
            Project.code == "ASSET"))).scalar_one()
        t = (await s.execute(select(Target).where(
            Target.project_id == pr.id))).scalars().first()
        v = Vuln(target_id=t.id, title="AWS credential in src/aws.ts",
                 severity="high", status="open",
                 description="Detector: AWS. Match: AK…LE (20 chars).",
                 external_id="detect-secrets:deadbeef")
        s.add(v)
        await s.flush()
        s.add(_FS(vuln_id=v.id, secret=PLANTED,
                  detector="AWS Access Key"))
        await s.commit()
        return v.id


_vid = asyncio.run(_plant_secret())

st, body = call(f"/api/vulns/{_vid}", token=admin)
check("the finding itself never carries the value", st == 200
      and PLANTED not in json.dumps(body), st)

st, sec = call(f"/api/vulns/{_vid}/secret", token=admin)
check("the reveal endpoint returns it", st == 200
      and (sec or {}).get("secret") == PLANTED, st)
check("...and names the detector",
      (sec or {}).get("detector") == "AWS Access Key", sec)

st, _ = call("/api/vulns/999999/secret", token=admin)
check("an unknown finding is 404", st == 404, st)

# A finding with no stored credential is the ordinary case for
# anything scanned before they were kept -- it must read as "none
# here", not as an error in the page.
async def _bare():
    async with SessionLocal() as s:
        pr = (await s.execute(select(Project).where(
            Project.code == "ASSET"))).scalar_one()
        t = (await s.execute(select(Target).where(
            Target.project_id == pr.id))).scalars().first()
        v = Vuln(target_id=t.id, title="older finding", severity="low",
                 status="open", external_id="detect-secrets:older")
        s.add(v)
        await s.commit()
        return v.id


_bare_id = asyncio.run(_bare())
st, msg = call(f"/api/vulns/{_bare_id}/secret", token=admin)
check("a finding with no stored credential says so", st == 404,
      f"{st} {str(msg)[:70]}")

# ------------------------------------------------------ the source
# Clicking a secret shows the file it was found in, positioned on
# the value. Three outcomes are asserted and not two: a stored body
# can have moved on since the scan, and scrolling somebody
# confidently to a line the value is no longer on would be the tool
# asserting something it has not checked.
SRC_URL = "https://app.acme.example/static/bundle.abc123.js"
SRC_PATH = "src/config/keys.ts"
SRC_LINES = ["export const config = {",
             "  region: 'us-east-1',",
             f"  key: '{PLANTED}',",
             "  retries: 3,",
             "}"]
SRC_BODY = "\n".join(SRC_LINES)
#: The value sits on line 3, counting from 1.
SRC_LINE = 3


async def _plant_source(tag, line, body=SRC_BODY, path=SRC_PATH,
                        with_asset=True):
    """A finding whose origin columns point at a stored file.

    One asset per call, named by `tag`: `web_assets` is unique on
    (project, url), so reusing one URL across these fixtures fails
    the second insert rather than the assertion it was written for.
    """
    url = SRC_URL.replace("abc123", f"abc123-{tag}")
    async with SessionLocal() as s:
        pr = (await s.execute(select(Project).where(
            Project.code == "ASSET"))).scalar_one()
        t = (await s.execute(select(Target).where(
            Target.project_id == pr.id))).scalars().first()
        v = Vuln(target_id=t.id, title="credential in a bundle",
                 severity="high", status="open",
                 external_id=f"detect-secrets:src-{line}-{with_asset}-{len(body)}")
        s.add(v)
        await s.flush()
        s.add(_FS(vuln_id=v.id, secret=PLANTED, detector="AWS Access Key",
                  asset_url=url, path=path, line=line))
        if with_asset:
            a = WebAsset(project_id=pr.id, target_id=t.id, url=url,
                         kind="script", host="app.acme.example")
            s.add(a)
            await s.flush()
            s.add(WebAssetFile(asset_id=a.id, project_id=pr.id,
                               origin="source", path=path, body=body,
                               bytes=len(body)))
        await s.commit()
        return v.id


_src_id = asyncio.run(_plant_source("hit", SRC_LINE))
st, src = call(f"/api/vulns/{_src_id}/secret/source", token=admin)
src = src or {}
check("the source endpoint returns the file", st == 200
      and src.get("body") == SRC_BODY, f"{st} {str(src)[:80]}")
check("...and says which origin it is, so a beautified line number "
      "is not read as the developer's own source",
      src.get("origin") == "source", src.get("origin"))
check("...and confirms the value is where the finding said",
      src.get("located") == "confirmed", src.get("located"))
# The offsets are the whole point: a minified bundle is one line, so
# the line number names the entire file and only these name the value.
_ms, _me = src.get("match_start"), src.get("match_end")
check("...and the match offsets select exactly the credential",
      _ms is not None and src.get("body", "")[_ms:_me] == PLANTED,
      f"{_ms}:{_me}")

# The file moved on after the scan. Still findable, and said so.
_moved_id = asyncio.run(_plant_source("moved", 1))
st, mv = call(f"/api/vulns/{_moved_id}/secret/source", token=admin)
mv = mv or {}
check("a value no longer at the recorded line reads as moved",
      st == 200 and mv.get("located") == "moved", f"{st} {mv.get('located')}")
_ms2, _me2 = mv.get("match_start"), mv.get("match_end")
check("...and is still highlighted where it actually is",
      _ms2 is not None and mv.get("body", "")[_ms2:_me2] == PLANTED,
      f"{_ms2}:{_me2}")

# The stored body is not the one that was scanned at all.
_gone_id = asyncio.run(_plant_source(
    "gone", 2, body="export const config = { region: 'us-east-1' }\n"))
st, gone = call(f"/api/vulns/{_gone_id}/secret/source", token=admin)
gone = gone or {}
check("a body that no longer holds the value reads as absent",
      st == 200 and gone.get("located") == "absent", f"{st} {gone.get('located')}")
check("...and highlights nothing rather than guessing",
      gone.get("match_start") is None, gone.get("match_start"))

# ---------------------------------------- a credential found in a PAGE
#
# `scan_pages` runs the same scanners over the body of every captured
# 2xx exchange and files what they find through the same `_file_vuln`,
# which stores the PAGE's url in `asset_url`. That url is a
# `web_addresses` row and is never in `web_assets`, so the asset
# lookup cannot succeed for one of them -- and the endpoint used to
# answer "the asset was removed, or the project was re-imported",
# which is a confident explanation of something that never happened.
#
# On the live estate that was 87 of 1,588 stored credentials: every
# one findable, none viewable, all blamed on a deletion that had not
# occurred. The evidence was in the captured response the whole time.
PAGE_URL = "https://app.acme.example/settings"
PAGE_BODY = ("<html><head><title>Settings</title></head>\n"
             "<body>\n"
             f"<script>const key = '{PLANTED}';</script>\n"
             "</body></html>\n")


async def _plant_page_secret():
    """A finding recorded against a captured page, not an asset file."""
    async with SessionLocal() as s:
        pr = (await s.execute(select(Project).where(
            Project.code == "ASSET"))).scalar_one()
        t = (await s.execute(select(Target).where(
            Target.project_id == pr.id))).scalars().first()
        v = Vuln(target_id=t.id, title="credential in a page",
                 severity="high", status="open",
                 external_id="detect-secrets:page-origin")
        s.add(v)
        await s.flush()
        # Line 3 of the BODY, which is what the scanner was handed:
        # `scan_pages` strips the header block before scanning.
        s.add(_FS(vuln_id=v.id, secret=PLANTED, detector="AWS Access Key",
                  asset_url=PAGE_URL, path=PAGE_URL, line=3))
        s.add(WebAddress(
            target_id=t.id, url=PAGE_URL,
            url_hash=hashlib.sha256(PAGE_URL.encode()).hexdigest(),
            exchange_hash=hashlib.sha256(b"page-origin").hexdigest(),
            scheme="https", path="/settings", status_code=200,
            content_type="text/html",
            # A raw capture: status line, headers, blank line, body.
            # The endpoint has to strip exactly what the scanner did
            # or the recorded line number lands in the headers.
            response="HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                     + PAGE_BODY,
            sources="pagescan"))
        await s.commit()
        return v.id


_page_id = asyncio.run(_plant_page_secret())
st, pg = call(f"/api/vulns/{_page_id}/secret/source", token=admin)
pg = pg or {}
check("a credential found in a page body can be viewed at all",
      st == 200, f"{st} {str(pg)[:120]}")
check("...showing the response BODY, not the header block",
      pg.get("body", "").startswith("<html>"), pg.get("body", "")[:40])
check("...and the recorded line still means what it meant to the "
      "scanner, which was handed the stripped body",
      pg.get("located") == "confirmed", pg.get("located"))
_pms, _pme = pg.get("match_start"), pg.get("match_end")
check("...with the value itself highlighted",
      _pms is not None and pg.get("body", "")[_pms:_pme] == PLANTED,
      f"{_pms}:{_pme}")
check("...offering one view, because a page has no minified sibling "
      "or source map to choose between",
      [v["origin"] for v in (pg.get("views") or [])] == ["page"],
      pg.get("views"))
check("...named as a page rather than borrowing an asset's vocabulary",
      pg.get("origin") == "page" and pg.get("recorded_origin") == "page", pg)

# Nothing to show, which is not the same as an error in the page.
_noasset_id = asyncio.run(_plant_source(
    "never-fetched", SRC_LINE, with_asset=False))
st, _nores = call(f"/api/vulns/{_noasset_id}/secret/source", token=admin)
check("a finding whose origin is not recorded is a 404, not a 500",
      st == 404, st)
# The message must not name a cause it cannot know. It used to blame
# a deletion for every page finding in the estate.
check("...and the 404 says BOTH an asset and a page were looked for",
      "asset" in str(_nores).lower() and "page" in str(_nores).lower(),
      _nores)

st, _ = call(f"/api/vulns/{_bare_id}/secret/source", token=admin)
check("a finding with no stored credential has no source either",
      st == 404, st)

# ------------------------------------------------- readable views
# A secret in a minified bundle is a secret on one line thousands of
# characters long. The same bytes usually exist in a second, readable
# form, so that is what opens.
#
# One line, and long enough that `looks_minified` agrees -- it judges
# on the longest line, not on file size.
MIN_BODY = ("var a=1;" * 80) + f"var k='{PLANTED}';" + ("var b=2;" * 80)
PRETTY_BODY = "\n".join(["var a=1;"] * 80 + [f"var k='{PLANTED}';"]
                        + ["var b=2;"] * 80)


async def _plant_views(tag, pretty: bool):
    """A finding recorded against a minified RAW file.

    `pretty` decides whether a beautified sibling is already stored,
    which is the difference between the two cases that matter: one
    where a readable rendering exists and one where it has to be
    produced.
    """
    url = f"https://app.acme.example/static/bundle-{tag}.js"
    async with SessionLocal() as s:
        pr = (await s.execute(select(Project).where(
            Project.code == "ASSET"))).scalar_one()
        t = (await s.execute(select(Target).where(
            Target.project_id == pr.id))).scalars().first()
        v = Vuln(target_id=t.id, title="credential in a minified bundle",
                 severity="high", status="open",
                 external_id=f"detect-secrets:views-{tag}")
        s.add(v)
        await s.flush()
        # Recorded against the RAW file, on its only line.
        s.add(_FS(vuln_id=v.id, secret=PLANTED, detector="AWS Access Key",
                  asset_url=url, path=f"bundle-{tag}.js", line=1))
        a = WebAsset(project_id=pr.id, target_id=t.id, url=url,
                     kind="script", host="app.acme.example")
        s.add(a)
        await s.flush()
        s.add(WebAssetFile(asset_id=a.id, project_id=pr.id, origin="raw",
                           path=f"bundle-{tag}.js", body=MIN_BODY,
                           bytes=len(MIN_BODY)))
        if pretty:
            s.add(WebAssetFile(asset_id=a.id, project_id=pr.id,
                               origin="beautified",
                               path=f"bundle-{tag}.js.pretty",
                               body=PRETTY_BODY, bytes=len(PRETTY_BODY)))
        await s.commit()
        return v.id


# A stored .pretty exists, so it is what opens.
_v_stored = asyncio.run(_plant_views("stored", pretty=True))
st, w = call(f"/api/vulns/{_v_stored}/secret/source", token=admin)
w = w or {}
check("a minified bundle opens on its readable copy",
      st == 200 and w.get("origin") == "beautified", f"{st} {w.get('origin')}")
check("...which is stored, not produced for this request",
      w.get("generated") is False, w.get("generated"))
check("...and both renderings are offered",
      sorted(v["origin"] for v in w.get("views", [])) == ["beautified", "raw"],
      [v.get("origin") for v in w.get("views", [])])
# The line belongs to the file the scanner read, and that is not the
# one on screen. Quoting it here would name a line in another file.
check("...the recorded origin is still reported as raw",
      w.get("recorded_origin") == "raw", w.get("recorded_origin"))
check("...the value is located by searching, not by the recorded line",
      w.get("located") == "found", w.get("located"))
check("...so no line number is claimed for a file the scanner never read",
      w.get("line") is None, w.get("line"))
_ms, _me = w.get("match_start"), w.get("match_end")
check("...and the highlight still selects exactly the credential",
      _ms is not None and w.get("body", "")[_ms:_me] == PLANTED, f"{_ms}:{_me}")

# And the other rendering is still reachable, where the line DOES mean
# something.
st, r = call(f"/api/vulns/{_v_stored}/secret/source?view=raw", token=admin)
r = r or {}
check("the raw file can still be asked for", st == 200
      and r.get("origin") == "raw", f"{st} {r.get('origin')}")
check("...and there the recorded line is confirmed",
      r.get("located") == "confirmed" and r.get("line") == 1,
      f"{r.get('located')} line={r.get('line')}")

# No stored .pretty: one is produced, and says so.
_v_gen = asyncio.run(_plant_views("gen", pretty=False))
st, g = call(f"/api/vulns/{_v_gen}/secret/source", token=admin)
g = g or {}
check("a bundle with no stored readable copy gets one made",
      st == 200 and g.get("origin") == "beautified", f"{st} {g.get('origin')}")
check("...and it is flagged as produced for this request, because its "
      "line numbers have never been stored",
      g.get("generated") is True, g.get("generated"))
check("...and the credential is found in it",
      g.get("located") == "found", g.get("located"))
_gs, _ge = g.get("match_start"), g.get("match_end")
check("...and highlighted exactly",
      _gs is not None and g.get("body", "")[_gs:_ge] == PLANTED, f"{_gs}:{_ge}")

# An unreadable `view` is not an error: it falls back to the default
# rather than 400ing a UI that asked for something reasonable.
st, bad = call(f"/api/vulns/{_v_gen}/secret/source?view=nonsense", token=admin)
check("an unknown view falls back rather than failing",
      st == 200 and (bad or {}).get("origin") == "beautified",
      f"{st} {(bad or {}).get('origin')}")

# And the page must not OFFER the reveal in the first place.
#
# The UI used to decide from the external_id prefix, which is true
# of every detect-secrets finding and wrong for the 92 on the
# estate that predate values being kept: the button appeared, was
# pressed, and returned the 404 above as an error. An operator
# reported it. A control that cannot do what it offers is worse
# than no control, so the server answers the question instead.
st, bare_detail = call(f"/api/vulns/{_bare_id}", token=admin)
check("a finding with no credential does not advertise one",
      st == 200 and (bare_detail or {}).get("has_secret") is False,
      f"{st} {(bare_detail or {}).get('has_secret')}")
st, rich_detail = call(f"/api/vulns/{_vid}", token=admin)
check("...and one that has a credential says so",
      st == 200 and (rich_detail or {}).get("has_secret") is True,
      f"{st} {(rich_detail or {}).get('has_secret')}")
check("...without the value riding along in the answer",
      PLANTED not in json.dumps(rich_detail), "value leaked into the detail")

# The reveal must be IN the audit log, and the log must not be a
# second place the credential lives -- it is readable by every
# site admin, which is the whole reason it is not in the
# description either.
async def _audit_rows():
    from app.models import AuditEvent
    async with SessionLocal() as s:
        return (await s.execute(select(AuditEvent).where(
            AuditEvent.action == "finding.secret.reveal"))).scalars().all()


_rows = asyncio.run(_audit_rows())
check("revealing is written to the audit log", len(_rows) >= 1, len(_rows))
check("...naming who did it",
      any(r.username == "root" for r in _rows),
      [r.username for r in _rows][:3])
check("...and the log does NOT contain the credential",
      all(PLANTED not in (r.detail or "") for r in _rows),
      [(r.detail or "")[:60] for r in _rows][:2])

print("\n== the secrets list: bulk, in clear, and still gated ==")
# A deliberate widening of the single reveal above. What has to
# survive the widening is the ROLE and the AUDIT -- if either of
# those is only enforced on the one-at-a-time endpoint then this
# list is a way around both.


async def _plant_origin():
    """Give the planted secret an origin, as a sweep would."""
    async with SessionLocal() as s:
        row = (await s.execute(select(_FS).where(
            _FS.vuln_id == _vid))).scalar_one()
        row.asset_url = "https://asset.example/static/app.js"
        row.path = "src/aws.ts"
        row.line = 118
        await s.commit()


asyncio.run(_plant_origin())

st, rows = call("/api/secrets?project=ASSET", token=admin)
_mine = [r for r in (rows or []) if r.get("vuln_id") == _vid]
check("the list returns the value in clear",
      st == 200 and len(_mine) == 1 and _mine[0]["secret"] == PLANTED, st)
check("...with the URL it came from",
      _mine and _mine[0]["asset_url"] == "https://asset.example/static/app.js",
      _mine and _mine[0].get("asset_url"))
check("...the file inside it",
      _mine and _mine[0]["path"] == "src/aws.ts" and _mine[0]["line"] == 118,
      _mine and (_mine[0].get("path"), _mine[0].get("line")))
check("...and the target it belongs to",
      _mine and _mine[0]["host"] == "127.0.0.1", _mine and _mine[0].get("host"))

# The finding with no stored credential must not appear as a row
# with an empty value -- there is nothing to show and a blank cell
# reads as "the secret is empty string".
check("a finding with no stored credential is not in the list",
      all(r.get("vuln_id") != _bare_id for r in (rows or [])),
      [r.get("vuln_id") for r in (rows or [])][:5])

# Origin is nullable, and null means NOT RECORDED. A row that
# never had one must come back with null rather than "" -- the UI
# tells those apart and says so.
async def _plant_no_origin():
    async with SessionLocal() as s:
        pr = (await s.execute(select(Project).where(
            Project.code == "ASSET"))).scalar_one()
        t = (await s.execute(select(Target).where(
            Target.project_id == pr.id))).scalars().first()
        v = Vuln(target_id=t.id, title="secret from before origins",
                 severity="low", status="open",
                 external_id="detect-secrets:noorigin")
        s.add(v)
        await s.flush()
        s.add(_FS(vuln_id=v.id, secret=PLANTED + "-2", detector="Base64"))
        await s.commit()
        return v.id


_noorigin = asyncio.run(_plant_no_origin())
st, rows2 = call("/api/secrets?project=ASSET", token=admin)
_no = [r for r in (rows2 or []) if r.get("vuln_id") == _noorigin]
check("an unrecorded origin is null, not empty string",
      len(_no) == 1 and _no[0]["asset_url"] is None, _no and _no[0].get("asset_url"))

# The role gate. Written so that REMOVING the gate fails the test:
# the readonly account can see the finding (so the 200 and the
# visibility filter are not what is being measured) and must still
# get no values back.
call("/api/users", "POST",
     {"username": "sec-viewer", "password": "sec-viewer-pass-1"}, token=admin)
_st, _r = call("/api/auth/login", "POST",
               {"username": "sec-viewer", "password": "sec-viewer-pass-1"})
_viewer = _r["access_token"]
call("/api/projects/ASSET/acl", "POST",
     {"username": "sec-viewer", "role": "readonly"}, token=admin)

st, seen = call("/api/vulns?project=ASSET", token=_viewer)
check("readonly can see the findings themselves",
      st == 200 and (seen or {}).get("total", 0) > 0,
      f"{st} {(seen or {}).get('total')}")

# Same guard as the reveal: the source endpoint returns a file
# CONTAINING the credential, so a weaker check there would make the
# stricter one next door decorative.
st, _ = call(f"/api/vulns/{_src_id}/secret/source", token=_viewer)
check("a readonly account is refused the source", st == 403, st)

st, ro = call("/api/secrets?project=ASSET", token=_viewer)
check("readonly gets NO credentials from the list",
      st == 200 and ro == [], f"{st} {len(ro or [])} row(s)")
check("...and the value is nowhere in that response",
      PLANTED not in json.dumps(ro), "value leaked to readonly")

call("/api/projects/ASSET/acl", "POST",
     {"username": "sec-viewer", "role": "user"}, token=admin)
st, up = call("/api/secrets?project=ASSET", token=_viewer)
check("...while the user role does get them",
      st == 200 and any(r["secret"] == PLANTED for r in (up or [])),
      f"{st} {len(up or [])} row(s)")


# Audit: one entry per bulk read, naming the count, never the value.
async def _list_audit():
    from app.models import AuditEvent
    async with SessionLocal() as s:
        return (await s.execute(select(AuditEvent).where(
            AuditEvent.action == "finding.secret.list"))).scalars().all()


_lrows = asyncio.run(_list_audit())
check("listing is written to the audit log", len(_lrows) >= 1, len(_lrows))
check("...naming who did it",
      {"root", "sec-viewer"} & {r.username for r in _lrows},
      [r.username for r in _lrows][:4])
check("...and the log does NOT contain any credential",
      all(PLANTED not in (r.detail or "") for r in _lrows),
      [(r.detail or "")[:60] for r in _lrows][:2])
check("a refused read writes no audit entry",
      not any(r.username == "sec-viewer" and "0 credential" in (r.detail or "")
              for r in _lrows),
      "an empty readonly result was logged as a read")

print("\n== triage: what a person concluded ==")
# Separate from `status`, which is what has been DONE. A confirmed
# issue can be open and a false positive can be closed; one column
# could not say both.
st, listing = call("/api/vulns?project=ASSET", token=admin)
_first = ((listing or {}).get("items") or [{}])[0]
check("a finding starts as needs_investigating",
      _first.get("triage") == "needs_investigating", _first.get("triage"))

st, r = call(f"/api/vulns/{_vid}/triage", "PATCH",
             {"triage": "false_positive"}, token=admin)
check("one finding can be marked", st == 200 and (r or {}).get("changed") == 1,
      f"{st} {r}")
st, one = call(f"/api/vulns/{_vid}", token=admin)
check("...and it sticks", (one or {}).get("triage") == "false_positive",
      (one or {}).get("triage"))

st, _ = call(f"/api/vulns/{_vid}/triage", "PATCH",
             {"triage": "probably-fine"}, token=admin)
check("an unknown verdict is refused", st == 422, st)

_ids = [v["id"] for v in ((listing or {}).get("items") or [])][:5]
st, r = call("/api/vulns/triage", "POST",
             {"ids": _ids, "triage": "true_positive"}, token=admin)
check("a selection can be marked in one request",
      st == 200 and (r or {}).get("changed", 0) >= 1, f"{st} {r}")
st, _l2 = call("/api/vulns?project=ASSET", token=admin)
_marked = [v for v in ((_l2 or {}).get("items") or []) if v["id"] in _ids]
check("...and every one of them took the verdict",
      all(v.get("triage") == "true_positive" for v in _marked),
      [v.get("triage") for v in _marked][:5])

st, r = call("/api/vulns/triage", "POST",
             {"ids": [999999], "triage": "true_positive"}, token=admin)
# Refused rows are NAMED. A bulk action that silently skipped what
# the caller cannot write to would look like it had worked.
check("a finding that cannot be written is named back, not skipped",
      (r or {}).get("changed") == 0 and (r or {}).get("refused") == [999999],
      r)
st, _ = call("/api/vulns/triage", "POST", {"ids": [], "triage": "true_positive"},
             token=admin)
check("an empty selection is refused rather than a no-op", st == 422, st)

print("\n== cloud resources named in a bundle ==")
# A bundle that talks to a bucket names an asset nothing else
# finds: it is on the provider's address space so no CIDR scan
# reaches it, and no page links to it so no crawl does either.

from app.assetlinks import cloud_resources  # noqa: E402

_BODY = """
var a='https://acme-assets.s3.eu-west-1.amazonaws.com/img/logo.png';
var b="https://s3.amazonaws.com/acme-legacy/report.pdf";
var c='https://a1b2c3.execute-api.us-east-1.amazonaws.com/prod/pay';
var d='https://acmestore.blob.core.windows.net/public/t.txt';
var e='https://acme-kv.vault.azure.net/secrets/x';
var f='https://acme-public.storage.googleapis.com/a.js';
var g='https://us-central1-acme.cloudfunctions.net/submit';
var noise1='https://my-bucket.s3.amazonaws.com/x';
var noise2='https://example.appspot.com';
"""
_got = {v: p for p, v in cloud_resources(_BODY)}

check("a virtual-hosted bucket is found",
      _got.get("acme-assets.s3.eu-west-1.amazonaws.com") == "aws", _got)
# Path-style names the same kind of thing and older SDKs still
# emit it. Rewritten to the hostname so one bucket is one target
# however the code addressed it.
check("a path-style bucket is rewritten to its hostname",
      _got.get("acme-legacy.s3.amazonaws.com") == "aws", _got)
# The bug this catches: `\b` is satisfied by the dot in
# `acme-assets.s3...`, so the path-style pattern matched INSIDE a
# virtual-hosted URL and read the first path segment as a bucket.
check("...and is not read out of a virtual-hosted URL's path",
      "img.s3.eu-west-1.amazonaws.com" not in _got, sorted(_got))
check("an API Gateway stage is found",
      _got.get("a1b2c3.execute-api.us-east-1.amazonaws.com") == "aws", _got)
check("azure blob storage is found and attributed",
      _got.get("acmestore.blob.core.windows.net") == "azure", _got)
check("an azure key vault is found",
      _got.get("acme-kv.vault.azure.net") == "azure", _got)
check("a gcs bucket is found and attributed",
      _got.get("acme-public.storage.googleapis.com") == "gcp", _got)
check("a cloud function is found",
      _got.get("us-central1-acme.cloudfunctions.net") == "gcp", _got)
check("an SDK's own sample bucket is not reported",
      "my-bucket.s3.amazonaws.com" not in _got
      and "example.appspot.com" not in _got, sorted(_got))
check("a file naming no cloud resource yields nothing",
      cloud_resources("var x=1; fetch('/api/v2/accounts');") == [])

# The scope gate. A bundle references a great deal of cloud that
# belongs to somebody else -- a CDN, an analytics vendor, a font
# host -- and auto-creating targets for those would put a third
# party's infrastructure into an engagement.
from app.assetwork import _record_cloud  # noqa: E402
from app.scopegate import index_for  # noqa: E402

# A REAL asset and a REAL file, not a stub with a body on it. The
# file is the whole provenance now -- a bucket's only account of
# itself is the bundle that named it and the pages that load that
# bundle -- and a stub cannot exercise any of that.
CLOUD_ASSET = f"{ORIGIN}/static/cloud.bundle.js"
CLOUD_PAGE = f"{ORIGIN}/index.html"
CLOUD_PAGE_2 = f"{ORIGIN}/checkout.html"
CLOUD_BODY = ("var a='https://acme-assets.s3.eu-west-1.amazonaws.com/x';"
              "var b='https://notours.blob.core.windows.net/y';")


async def _cloud_file(s, pr_id):
    """The asset carrying the bundle, its file, and a second page."""
    a = (await s.execute(select(WebAsset).where(
        WebAsset.project_id == pr_id,
        WebAsset.url == CLOUD_ASSET))).scalar_one_or_none()
    if a is None:
        # Stamped fetched and scanned so the sweeps above do not pick
        # it up and change counts those assertions already made.
        a = WebAsset(project_id=pr_id, target_id=None, url=CLOUD_ASSET,
                     host="127.0.0.1", kind="script", first_page=CLOUD_PAGE,
                     seen_on=2, fetched_at=_aw.assetfetch.now(),
                     scanned_at=_aw.assetfetch.now())
        s.add(a)
        await s.flush()
        # A SECOND page loading the same bundle. One asset is loaded
        # by many pages, and "what site did this come from" has that
        # many answers.
        s.add(WebAssetRef(asset_id=a.id, target_id=None,
                          page_url=CLOUD_PAGE_2))
    f = (await s.execute(select(WebAssetFile).where(
        WebAssetFile.asset_id == a.id))).scalars().first()
    if f is None:
        f = WebAssetFile(asset_id=a.id, project_id=pr_id, origin="raw",
                         path="cloud.bundle.js", body=CLOUD_BODY,
                         scanned_at=_aw.assetfetch.now())
        s.add(f)
        await s.flush()
    return f


async def _cloud_into_targets():
    async with SessionLocal() as s:
        pr = (await s.execute(select(Project).where(
            Project.code == "ASSET"))).scalar_one()
        idx = await index_for(s, pr.id)
        f = await _cloud_file(s, pr.id)
        added, refused = await _record_cloud(s, pr.id, idx, f)
        await s.commit()
        rows = {t.host: t for t in (await s.execute(select(Target).where(
            Target.project_id == pr.id))).scalars().all()}
        return added, refused, rows


# Nothing cloud-shaped is in ASSET's scope yet, so BOTH are refused.
_added, _refused, _rows = asyncio.run(_cloud_into_targets())
check("with neither bucket in scope, no target is created", _added == 0, _added)
check("...and the refusals are counted rather than silent", _refused == 2,
      _refused)
check("...so an out-of-scope bucket really is absent",
      "acme-assets.s3.eu-west-1.amazonaws.com" not in _rows, sorted(_rows))

# Put one of them in scope and only that one appears.
st, _ = call("/api/projects/ASSET/scope", "POST",
             {"lines": ["127.0.0.1", "acme-assets.s3.eu-west-1.amazonaws.com"]},
             token=admin)
_added, _refused, _rows = asyncio.run(_cloud_into_targets())
check("an in-scope bucket becomes a target", _added == 1, _added)
check("...named by its hostname",
      "acme-assets.s3.eu-west-1.amazonaws.com" in _rows, sorted(_rows))
_t = _rows.get("acme-assets.s3.eu-west-1.amazonaws.com")
check("...recorded as a cloud resource, not a machine",
      _t is not None and _t.kind == "cloud", _t and _t.kind)
check("...carrying which cloud it is",
      _t is not None and _t.provider == "aws", _t and _t.provider)
check("...and not probed, which is not the same as not responding",
      _t is not None and _t.alive is None, _t and _t.alive)
check("the out-of-scope one is still refused", _refused == 1, _refused)

# Re-running must not fork a second row: the sweep sees the same
# bundle on every pass.
_added2, _, _rows2 = asyncio.run(_cloud_into_targets())
check("a second sweep adds nothing", _added2 == 0, _added2)
check("...and leaves one row for the bucket",
      len([h for h in _rows2 if h.startswith("acme-assets.")]) == 1,
      sorted(_rows2))

print("\n== and WHERE the bucket came from ==")
# The point of the whole thing. A bucket is in no CIDR, nothing links
# to it and no port scan meets it: the bundle that named it is the
# only reason it is in the project at all, and a row that cannot say
# so leaves an operator with a hostname and no account of it.


async def _cloud_origins():
    async with SessionLocal() as s:
        t = (await s.execute(select(Target).where(
            Target.host == "acme-assets.s3.eu-west-1.amazonaws.com"))
             ).scalar_one()
        rows = (await s.execute(select(TargetOrigin).where(
            TargetOrigin.target_id == t.id))).scalars().all()
        return t, rows


_t2, _origins = asyncio.run(_cloud_origins())
check("the discovery is recorded, not thrown away", len(_origins) == 1,
      len(_origins))
_o = _origins[0] if _origins else None
check("...naming the bundle it was read out of",
      _o is not None and _o.asset_url == CLOUD_ASSET, _o and _o.asset_url)
check("...and the file inside it, not just the bundle",
      _o is not None and _o.file_path == "cloud.bundle.js",
      _o and _o.file_path)
check("...and the page that loads the bundle",
      _o is not None and _o.page_url == CLOUD_PAGE, _o and _o.page_url)
check("...tied back to the asset and file rows it came from",
      _o is not None and _o.asset_id is not None and _o.file_id is not None,
      _o and (_o.asset_id, _o.file_id))
# Three sweeps have now read the same bundle. The sweep sees it on
# every pass, so without the uniqueness key this table would grow
# without bound while saying nothing new.
check("re-reading the same bundle does not file the discovery again",
      len(_origins) == 1, len(_origins))

# The API, which is what the Targets page actually reads.
st, r = call("/api/targets/origins?project=ASSET", token=admin)
check("the origins endpoint answers", st == 200, st)
_got = (r or {}).get(str(_t2.id)) or []
check("...with the bucket's provenance keyed by target id",
      len(_got) == 1, r)
_first = _got[0] if _got else {}
check("...carrying the site, derived from the page",
      _first.get("site") == "127.0.0.1", _first.get("site"))
# `first_page` is one page. Every page loading the asset is in
# `web_asset_refs`, and a page crawled later is genuinely another
# site this resource was found on -- so the list is read live.
check("...and EVERY page that loads the bundle, not just the first",
      sorted(_first.get("pages") or []) == sorted([CLOUD_PAGE, CLOUD_PAGE_2]),
      _first.get("pages"))
check("...with the full count beside the capped list",
      _first.get("pages_total") == 2, _first.get("pages_total"))
check("...said to have come from an asset, rather than left unexplained",
      _first.get("source") == "asset", _first.get("source"))

# The distinction the whole feature turns on. 127.0.0.1 was typed in
# by hand at the top of this suite; nothing recorded where it came
# from, and that is NOT the same claim as it having come from
# nowhere. The endpoint leaves it out and the UI says "not recorded".
_hand = (r or {}).get(str(_t2.id - 10**9))   # an id that cannot exist
check("a target nothing recorded an origin for is simply absent",
      _hand is None, _hand)
st, r = call("/api/targets/ASSET/127.0.0.1/detail", token=admin)
check("the detail of a hand-made target carries no origin",
      st == 200 and (r or {}).get("origins") == [], (r or {}).get("origins"))
st, r = call(
    "/api/targets/ASSET/acme-assets.s3.eu-west-1.amazonaws.com/detail",
    token=admin)
check("...while the bucket's detail carries the bundle it came from",
      st == 200 and len((r or {}).get("origins") or []) == 1, st)

print("\n== a bot filter's refusal is not the application's answer ==")
# The same cases as TestBlockedNeedsAProductAndAStatus in
# ghost/internal/browserfetch/blocked_test.go, on purpose. The Ghost
# meets this on the client's estate and the server meets it fetching
# assets; two copies of a table that must agree should be tested
# against the same vectors, as the tunnel codec is.
from app import blocked as _bl  # noqa: E402

_CF_HDR = {"CF-Ray": "8a1b2c3d4e5f6789-LHR"}
for _name, _st, _h, _body, _want in [
    # The whole point. A 403 on /admin is the application telling a
    # tester where the boundary is, and calling it a WAF block would
    # hide a real access-control finding behind a plausible excuse.
    ("a bare 403 is the server's answer, not a block",
     403, None, "<h1>Forbidden</h1>", None),
    ("a 200 is never a block however it is branded",
     200, _CF_HDR, "ray id: abc", None),
    ("a 401 is authentication, not interdiction",
     401, _CF_HDR, "attention required! | cloudflare", None),
    ("a cf-ray header on a 403 is Cloudflare", 403, _CF_HDR, "", "Cloudflare"),
    ("...and on a 503, the mode that looks like downtime",
     503, _CF_HDR, "", "Cloudflare"),
    ("...and on a 429", 429, _CF_HDR, "", "Cloudflare"),
    ("header case does not decide it, because three libraries disagree",
     403, {"cf-RAY": "x"}, "", "Cloudflare"),
    ("Cloudflare's own wording counts without the header",
     403, None, "<title>Attention Required! | Cloudflare</title>",
     "Cloudflare"),
    # NOT a block. `Server: cloudflare` is on everything Cloudflare
    # proxies, so a legitimate 403 from the origin behind it carries
    # the header too -- and excusing a real access-control boundary
    # as "the CDN blocked us" is worse than inventing a finding.
    # cf-ray is what means Cloudflare itself decided.
    ("Server: cloudflare alone is the proxy, not a decision",
     403, {"Server": "cloudflare"}, "", None),
    ("...while AkamaiGHost IS, because Akamai passes the origin's through",
     403, {"Server": "AkamaiGHost"}, "", "Akamai"),
    # The products the operator named, plus the rest of the estate's
    # likely front ends.
    ("Fastly's Next-Gen WAF by its agent header",
     403, {"X-SigSci-RequestID": "abc"}, "", "Fastly (Signal Sciences)"),
    # Fastly's own block page is a customer-defined synthetic, so
    # there is nothing in the body to match and a Fastly-fronted 403
    # without the agent header is not claimed.
    ("a Fastly-fronted 403 with no decision header is not claimed",
     403, {"X-Served-By": "cache-lhr-x", "X-Timer": "S123"},
     "<h1>Forbidden</h1>", None),
    ("a CloudFront routing header on a 403 is not a block either",
     403, {"X-Cache": "Error from cloudfront", "X-Amz-Cf-Id": "abc"},
     "<h1>Forbidden</h1>", None),
    ("AWS WAF when it names its own action",
     403, {"x-amzn-waf-action": "block"}, "", "AWS WAF"),
    ("Azure's WAF, which reads like an outage", 403, None,
     "<h2>Our services aren't available right now</h2>", "Azure WAF"),
    ("ModSecurity", 406, None, "This error was generated by Mod_Security",
     "ModSecurity"),
    ("Fortinet", 403, None, "<title>Web Page Blocked</title>",
     "Fortinet FortiWeb"),
    ("Imperva by its incident id", 403, None,
     "Incapsula incident ID: 123-456", "Imperva/Incapsula"),
    ("Akamai by its reference", 403, None, "Reference #18.1a2b3c4d",
     "Akamai"),
    ("F5 by its rejection wording", 403, None,
     "The requested URL was rejected. Support ID is: 99", "F5 BIG-IP ASM"),
    ("CloudFront's WAF sentence, whole", 403, None,
     "The request could not be satisfied. Request blocked. We can't",
     "AWS WAF"),
    # The near miss that matters: every CloudFront error page says
    # this, including a legitimate origin 403.
    ("a plain CloudFront error page is NOT a WAF block", 403, None,
     "<H2>The request could not be satisfied.</H2>Bad request."
     "<PRE>Generated by cloudfront (CloudFront)</PRE>", None),
]:
    check(_name, _bl.blocked_by(_st, _h, _body) == _want,
          _bl.blocked_by(_st, _h, _body))

# Counted, not only described. The prose lands in one asset's
# `fetch_error`; the count is what makes "nine assets refused by
# Cloudflare" visible as one fact rather than nine unrelated
# failures nobody reads together.
_sw = _aw.Swept()
check("a sweep can report what refused it", _sw.blocked == 0 and
      _sw.blocked_by == {}, (_sw.blocked, _sw.blocked_by))
check("...and the count is separate from `failed`, which also counts it",
      "blocked" in _aw.Swept.__dataclass_fields__
      and "failed" in _aw.Swept.__dataclass_fields__)

# The sentence that replaces `HTTP 403`. An operator reading a
# fetch_error has to be able to tell a refusal from an answer.
_d = _bl.describe(403, "Cloudflare")
check("the description names the product", "Cloudflare" in _d, _d)
check("...and says it was not the application",
      "not by the application" in _d, _d)
check("...and does not claim a retry it cannot make",
      "cannot" in _d, _d)

print("\n== the scanners read the pages too, not only what pages pull in ==")
# The asset sweep reads bundles. It never read the page itself, and
# an API key inlined in a <script> block is the same finding as the
# same string in a bundle.

# --- which responses are worth reading, decided without a database
check("an .html URL picks the html rules",
      _aw.page_ext("https://acme.example/index.html", None) == ".html")
check("...and .htm is the same thing",
      _aw.page_ext("https://acme.example/a.htm", None) == ".html")
check("the URL beats a wrong content type, because /app.js is javascript",
      _aw.page_ext("https://acme.example/app.js", "text/html") == ".js")
check("a declared type is used when the URL has no extension",
      _aw.page_ext("https://acme.example/api/session",
                   "application/json; charset=utf-8") == ".json")
# 96% of the eligible responses on a live engagement declared no
# content type at all -- 48,990 of 51,059 -- so this branch is not
# an edge case, it is the common path, and what it returns is what
# the sweep actually does. Returning `.txt` sent nearly every page
# to the `generic` ruleset, whose `gitleaks.generic-api-key` rule
# then supplied 54% of everything the first 300 pages produced.
check("a route with neither is read as what its BODY looks like",
      _aw.page_ext("https://acme.example/api/session", None,
                   '{"session": "x"}') == ".json")
check("...markup is html, which is the ruleset a page wants",
      _aw.page_ext("https://acme.example/login", None,
                   "<!DOCTYPE html><html>") == ".html")
check("...including a fragment, which starts with a tag and no doctype",
      _aw.page_ext("https://acme.example/widget", None,
                   "<div id=x>hello</div>") == ".html")
check("...an xml declaration is xml",
      _aw.page_ext("https://acme.example/feed", None,
                   "<?xml version='1.0'?><rss/>") == ".xml")
# NOT read. `.txt` selects the `generic` ruleset, whose
# `gitleaks.generic-api-key` rule supplied 54% of everything the
# first 300 pages of the live sweep produced. A classifier that
# always answers is one whose answer means nothing -- "could not
# determine" is its own answer here too, and it means skip.
check("...and text we cannot name is NOT thrown at a catch-all ruleset",
      _aw.page_ext("https://acme.example/robots", None,
                   "User-agent: *") is None)
check("javascript served at a web address gets the javascript rules",
      _aw.page_ext("https://acme.example/app", None,
                   "/* @license */ (function(){})()") == ".js")
check("...and a stylesheet gets css",
      _aw.page_ext("https://acme.example/s", None,
                   ".sec-container{padding-top:1px}") == ".css")
# Reading a binary as text is how an entropy detector finds a
# credential in a compression stream. 131 PDFs were in the corpus.
check("a PDF is not read at all",
      _aw.page_ext("https://acme.example/doc", None, "%PDF-1.7 %abc") is None)
check("...nor a PNG", _aw.page_ext("https://acme.example/i", None,
                                   "\x89PNG\r\n") is None)
# Both cost real pages on the live corpus: 148 behind a BOM, 150
# behind a chunked-transfer size line the capture never stripped.
check("HTML behind a byte-order mark is still HTML",
      _aw.page_ext("https://acme.example/b", None,
                   "\ufeff<!DOCTYPE html PUBLIC") == ".html")
check("...and HTML behind a chunk-size line is too",
      _aw.page_ext("https://acme.example/c", None,
                   "14e27\r\n<!DOCTYPE html>") == ".html")
check("nothing to go on at all is not read",
      _aw.page_ext("https://acme.example/empty", None, "") is None)
# A declared type still wins over the body: the server saying what
# it sent is better evidence than our guess at it.
check("a declared type beats the sniff",
      _aw.page_ext("https://acme.example/x", "application/json",
                   "<html>") == ".json")
# Guessing `.txt` at an unknown type is how a font ends up in front
# of a secret scanner, which finds entropy in all of them.
check("an image is NOT read",
      _aw.page_ext("https://acme.example/logo.png", "image/png") is None)
check("...nor a font", _aw.page_ext("https://acme.example/f.woff2",
                                    "font/woff2") is None)

# --- the header block is not the page
_raw = ("HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Set-Cookie: SESSION=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; HttpOnly\r\n"
        "\r\n"
        "<html><body>hello</body></html>")
check("a raw exchange is cut at the header block",
      _aw.response_body(_raw) == "<html><body>hello</body></html>",
      _aw.response_body(_raw)[:60])
# The reason it is cut: every authenticated response in the estate
# carries the client's own session cookie, and reporting one as a
# found credential on every page buries the key that is actually
# inlined in the markup.
check("...so the session cookie is not handed to a secret scanner",
      "SESSION=" not in _aw.response_body(_raw))
check("a body with no header block is left whole",
      _aw.response_body("<html>\n\nstill the body</html>")
      == "<html>\n\nstill the body</html>")
check("a bare-LF header block is cut too",
      _aw.response_body("HTTP/1.1 200 OK\nX: y\n\nbody") == "body")
check("headers and nothing else is an empty body, not an error",
      _aw.response_body("HTTP/1.1 204 No Content\r\n\r\n") == "")
check("nothing at all is nothing", _aw.response_body("") == "")

# --- end to end over the real table
async def _scan_pages():
    async with SessionLocal() as s:
        t = (await s.execute(select(Target).where(
            Target.project_id == pid))).scalars().first()
        rows = [
            # A 2xx page with a credential inlined in it.
            #
            # Deliberately NOT AWS's own documented example access
            # key, which is the obvious thing to reach for here: it
            # matches the access-key pattern in
            # scripts/check-secrets.sh, which fails the build on a
            # public repository -- and is right to, because a
            # pattern that carves out "the example one" is a pattern
            # people learn to argue with. This fires detect-secrets'
            # Secret Keyword detector instead: a real detector path,
            # and a string that is nobody's credential in any shape.
            WebAddress(
                target_id=t.id, url="https://acme.example/inline.html",
                url_hash=hashlib.sha256(b"inline").hexdigest(),
                exchange_hash=hashlib.sha256(b"inline-x").hexdigest(),
                scheme="https", path="/inline.html", status_code=200,
                content_type="text/html",
                response="HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                         "\r\n<html><script>var apiKey = "
                         '"a3f1c9e7b2d84f60a1c5e8b3d7f20946";'
                         "</script></html>"),
            # A 404 carrying the same string. The server's error
            # template is identical across a thousand URLs, so
            # reading it files one finding a thousand times.
            WebAddress(
                target_id=t.id, url="https://acme.example/missing.html",
                url_hash=hashlib.sha256(b"missing").hexdigest(),
                exchange_hash=hashlib.sha256(b"missing-x").hexdigest(),
                scheme="https", path="/missing.html", status_code=404,
                content_type="text/html",
                response='<html><script>var apiKey = '
                         '"a3f1c9e7b2d84f60a1c5e8b3d7f20946";'
                         "</script></html>"),
            # Not text. Marked read, never handed to a scanner.
            WebAddress(
                target_id=t.id, url="https://acme.example/logo.png",
                url_hash=hashlib.sha256(b"logo").hexdigest(),
                exchange_hash=hashlib.sha256(b"logo-x").hexdigest(),
                scheme="https", path="/logo.png", status_code=200,
                content_type="image/png", response="\x89PNG binary"),
        ]
        for r in rows:
            s.add(r)
        await s.commit()
        ids = [r.id for r in rows]

        owed_before = (await _aw.pending(s, pid))["unscanned_pages"]
        sw = await _aw.scan_pages(s, pid, limit=50)
        owed_after = (await _aw.pending(s, pid))["unscanned_pages"]

        back = {r.id: r for r in (await s.execute(select(WebAddress).where(
            WebAddress.id.in_(ids)))).scalars().all()}
        vulns = (await s.execute(select(Vuln).where(
            Vuln.target_id == t.id))).scalars().all()
        return sw, owed_before, owed_after, back, ids, vulns

_sw, _before, _after, _back, _ids, _vulns = asyncio.run(_scan_pages())

check("a 2xx body is queued to be read", _before >= 2, _before)
check("...and a 404 is not — only 2xx", _back[_ids[1]].scanned_at is None,
      _back[_ids[1]].scanned_at)
check("the queue drains", _after < _before, f"{_before} -> {_after}")
check("the 2xx page is marked read", _back[_ids[0]].scanned_at is not None)
check("an image is marked read without being scanned",
      _back[_ids[2]].scanned_at is not None)

if have.get("detect-secrets"):
    _hit = [v for v in _vulns
            if "inline.html" in (v.description or "")]
    check("a key inlined in a page becomes a finding", len(_hit) >= 1,
          [v.title for v in _vulns][:4])
    check("...and the finding names the page it came from",
          any("https://acme.example/inline.html" in (v.description or "")
              for v in _hit), [v.description[:60] for v in _hit][:2])
    # The whole reason the 404 is excluded.
    check("the same string in a 404 is NOT a second finding",
          not any("missing.html" in (v.description or "") for v in _vulns))
else:
    check("skipped: no secret scanner present in this suite", True,
          "(detect-secrets lives in the image)")

# A second pass must not re-read what it already read, or the
# backlog never drains and every finding is written twice.
async def _again():
    async with SessionLocal() as s:
        return await _aw.scan_pages(s, pid, limit=50)

check("a second pass reads nothing again", asyncio.run(_again()).scanned == 0)

print("\n== entropy is not a finding on a page ==")
# `assetscan` already says why for a bundle -- "a high-entropy
# string in minified JavaScript is very often a hash" -- and on
# markup it is worse: SRI digests, CSP nonces, inline data URIs and
# analytics ids are all high-entropy and none is a credential.
# Measured on the first 300 pages of the live sweep, 39% of
# everything raised was one of these two detectors.
check("the suppressed detectors are the entropy ones, by name",
      set(_asx._ENTROPY_TYPES) ==
      {"Base64 High Entropy String", "Hex High Entropy String"},
      _asx._ENTROPY_TYPES)
check("a sweep can say how many it dropped",
      _aw.Swept().entropy_skipped == 0)
# The distinction that keeps this from being censorship: dropping
# "it looked random" is not dropping "this is a Google API key",
# and the second is the reason to read pages at all.
_named = _asx.scan_detect_secrets(
    "page.html",
    '<html><script>var apiKey = "a3f1c9e7b2d84f60a1c5e8b3d7f20946";'
    "</script></html>")
check("a named-shape secret still fires",
      any(f.rule not in _asx._ENTROPY_TYPES for f in _named),
      [f.rule for f in _named])


print("\n== the libraries a page ships, against the CVE corpus ==")
# `web_assets` has carried `name` and `version` since library
# detection landed, and nothing ever asked the CVE corpus about
# them -- `leads_for_service` was only ever called for PORTS. A
# version read out of a file the client's own page serves is better
# evidence than a service banner, which is a guess about software
# nobody can see.

check("the upsert key is stable, so a re-run amends",
      _aw.library_external_id("jQuery", "3.6.0", "CVE-2020-11022")
      == _aw.library_external_id("jquery", "3.6.0", "CVE-2020-11022"))
check("...and distinguishes versions of the same library",
      _aw.library_external_id("jQuery", "3.6.0", "CVE-1")
      != _aw.library_external_id("jQuery", "1.12.4", "CVE-1"))

_body = _aw._library_body(
    "jQuery", "3.6.0",
    {"cve": "CVE-2020-11022", "summary": "XSS in jQuery.",
     "kev": True, "kev_added": "2022-05-03",
     "epss": 0.0423, "epss_percentile": 0.91},
    "https://acme.example/js/jquery.min.js")
check("the finding names the library, the version and the CVE",
      all(x in _body for x in ("jQuery 3.6.0", "CVE-2020-11022")), _body[:70])
check("...and says where it is served from",
      "https://acme.example/js/jquery.min.js" in _body)
# The two facts that change what somebody does about it this
# morning, now that both are knowable.
check("...and that CISA has seen it used", "Known Exploited" in _body)
check("...and how likely it is to be used next", "EPSS 0.0423" in _body)

# The caveat is not decoration. A backported fix leaves the version
# string alone, which is the single most common way a version-based
# finding is wrong.
check("it says plainly that this is a lead, not a confirmed finding",
      "LEAD, not a confirmed vulnerability" in _body, _body[-220:])
check("...and names the reason it might be wrong",
      "backported fix" in _body)

_quiet = _aw._library_body("jQuery", "3.6.0",
                           {"cve": "CVE-1", "summary": "x"},
                           "https://acme.example/a.js")
check("a CVE with no KEV or EPSS data says neither",
      "Known Exploited" not in _quiet and "EPSS" not in _quiet, _quiet[:60])

print("\n== endpoints found in code become known addresses ==")
# `assetlinks.extract` has pulled API paths out of bundles since
# endpoint extraction landed, and NOTHING read the table. The paths
# were recorded and never became part of the estate.

# --- resolving one endpoint to an absolute URL
check("a path resolves against the page that loaded the bundle",
      _aw.endpoint_url("/api/v2/users", "path", "https://acme.example/app")
      == "https://acme.example/api/v2/users")
check("an absolute url is taken as it is",
      _aw.endpoint_url("https://api.acme.example/x", "url", None)
      == "https://api.acme.example/x")
# A wrong URL is worse than a missing one: relative-to-the-bundle
# cannot be resolved without knowing where the bundle lived.
check("a bundle-relative path is dropped, not guessed at",
      _aw.endpoint_url("api/v2", "path", "https://acme.example/app") is None)
check("a path with no page is dropped",
      _aw.endpoint_url("/x", "path", None) is None)
# These are the shapes that would turn an extracted string into a
# request somewhere nobody authorised.
check("a javascript: url is not an endpoint",
      _aw.endpoint_url("javascript:alert(1)", "url", "https://acme.example/")
      is None)
check("a protocol-relative url is not followed to another host",
      _aw.endpoint_url("//evil.example/x", "url", "https://acme.example/")
      is None)
check("a data: url is not an endpoint",
      _aw.endpoint_url("data:text/html,x", "url", "https://acme.example/")
      is None)
check("an over-long blob from a minified file is not a route",
      _aw.endpoint_url("/" + "a" * 600, "path", "https://acme.example/")
      is None)

# --- the invariant that matters
# `crawl_seeds` keeps a one-way edge -- gobuster feeds katana, a
# crawl never feeds itself -- because a crawl producing more
# crawling took one project from 1,109 queued tasks to 97,959 in an
# hour. These endpoints come OUT of files found BY a crawl, so a row
# written here must never be readable as a crawl seed.

# --- scope, which is the other half
async def _endpoints_in_scope():
    async with SessionLocal() as s:
        t = (await s.execute(select(Target).where(
            Target.project_id == pid))).scalars().first()
        a = (await s.execute(select(WebAsset).where(
            WebAsset.project_id == pid))).scalars().first()
        if a is None or t is None:
            return None
        a.first_page = f"https://{t.host}/app"
        for kind, value in (("path", "/api/v2/users"),
                            ("url", "https://cdn.vendor.example/lib.js"),
                            ("url", "https://analytics.vendor.example/t")):
            s.add(WebAssetEndpoint(project_id=pid, asset_id=a.id,
                                   kind=kind, value=value))
        await s.commit()
        return await _aw.record_endpoint_urls(s, pid)

from app.models import WebAssetEndpoint  # noqa: E402

_res = asyncio.run(_endpoints_in_scope())
if _res is not None:
    check("a path on an in-scope target becomes an address",
          _res["added"] >= 1, _res)
    # The common case, and the feature: most of what a bundle names
    # belongs to somebody else.
    check("...while a vendor's CDN and analytics host are refused",
          _res["refused"] >= 2, _res)
    check("the counts are reported rather than inferred",
          set(_res) == {"considered", "added", "refused", "unresolvable"},
          sorted(_res))

    async def _again2():
        async with SessionLocal() as s:
            return await _aw.record_endpoint_urls(s, pid)

    check("running it twice adds nothing the second time",
          asyncio.run(_again2())["added"] == 0)

    # The invariant, checked against the ROWS and against
    # `crawl_seeds` itself rather than against the source text. A
    # crawl that produces more crawling took one project from 1,109
    # queued tasks to 97,959 in an hour, and these endpoints come OUT
    # of files found BY a crawl -- so a row written here must not be
    # readable as a seed.
    async def _seed_check():
        async with SessionLocal() as s:
            rows = (await s.execute(select(WebAddress).where(
                WebAddress.sources == "assets"))).scalars().all()
            from app.webtargets import crawl_seeds
            seeds = await crawl_seeds(s, pid)
            return ([r.url for r in rows],
                    {u for urls in seeds.values() for u in urls})

    _made, _seeded = asyncio.run(_seed_check())
    check("the row says where it came from", bool(_made), _made[:2])
    check("...and NO row from code is handed to a crawler",
          not (set(_made) & _seeded),
          sorted(set(_made) & _seeded)[:3])
else:
    check("skipped: no asset seeded to hang endpoints off", True)


print("\n== dependency manifests served to the world ==")
# `library_leads` asks the CVE corpus about every library a page
# SHIPS. This is the other half: the manifests that say what went
# INTO the build, which turn up on web servers more often than
# anybody intends.
from app import lockfiles as _lk  # noqa: E402

check("a lockfile is recognised by its basename, wherever it is served",
      _lk.format_of("/static/vendor/package-lock.json") == "npm"
      and _lk.format_of("package-lock.json") == "npm")
check("an ordinary script is not a manifest",
      _lk.format_of("/static/app.js") is None)

_NPM3 = json.dumps({"lockfileVersion": 3, "packages": {
    "": {"name": "app"},
    "node_modules/lodash": {"version": "4.17.15"},
    "node_modules/@scope/thing": {"version": "1.2.3"}}})
check("npm lockfileVersion 3 is read from `packages`",
      _lk.parse("package-lock.json", _NPM3)
      == [("@scope/thing", "1.2.3"), ("lodash", "4.17.15")],
      _lk.parse("package-lock.json", _NPM3))
_NPM1 = json.dumps({"lockfileVersion": 1, "dependencies": {
    "lodash": {"version": "4.17.15",
               "dependencies": {"minimist": {"version": "1.2.0"}}}}})
check("...and version 1 is read from the nested `dependencies`",
      ("minimist", "1.2.0") in _lk.parse("package-lock.json", _NPM1))

check("yarn.lock keeps a scoped name whole",
      ("@scope/x", "1.2.3") in _lk.parse(
          "yarn.lock",
          'lodash@^4.17.0, lodash@^4.17.15:\n  version "4.17.15"\n\n'
          '"@scope/x@^1.0.0":\n  version "1.2.3"\n'))
check("Gemfile.lock reads only the specs block",
      _lk.parse("Gemfile.lock",
                "GEM\n  remote: https://rubygems.org/\n  specs:\n"
                "    rails (6.0.3)\n\nPLATFORMS\n  ruby\n")
      == [("rails", "6.0.3")])
check("Cargo.lock is read without a TOML dependency",
      _lk.parse("Cargo.lock",
                '[[package]]\nname = "serde"\nversion = "1.0.104"\n')
      == [("serde", "1.0.104")])
check("go.mod require lines are read",
      _lk.parse("go.mod",
                "module x\n\nrequire github.com/gin-gonic/gin v1.7.2\n")
      == [("github.com/gin-gonic/gin", "1.7.2")])

# A constraint is not a version. Matching a CVE against `^4.17.0`
# would be matching against something nobody is running.
check("requirements.txt takes == and refuses >=",
      _lk.parse("requirements.txt", "Django==2.2.10\nrequests>=2.0\n")
      == [("django", "2.2.10")])
check("a caret range is not treated as an installed version",
      _lk.parse("package-lock.json", json.dumps(
          {"dependencies": {"lodash": {"version": "^4.17.0"}}})) == [])
check("a git ref is not a release",
      _lk.parse("package-lock.json", json.dumps(
          {"dependencies": {"x": {"version": "git+ssh://a/b#c0ffee"}}})) == [])

# A malformed manifest is a file that did not parse, which the
# caller reports as nothing found rather than as a clean result.
check("malformed JSON yields nothing rather than raising",
      _lk.parse("package-lock.json", "{not json") == [])
check("an empty file likewise", _lk.parse("yarn.lock", "") == [])
# Two reads of an unchanged file must produce an identical list, or
# the findings it raises are not idempotent.
check("parsing is stable and deduplicated",
      _lk.parse("package-lock.json", _NPM3)
      == _lk.parse("package-lock.json", _NPM3))

print("\n-- the findings a served manifest raises --")


async def _plant_lockfile(body):
    async with SessionLocal() as s:
        pr = (await s.execute(select(Project).where(
            Project.code == "ASSET"))).scalar_one()
        t = (await s.execute(select(Target).where(
            Target.project_id == pr.id))).scalars().first()
        a = WebAsset(project_id=pr.id, target_id=t.id,
                     url="https://app.acme.example/package-lock.json",
                     kind="script", host="app.acme.example")
        s.add(a)
        await s.flush()
        s.add(WebAssetFile(asset_id=a.id, project_id=pr.id, origin="raw",
                           path="package-lock.json", body=body,
                           bytes=len(body)))
        await s.commit()
        return pr.id


async def _run_lockfiles(pid):
    async with SessionLocal() as s:
        return await _aw.lockfile_leads(s, pid)


_pid = asyncio.run(_plant_lockfile(_NPM3))
_res = asyncio.run(_run_lockfiles(_pid))
check("the manifest was read", _res["manifests"] == 1, _res)
check("...and its packages counted", _res["packages"] == 2, _res)
# An exposed lockfile is a finding on its own. Waiting for a CVE to
# justify saying so would be the wrong way round.
check("the file being reachable is a finding by itself",
      _res["exposed"] == 1, _res)

st, v = call("/api/vulns?project=ASSET&limit=200", token=admin)
_lkv = [x for x in ((v or {}).get("items") or [])
        if (x.get("external_id") or "").startswith("lockfile")]
_exp = [x for x in _lkv if x["external_id"].startswith("lockfile-exposed")]
check("...and it is filed", len(_exp) == 1, [x["title"] for x in _lkv])
if _exp:
    check("...at low, because it is disclosure and not a breach",
          _exp[0]["severity"] == "low", _exp[0]["severity"])
    check("...saying what a manifest discloses",
          "inventory" in (_exp[0].get("description") or ""))
    # A secret sweep finding nothing says nothing about whether a
    # lockfile CVE is still there. See app/lifecycle.py.
    check("...attributed to its own scanner",
          _exp[0].get("scanner") == "lockfile", _exp[0].get("scanner"))

_again = asyncio.run(_run_lockfiles(_pid))
check("a second sweep raises no second exposure finding",
      _again["exposed"] == 0, _again)
st, v2 = call("/api/vulns?project=ASSET&limit=200", token=admin)
check("...and the count is unchanged",
      len([x for x in ((v2 or {}).get("items") or [])
           if (x.get("external_id") or "").startswith("lockfile-exposed")])
      == 1)


print("\n== high-entropy noise, measured and cut ==")
# 1,498 entropy findings on a live estate against 11 from every
# named vendor detector put together. The filters here were measured
# against that data rather than guessed, and each is written as the
# fact about the string that makes it not a credential.

# 1. Too long to be issued. The commonest single length was 452:
#    inline source-map fragments, base64 fonts, data URIs.
check("a 452-character high-entropy string is not a credential",
      _asx.implausible_secret("Zm9v" * 113, "Base64 High Entropy String")
      is not None)
check("...and the reason says what it actually is",
      "source-map" in (_asx.implausible_secret(
          "Zm9v" * 113, "Base64 High Entropy String") or ""))
check("a credential-sized one is still considered",
      _asx.implausible_secret("aG92ZXJjcmFmdDI0ZWVsczE5",
                              "Base64 High Entropy String") is None)
# A vendor shape this long is somebody else's problem to be wrong
# about: the length rule is for entropy only.
check("the length rule does not touch a named vendor detector",
      "too long" not in (_asx.implausible_secret(
          "A1b2" * 80, "Stripe Access Key") or ""))

# 2. A file full of high-entropy strings is a generated file.
_blob = [_asx.Finding(scanner="detect-secrets",
                      rule="Base64 High Entropy String",
                      title="x", severity="low", path="bundle.js",
                      line=i, detail="", fingerprint=f"f{i}",
                      secret="s" * 20) for i in range(40)]
check("forty high-entropy hits in one file are all dropped",
      _asx._drop_entropy_blobs("bundle.js", _blob) == [])
check("...but a handful are kept",
      len(_asx._drop_entropy_blobs("bundle.js", _blob[:5])) == 5)
# A file with forty AWS keys in it is a different thing entirely.
_real = [_asx.Finding(scanner="detect-secrets", rule="AWS Access Key",
                      title="x", severity="high", path="c.js", line=i,
                      detail="", fingerprint=f"a{i}", secret="k" * 20)
         for i in range(40)]
check("forty NAMED credentials in one file are all kept",
      len(_asx._drop_entropy_blobs("c.js", _real)) == 40)
check("...and a named one survives alongside a dropped blob",
      [f.rule for f in _asx._drop_entropy_blobs("m.js", _blob + _real[:1])]
      == ["AWS Access Key"])


print("\n-- a value on more than one host is not that host's secret --")
# Of 1,498 entropy findings, 1,025 had a value that appeared on more
# than one host. A credential issued to one application does not
# turn up on forty-one of them; library content does.


async def _plant_shared(value, hosts):
    """The same high-entropy value on several hosts."""
    async with SessionLocal() as s:
        pr = (await s.execute(select(Project).where(
            Project.code == "ASSET"))).scalar_one()
        ids = []
        for h in hosts:
            t = (await s.execute(select(Target).where(
                Target.project_id == pr.id, Target.host == h))).scalar_one_or_none()
            if t is None:
                t = Target(project_id=pr.id, host=h, kind="host")
                s.add(t); await s.flush()
            v = Vuln(target_id=t.id, title=f"entropy on {h}", severity="low",
                     status="open", external_id=f"detect-secrets:shared-{h}")
            s.add(v); await s.flush()
            s.add(_FS(vuln_id=v.id, secret=value,
                      detector="Base64 High Entropy String",
                      asset_url=f"https://{h}/a.js", path="a.js", line=1))
            ids.append(v.id)
        await s.commit()
        return pr.id, ids


_pid2, _ids = asyncio.run(_plant_shared(
    "c2hhcmVkLWJ1bmRsZS1oYXNoLTEyMzQ1",
    ["one.acme.example", "two.acme.example", "three.acme.example"]))


async def _prune():
    async with SessionLocal() as s:
        return await _aw.prune_shared_secrets(s, _pid2)


_pr = asyncio.run(_prune())
check("the shared value is recognised", _pr["shared_values"] >= 1, _pr)
check("...and every copy of it is retracted", _pr["retracted"] >= 3, _pr)

st, v = call("/api/vulns?project=ASSET&limit=400", token=admin)
_left = [x for x in ((v or {}).get("items") or [])
         if (x.get("external_id") or "").startswith("detect-secrets:shared-")]
check("...so none are left in the findings list", _left == [],
      [x["title"] for x in _left])

# A person's judgement is not a sweep's to overturn.
_pid3, _ids3 = asyncio.run(_plant_shared(
    "dHJpYWdlZC1zaGFyZWQtdmFsdWUtOTk5",
    ["four.acme.example", "five.acme.example"]))
st, _ = call(f"/api/vulns/{_ids3[0]}/triage", "PATCH",
             {"triage": "true_positive"}, token=admin)
check("a finding can be triaged", st == 200, st)
_pr2 = asyncio.run(_prune())
check("a triaged shared finding is left alone",
      _pr2["kept_triaged"] >= 1, _pr2)
st, v = call(f"/api/vulns/{_ids3[0]}", token=admin)
check("...and is still there afterwards", st == 200, st)

# Idempotent: the sweep runs every cycle.
_pr3 = asyncio.run(_prune())
check("running the sweep again retracts nothing new",
      _pr3["retracted"] == 0, _pr3)


print("\n-- identifiers that read like tokens --")
# Five shapes an operator reported from a live estate, all kept by
# the filter as it stood. The values here are SYNTHETIC: the real
# ones are a client's and this repository is public. The shapes are
# reproduced exactly.
_f = _asx.implausible_secret

# A URL is a location. It may CARRY a credential in a query
# parameter, and that parameter is its own finding with its own
# value -- the whole URL is not one.
for _u in ("https://profile.example.com/forgot?b=35k2hAikCYidx5Sgiwiu"
           "iiBm&client_id=dnuF0kFljdpNScQr5YUepIiE",
           # Minified JavaScript holds URLs JSON-escaped.
           "https:\\/\\/profile.example.com\\/forgot?b=35k2hAikCYid",
           "wss://socket.example.com/stream?token=abcd1234efgh5678"):
    check(f"a URL is not a credential ({_u[:18]}…)",
          "URL" in (_f(_u, "Base64 High Entropy String") or ""),
          _f(_u, "Base64 High Entropy String"))

# A CDN or beacon path is slash-separated base64-looking junk and
# reads exactly like a token to a detector that only sees characters.
check("a slash path is not a credential",
      "path" in (_f("/l10cRx/2I/a0/RvA6/zJAN8mbr__/bE/RGNjR0IHcgQ/LQlZ",
                    "Base64 High Entropy String") or ""))
check("...but a single slash is not enough to call it one",
      _f("abc/defGHI123jklMNO456pqr", "Base64 High Entropy String") is None)

# Words joined by separators: message constants, resource keys and
# config names. All have respectable entropy and none is a secret.
for _id in ("ForeignTaxResidency_Investorsummary_Deceased_Message_YES_WARNING",
            "Notification-sc-1ok6jey-0.gigMLv.PendingInvestm",
            "greenid_hosted_dev_user:6MtUzoUDQsf66uLpG3cbzSF"):
    check(f"a separator-joined name is not a credential ({_id[:20]}…)",
          "separator-joined" in (_f(_id, "Base64 High Entropy String") or ""),
          _f(_id, "Base64 High Entropy String"))

# The rule has to leave real credentials alone, and the ones with a
# vendor prefix are exactly the shape it could get wrong: two
# segments where one is a word.
# Shortened on purpose. `scripts/check-secrets.sh` greps for the
# full-length shapes and says why: "Real tokens have a length; the
# placeholders in the docs and tests do not reach these thresholds."
# A fixture that trips the repository's own credential check is a
# fixture that teaches people to skip the check.
for _real, _det in (("AKIAEXAMPLEKEY01", "AWS Access Key"),
                    # Not a real vendor prefix. The SHAPE is what is under test --
# three segments of which exactly one is a word, which is the
# case the identifier rule must not catch -- and GitHub's push
# protection rejects the genuine prefix even on a documented
# example value.
                    ("xx_live_4eC39HqLyjWDarjtT1zdp7dc", "Stripe Access Key"),
                    ("ghp_16C7e42F292c6912E7710c8", "GitHub Token"),
                    ("550e8400-e29b-41d4-a716-446655440000",
                     "Hex High Entropy String"),
                    ("aG92ZXJjcmFmdDI0ZWVsczE5",
                     "Base64 High Entropy String")):
    check(f"{_det} is still kept", _f(_real, _det) is None, _f(_real, _det))

# Two segments is the shape of a prefixed credential, so the rule
# requires three and two words. Asserted because loosening it is the
# obvious "improvement" somebody will make.
check("two segments are not enough to call something an identifier",
      not _asx._compound_identifier("live_4eC39HqLyjWDarjtT1zdp7dc"))
check("...nor is a three-segment credential with one word in it",
      not _asx._compound_identifier("xx_live_4eC39HqLyjWDarjtT1zdp7dc"))
check("...nor is one word among numbers",
      not _asx._compound_identifier("550e8400-e29b-41d4-a716-4466"))
check("three words joined are", _asx._compound_identifier("Foo_Bar_Baz"))


srv.shutdown()
print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
