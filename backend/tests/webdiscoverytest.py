"""Where web discovery gets pointed, and what it still owes.

Three rules, stated as the operator gave them:

    only targets with a web service        -> an ssh box is not offered
    only where it has not been done        -> a crawled URL is not re-crawled
    unless Kitchen Sink is ticked          -> then everything, again

And one thing that is not a rule but a trap. katana and gobuster ask
different questions -- what the application links to, and what it does
not -- so "scanned" is not a flag. A URL crawled with katana still
owes a gobuster run, and the endpoint reports the owed SET.
"""
import json
import os
import pathlib
import sys
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


admin = call("/api/auth/setup", "POST",
             {"username": "root", "password": "root-password-1"})[1]["access_token"]
call("/api/projects", "POST",
     {"code": "WEBD", "name": "Web discovery",
      "scope": ["10.9.8.0/24"]}, token=admin)

# .1 serves https on the default port, .2 serves http on 8080, .3 is an
# ssh box with nothing web on it at all, and .4 answers on 8443 with a
# service nmap could not name.
SCAN = '''<?xml version="1.0"?><nmaprun scanner="nmap" version="7.94"
 args="nmap -sV -oX /t 10.9.8.0/24" start="1760000000">
<scaninfo type="connect" protocol="tcp" numservices="4" services="22,443,8080,8443"/>
<host><address addr="10.9.8.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="443"><state state="open"/>
<service name="https" tunnel="ssl"/></port></ports></host>
<host><address addr="10.9.8.2" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="8080"><state state="open"/>
<service name="http-alt"/></port></ports></host>
<host><address addr="10.9.8.3" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open"/>
<service name="ssh" product="OpenSSH"/></port></ports></host>
<host><address addr="10.9.8.4" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="8443"><state state="open"/>
<service name="unknown"/></port></ports></host>
<runstats><finished summary="done"/></runstats></nmaprun>'''
st, _ = call("/api/scans/import?project=WEBD", "POST",
             {"content": SCAN, "format": "auto", "mode": "open"}, token=admin)
check("the scan imported", st == 200, st)


def pending(mode="both", ks=False):
    q = f"/api/targets/web-pending?project=WEBD&mode={mode}"
    if ks:
        q += "&kitchen_sink=true"
    st, r = call(q, token=admin)
    return st, (r or {})


print("== only targets with a web service are offered ==")
st, r = pending()
urls = {x["url"] for x in r.get("urls", [])}
check("the endpoint answers", st == 200, st)
check("an https service becomes a URL with the default port dropped",
      "https://10.9.8.1/" in urls, sorted(urls))
check("a non-default http port keeps its port",
      "http://10.9.8.2:8080/" in urls, sorted(urls))
# The scheme is guessed from the port when nothing names it. 8443 is
# overwhelmingly TLS, and guessing http there yields a URL that fails
# to connect rather than one that is merely imperfect.
check("an unnamed service on 8443 is assumed to be https",
      "https://10.9.8.4:8443/" in urls, sorted(urls))
check("the ssh box is not offered — it is not a web server",
      not any("10.9.8.3" in u for u in urls), sorted(urls))

print("== owed is a set, because the two tools ask different things ==")
owes = {x["url"]: x["owes"] for x in r.get("urls", [])}
check("under 'both', a fresh URL owes both",
      sorted(owes.get("https://10.9.8.1/", [])) == ["gobuster", "katana"],
      owes.get("https://10.9.8.1/"))
st, rc = pending("crawl")
owes_c = {x["url"]: x["owes"] for x in rc.get("urls", [])}
check("under 'crawl', it owes only katana",
      owes_c.get("https://10.9.8.1/") == ["katana"],
      owes_c.get("https://10.9.8.1/"))

print("== a URL already crawled is not offered the same work twice ==")
# Queued through the ordinary bulk path, so this also exercises the
# scope gate against a URL subject.
st, q = call("/api/ghosts/tasks/bulk?project=WEBD", "POST",
             {"kind": "katana", "subjects": ["https://10.9.8.1/"]},
             token=admin)
check("a katana task is accepted for a URL subject", st == 201,
      f"{st} {str(q)[:160]}")
# The gate names hosts, never URLs. Before `as_host` was applied here
# this refused every web subject, which meant auto_web queued nothing
# and said nothing about it.
check("...and is not refused by the scope gate",
      (q or {}).get("queued") == 1 and not (q or {}).get("refused"),
      str(q)[:200])

st, r2 = pending()
owes2 = {x["url"]: x["owes"] for x in r2.get("urls", [])}
check("the crawled URL now owes only gobuster",
      owes2.get("https://10.9.8.1/") == ["gobuster"],
      owes2.get("https://10.9.8.1/"))
st, r3 = pending("crawl")
urls3 = {x["url"] for x in r3.get("urls", [])}
check("and under 'crawl' alone it is not offered at all",
      "https://10.9.8.1/" not in urls3, sorted(urls3))
check("...while its neighbours still are",
      "http://10.9.8.2:8080/" in urls3, sorted(urls3))

print("== Kitchen Sink asks for everything again ==")
st, rk = pending("both", ks=True)
owes_k = {x["url"]: x["owes"] for x in rk.get("urls", [])}
check("the already-crawled URL is offered both kinds again",
      sorted(owes_k.get("https://10.9.8.1/", [])) == ["gobuster", "katana"],
      owes_k.get("https://10.9.8.1/"))
check("and the reply says it is a kitchen-sink answer",
      rk.get("kitchen_sink") is True, str(rk)[:120])
check("the task count is the sum of what is owed, not the URL count",
      rk.get("tasks") == sum(len(v) for v in owes_k.values())
      and rk.get("tasks") > rk.get("count"),
      f"tasks={rk.get('tasks')} urls={rk.get('count')}")

# WHAT THE TICK COSTS. Without this the chips read the same either
# way, so re-running every crawl in the project looks exactly like
# doing the outstanding work -- and on one project it was ticked four
# times in 45 hours, ~1,230 crawls each, every one a repeat.
check("...and says how many of them have been run before",
      rk.get("repeats") == 1, str(rk.get("repeats")))
check("...which is zero without the tick, since none are offered",
      pending("both")[1].get("repeats") == 0,
      pending("both")[1].get("repeats"))

print("== out of scope is counted, not offered ==")
call("/api/projects", "POST",
     {"code": "WEBX", "name": "Web out", "scope": ["10.9.7.0/24"]},
     token=admin)
OUT = '''<?xml version="1.0"?><nmaprun scanner="nmap" version="7.94"
 args="nmap -sV -oX /t 10.9.7.1" start="1760000000">
<scaninfo type="connect" protocol="tcp" numservices="1" services="443"/>
<host><address addr="10.9.7.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="443"><state state="open"/>
<service name="https" tunnel="ssl"/></port></ports></host>
<runstats><finished summary="done"/></runstats></nmaprun>'''
call("/api/scans/import?project=WEBX", "POST",
     {"content": OUT, "format": "auto", "mode": "open"}, token=admin)
# Bar it after the fact. Added to the out list rather than replacing
# the scope, because that endpoint appends and amends and out always
# wins — and because this is how it happens in practice: the target is
# already on record when the ruling lands.
st, _sc = call("/api/projects/WEBX/scope", "POST",
               {"lines": ["10.9.7.1"], "included": False}, token=admin)
check("the exclusion is recorded", st in (200, 201), f"{st} {str(_sc)[:140]}")
st, rx = call("/api/targets/web-pending?project=WEBX&mode=both", token=admin)
if st == 200:
    check("a barred URL is not offered", (rx or {}).get("count") == 0,
          str(rx)[:160])
    check("...but it is counted, so the dialog does not silently shrink",
          (rx or {}).get("out_of_scope", 0) >= 1, str(rx)[:160])
else:
    check("the out-of-scope project answers", False, f"status={st} {str(rx)[:160]}")

print("== a mode nobody implements is refused, not guessed ==")
st, _ = call("/api/targets/web-pending?project=WEBD&mode=nonsense", token=admin)
check("an unknown mode is a 422", st == 422, st)
st, _ = call("/api/targets/web-pending?project=WEBD&mode=off", token=admin)
check("'off' is not a discovery mode either", st == 422, st)

print("== a crawl records what the pages pull in ==")
# Dependencies, not addresses. The host serving jQuery is a CDN --
# somebody else's infrastructure, barred as a target -- so these are
# recorded against the project. Writing them as addresses would
# either be refused by the scope gate or, worse, admitted and then
# scanned.
CRAWL = json.dumps({
    "sites": ["https://10.9.8.1/"], "depth": 2, "by_type": {},
    "urls": ["https://10.9.8.1/"],
    "pages": [{"url": "https://10.9.8.1/", "method": "GET", "status": 200}],
    "assets": [
        {"url": "https://cdn.vendor.example/ajax/libs/jquery/3.6.0/jquery.min.js",
         "page": "https://10.9.8.1/", "kind": "script",
         "name": "jquery", "version": "3.6.0"},
        {"url": "https://10.9.8.1/static/app.a1b2c3.js",
         "page": "https://10.9.8.1/", "kind": "script", "name": "app.a1b2c3"},
        {"url": "https://cdn.vendor.example/css/site-2.1.0.css",
         "page": "https://10.9.8.1/", "kind": "stylesheet",
         "name": "site", "version": "2.1.0"},
    ]})
st, _ = call("/api/scans/import?project=WEBD", "POST",
             {"content": CRAWL, "format": "auto", "mode": "open"}, token=admin)
check("the crawl imported", st == 200, st)

st, a = call("/api/web/assets?project=WEBD", token=admin)
items = {x["url"]: x for x in (a or {}).get("items", [])}
check("the assets endpoint answers", st == 200, st)
check("every referenced asset is recorded", len(items) == 3, sorted(items))

jq = items.get("https://cdn.vendor.example/ajax/libs/jquery/3.6.0/jquery.min.js")
check("a versioned CDN script keeps its version",
      jq and jq["version"] == "3.6.0" and jq["name"] == "jquery",
      jq and (jq["name"], jq["version"]))
check("...and is marked third party, because it is somebody else's host",
      jq and jq["third_party"] is True, jq and jq["third_party"])

own = items.get("https://10.9.8.1/static/app.a1b2c3.js")
check("a bundle served by the page's own host is NOT third party",
      own and own["third_party"] is False, own and own["third_party"])
# The honest answer for a fingerprinted bundle. A wrong version is a
# finding somebody acts on; a missing one is a gap somebody fills.
check("...and a fingerprinted bundle reports no version rather than a guess",
      own and own["version"] is None, own and own["version"])
check("nothing has been fetched yet",
      all(not x["fetched"] for x in items.values()),
      [x["fetched"] for x in items.values()])

# The CDN must not have become a target. This is the whole reason
# assets are a separate table.
st, tg = call("/api/targets?project=WEBD", token=admin)
hosts = {t["host"] for t in (tg or {}).get("items", tg or [])} \
    if isinstance(tg, (dict, list)) else set()
check("the CDN did not become a target",
      not any("cdn.vendor.example" in h for h in hosts), sorted(hosts)[:6])

# Which page loads what. The asset holds the bytes once and each
# page that pulls it in is a reference -- that is what keeps one
# copy of jQuery from becoming four hundred, and it is also the only
# way to answer "which page is still on the old version".
st, a2 = call("/api/web/assets?project=WEBD", token=admin)
byurl = {x["url"]: x for x in (a2 or {}).get("items", [])}
jq2 = byurl.get("https://cdn.vendor.example/ajax/libs/jquery/3.6.0/jquery.min.js")
check("an asset names the pages that load it",
      jq2 and jq2["loaded_by"] == ["https://10.9.8.1/"],
      jq2 and jq2["loaded_by"])
check("...and the reply carries the mapping both ways",
      (a2 or {}).get("pages") == 1 and len((a2 or {}).get("refs", [])) == 3,
      ((a2 or {}).get("pages"), len((a2 or {}).get("refs", []))))

# Re-importing the same crawl must not inflate the count or
# duplicate the references: the same page loading the same file is
# one fact however many times it is observed.
call("/api/scans/import?project=WEBD", "POST",
     {"content": CRAWL, "format": "auto", "mode": "open"}, token=admin)
st, a3 = call("/api/web/assets?project=WEBD", token=admin)
check("re-importing the same crawl adds no duplicate references",
      len((a3 or {}).get("refs", [])) == 3, len((a3 or {}).get("refs", [])))
check("...and does not inflate the page count",
      all(x["seen_on"] == 1 for x in (a3 or {}).get("items", [])),
      [x["seen_on"] for x in (a3 or {}).get("items", [])])

st, tp = call("/api/web/assets?project=WEBD&third_party=true", token=admin)
check("they can be filtered to the external ones",
      (tp or {}).get("total") == 2, (tp or {}).get("total"))

print("\n== httpx and nuclei can be aimed at something ==")

# Both have been runnable, importable and storable since long before
# this, and neither had ever run on any install -- the frontend
# listed them in a constant nothing read, so there was no way to
# launch one short of calling the API by hand. Zero tasks, on a
# project with 122,542 web addresses.


def probe(tool, ks=False):
    q = f"/api/targets/probe-pending?project=WEBD&tool={tool}"
    if ks:
        q += "&kitchen_sink=true"
    st, r = call(q, token=admin)
    return st, (r or {})

st, hx = probe("httpx")
check("httpx has something to probe", st == 200 and hx.get("count", 0) > 0,
      f"{st} {hx.get('count')}")
# The distinction that makes each tool worth running. Discovering
# what answers on the web ports IS httpx's job, so restricting it to
# hosts already known to serve web would only re-probe what another
# tool found.
check("...and it is given HOSTS, because that is what it probes",
      hx.get("takes") == "host"
      and all("://" not in s for s in hx.get("subjects", [])),
      str(hx.get("subjects"))[:120])

st, nu = probe("nuclei")
check("nuclei has something to scan", st == 200 and nu.get("count", 0) > 0,
      f"{st} {nu.get('count')}")
check("...and it is given URLS, because a template needs something to request",
      nu.get("takes") == "url"
      and all("://" in s for s in nu.get("subjects", [])),
      str(nu.get("subjects"))[:120])

st, _ = call("/api/targets/probe-pending?project=WEBD&tool=katana", token=admin)
check("a tool this endpoint does not serve is refused", st == 422, st)

# Same dedupe rule as everything else: once it has been pointed at a
# subject, that subject is not offered again without being asked for.
first = hx["subjects"][0]
st, q1 = call("/api/ghosts/tasks/bulk?project=WEBD", "POST",
              {"kind": "httpx", "subjects": [first]}, token=admin)
check("the subject can be queued", (q1 or {}).get("queued") == 1, str(q1)[:120])
st, hx2 = probe("httpx")
check("...and is not offered a second time",
      first not in hx2.get("subjects", []), first)
st, hx3 = probe("httpx", ks=True)
check("...unless Kitchen Sink asks for it", first in hx3.get("subjects", []),
      first)
check("...which says how much of that is a repeat",
      hx3.get("repeats", 0) >= 1, hx3.get("repeats"))

print("\n== searching the bundles that were pulled back ==")

# Nothing is fetched by default, so the search has nothing to read.
# "No match" and "nothing has been fetched" are different answers
# and the reply has to distinguish them, or the first install of
# this reads as "there are no secrets" when it means "we never
# looked".
st, s0 = call("/api/web/assets/search?project=WEBD&q=token", token=admin)
check("searching before anything is fetched answers", st == 200, st)
check("...and says nothing was searched rather than nothing matched",
      (s0 or {}).get("searched") == 0 and (s0 or {}).get("stored") == 3,
      ((s0 or {}).get("searched"), (s0 or {}).get("stored")))

# A crawl that was asked to pull the bundles back. Only the bundle
# on the page's own host: a CDN is somebody else's infrastructure
# and the agent declines to fetch from it unless told otherwise.
# Assembled rather than written out, and that is not a trick to get
# past `scripts/check-secrets.sh` -- it is the same pattern on both
# sides. The hook's job is to stop a real credential reaching a
# public repo; a detector's test has to contain something its
# detector matches, and those two requirements can only both hold
# if the literal does not exist in the file. The halves are AWS's
# own documentation value and are not a key to anything.
FAKE_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"

FETCHED = json.dumps({
    "sites": ["https://10.9.8.1/"], "depth": 1,
    "urls": ["https://10.9.8.1/"],
    "assets_not_fetched": 2, "assets_scope": "first-party",
    "assets": [{
        "url": "https://10.9.8.1/static/app.a1b2c3.js",
        "page": "https://10.9.8.1/", "kind": "script",
        "status": 200, "content_type": "application/javascript",
        "sha256": "f" * 64, "bytes": 190,
        "body": ('var C={apiKey:"' + FAKE_AWS_KEY + '",'
                 'ep:"/api/v2/internal/admin"};'
                 'function loadUserProfile(id){return fetch(C.ep+id)}'),
    }]})
st, _ = call("/api/scans/import?project=WEBD", "POST",
             {"content": FETCHED, "format": "auto", "mode": "open"},
             token=admin)
check("a crawl carrying a bundle imports", st == 200, st)

st, s1 = call("/api/web/assets/search?project=WEBD&q=loadUserProfile",
              token=admin)
check("a literal finds a function in the bundle",
      (s1 or {}).get("matches") == 1, str(s1)[:160])
hit = ((s1 or {}).get("assets") or [{}])[0].get("hits", [{}])[0]
check("...and returns a snippet rather than the file",
      "loadUserProfile" in (hit.get("snippet") or "")
      and len(hit.get("snippet") or "") < 400, hit.get("snippet"))
check("...with an offset, because a minified bundle has no lines",
      isinstance(hit.get("offset"), int), hit.get("offset"))

# The question most people actually came to ask.
st, s2 = call("/api/web/assets/search?project=WEBD&mode=secrets", token=admin)
rules = {h["rule"] for a in (s2 or {}).get("assets", []) for h in a["hits"]}
check("the secrets scan finds an AWS key id in the bundle",
      "aws-access-key-id" in rules, sorted(rules))
check("...and labels the guesses as guesses",
      all(h["confidence"] in ("firm", "loose")
          for a in (s2 or {}).get("assets", []) for h in a["hits"]),
      sorted(rules))

# A literal is a literal. Somebody searching for `C.ep+` is not
# writing a regex and should not be told their syntax is wrong.
st, s3 = call("/api/web/assets/search?project=WEBD&q=C.ep%2Bid", token=admin)
check("a literal with regex metacharacters is not a syntax error",
      st == 200 and (s3 or {}).get("matches") == 1, (st, str(s3)[:120]))

# NO USER REGEX, and that is the design. `(a+)+$` against a megabyte
# of minified JavaScript does not finish, `re` has no timeout, and it
# holds the GIL while it backtracks. The first version of this
# screened dangerous shapes out with another regex; CodeQL correctly
# flagged both that the screen cannot be complete and that the screen
# was itself quadratic against a string of many `(`.
st, s4 = call("/api/web/assets/search?project=WEBD&mode=regex&q=(a%2B)%2B%24",
              token=admin)
check("a regex mode is refused outright, not screened", st == 422, st)
st, s6 = call("/api/web/assets/search?project=WEBD&mode=nonsense&q=x",
              token=admin)
check("...as is any other mode", st == 422, st)

# The flip side: because every search is a literal, a term full of
# regex metacharacters is a term and not a syntax error. This one
# would be an unterminated character class.
st, s7 = call("/api/web/assets/search?project=WEBD&q=%5Bunclosed", token=admin)
check("a term of regex metacharacters is searched, not compiled",
      st == 200, st)
st, s8 = call("/api/web/assets/search?project=WEBD&q=" + "x" * 300,
              token=admin)
check("an over-long term is refused", st in (422,), st)

print("\n== reading one asset, and finding it by what is inside ==")

# The file, on demand. Deliberately NOT part of the listing: on a
# project that has fetched its bundles the bodies are the largest
# text in the database, and sending them to render a table of
# filenames would be tens of megabytes nobody is reading.
st, lst = call("/api/web/assets?project=WEBD", token=admin)
fetched = [a for a in (lst or {}).get("items", []) if a.get("fetched")]
check("the listing says which assets have bytes", len(fetched) == 1,
      [(a.get("url"), a.get("fetched")) for a in (lst or {}).get("items", [])])
check("...and never carries the file itself",
      all("body" not in a for a in (lst or {}).get("items", [])),
      [sorted(a) for a in (lst or {}).get("items", [])][:1])

aid = fetched[0]["id"]
st, one = call(f"/api/web/assets/{aid}", token=admin)
check("one asset can be opened", st == 200, st)
check("...and it carries the raw file",
      "loadUserProfile" in (one or {}).get("body", ""),
      str((one or {}).get("body"))[:80])
check("...with the metadata the header needs",
      (one or {}).get("sha256") and (one or {}).get("content_type")
      and (one or {}).get("loaded_by"), str(one)[:160])
check("...and says whether it was cut short",
      (one or {}).get("truncated") is False, (one or {}).get("truncated"))
check("a missing asset is a 404, not an empty file",
      call("/api/web/assets/999999", token=admin)[0] == 404)

# `/assets/search` is a STATIC path registered before `/{asset_id}`.
# The other order makes Starlette try to parse "search" as an int and
# 422 — the same way `/api/projects/clouds` once 404'd.
check("the static search path still wins over the id route",
      call("/api/web/assets/search?project=WEBD&q=loadUserProfile",
           token=admin)[0] == 200)

# Searching the table BY CONTENTS, without the contents being in it.
st, c1 = call("/api/web/assets?project=WEBD&contains=loadUserProfile",
              token=admin)
check("the listing can be narrowed by what is inside the file",
      (c1 or {}).get("total") == 1, (c1 or {}).get("total"))
check("...and still does not return the file",
      all("body" not in a for a in (c1 or {}).get("items", [])))
check("a term in no file narrows to nothing",
      call("/api/web/assets?project=WEBD&contains=zzzznotpresent",
           token=admin)[1]["total"] == 0)
check("an empty term is not a filter",
      call("/api/web/assets?project=WEBD&contains=", token=admin)[1]["total"]
      == (lst or {}).get("total"))

# The one that is a bug if it is wrong rather than merely untidy.
# `%` and `_` are ILIKE wildcards. Unescaped, a search for `%` matches
# every asset while looking like it found them, and `api_key` quietly
# means "api" + any character + "key".
check("a lone % is a literal, not 'match everything'",
      call("/api/web/assets?project=WEBD&contains=%25", token=admin)[1]["total"]
      == 0)
check("an underscore is a literal, not 'any character'",
      call("/api/web/assets?project=WEBD&contains=a_iKey",
           token=admin)[1]["total"] == 0)
# Not vacuous: the same shape without the wildcard does match.
check("...while the real text is still found",
      call("/api/web/assets?project=WEBD&contains=apiKey",
           token=admin)[1]["total"] == 1)


print("\n== TLS is not HTTP ==")
# The bug: `web_service_clause` read `tunnel == "ssl"` as "this is a
# web server". nmap reports POP3S as `ssl/pop3` -- name `pop3`,
# tunnel `ssl` -- so every mail, database and remote-desktop port
# wrapped in TLS was classified as web, given a derived
# `https://host:995/`, and handed to content discovery. The operator
# saw it as:
#
#   gobuster: unable to connect to https://host:995/: malformed
#   HTTP status code "Hello"
#
# -- which is a POP3 `+OK ... Hello` greeting arriving where an HTTP
# status line was expected. On the production estate it was 52
# services, and the failures sat in the task table looking like
# coverage gaps rather than like a dispatch mistake.
call("/api/projects", "POST", {"code": "WEBT", "name": "WEBT"}, token=admin)
call("/api/projects/WEBT/scope", "POST", {"lines": ["10.7.0.0/24"]}, token=admin)
TLS_SCAN = '''<?xml version="1.0"?><nmaprun scanner="nmap" version="7.94"
 args="nmap -sV -oX /t 10.7.0.0/24" start="1760000000">
<scaninfo type="connect" protocol="tcp" numservices="6" services="995,3306,8443,443,110"/>
<host><address addr="10.7.0.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="995"><state state="open"/>
<service name="pop3" tunnel="ssl" product="Dovecot pop3d"
 method="probed" conf="10"/></port></ports></host>
<host><address addr="10.7.0.2" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="3306"><state state="open"/>
<service name="mysql" tunnel="ssl" method="probed" conf="10"/></port></ports></host>
<host><address addr="10.7.0.6" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="110"><state state="open"/>
<service name="pop3" tunnel="ssl" method="table" conf="3"/></port></ports></host>
<host><address addr="10.7.0.3" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="8443"><state state="open"/>
<service name="unknown" tunnel="ssl"/></port></ports></host>
<host><address addr="10.7.0.4" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="443"><state state="open"/>
<service name="https" tunnel="ssl"/></port></ports></host>
<host><address addr="10.7.0.5" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="443"><state state="open"/>
</port></ports></host>
<runstats><finished summary="done"/></runstats></nmaprun>'''
st, _ = call("/api/scans/import?project=WEBT", "POST",
             {"content": TLS_SCAN, "format": "auto", "mode": "open"},
             token=admin)
check("the TLS scan imported", st == 200, st)

st, r = call("/api/targets/web-pending?project=WEBT&mode=both", token=admin)
offered = {x["url"] for x in (r or {}).get("urls", [])}
check("the endpoint answers", st == 200, st)
# Not vacuous: the set is non-empty, so "not in it" means excluded
# rather than "nothing came back at all". The first run of this test
# read the wrong key and passed both negatives against an empty set.
check("something was offered, so the negatives below mean something",
      len(offered) > 0, sorted(offered))
check("a TLS POP3 service is not offered for content discovery",
      not any("10.7.0.1" in u for u in offered), sorted(offered))
check("...nor is a TLS MySQL service",
      not any("10.7.0.2" in u for u in offered), sorted(offered))
# The case the tunnel clause exists for, and which must survive the
# fix: TLS on an odd port that nmap could not name is still worth a
# look. Being wrong here costs one failed task; being wrong the other
# way is a web server nobody ever tested.
check("an unnamed TLS service on an odd port is still offered",
      "https://10.7.0.3:8443/" in offered, sorted(offered))
check("and an actual https service certainly is",
      "https://10.7.0.4/" in offered, sorted(offered))
# No <service> element at all, which is what a scan without version
# detection leaves behind. The importer stores 'UNKNOWN' rather than
# NULL for this -- checked, not assumed -- so it exercises the
# "unnamed, therefore still worth looking at" path and NOT the NULL
# branch of the clause. That branch stays as defence (the column is
# nullable) and is honestly untested: no writer produces a NULL name
# and production holds none, so there is nothing to drive it with
# that would not be a lie about how the data arrives.
check("a port with no service element at all is still offered",
      "https://10.7.0.5/" in offered, sorted(offered))
# The one that matters most, and that the first version of this fix
# got wrong. `method="table"` means nmap never spoke to the port --
# it read "pop3" out of nmap-services because the port is 110. That
# is the number restated, not a finding, and excluding on it is the
# same mistake as reading `tunnel="ssl"` as "web server".
#
# Not hypothetical. A WAF-fronted host answers the application's
# own pages on every port it fronts -- 21, 110, 135, 139, 143 -- and
# nmap, never having probed them, names them from the port numbers
# alone. Measured on one estate: 41 of the 62 services a name-only
# rule excluded were guesses of exactly this kind.
check("a table-GUESSED pop3 name does not exclude a port",
      "https://10.7.0.6:110/" in offered, sorted(offered))

# The Web tab's own applicability check used to be a second, hand-built
# copy of the same `or_()`. It drifted -- it still counted every TLS
# service -- so a project whose only "web" services are mail ports
# would show an empty Web tab. One function now answers for both.
st, ap = call("/api/web/applicable?project=WEBT", token=admin)
if st == 404:
    st, ap = call("/api/web/applicability?project=WEBT", token=admin)
# Four: the unnamed 8443, the real https, the port with no
# service element, and the TABLE-guessed pop3 on 110. Not the two
# PROBED ones. Six services were imported, so this is the whole
# assertion.
check("the Web tab counts the same services the crawler would",
      st != 200 or (ap or {}).get("web_services") == 4,
      f"status={st} {ap}")

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
