"""Where web discovery should be pointed, and what it still owes.

Crawling and content discovery are queued per URL, not per host: one
host can serve several sites, and "scan example.com" is not a thing
either tool can do -- both need somewhere to start.

Two sources of URLs, and the second is the one that matters here:

  * URLs already recorded against the project, from httpx, Burp,
    nuclei or an operator typing one in. These are known-good.
  * URLs DERIVED from an open web service. A target with 443 open and
    nothing recorded against it has never been looked at, and it is
    exactly the one worth looking at. Deriving `https://host/` from
    the open port is what turns "this port is open" into something a
    crawler can be aimed at.

The derived half is why this module exists rather than the automation
snapshot's `web_urls` being reused: that set is recorded URLs only, so
a project whose hosts had been port-scanned but never crawled looked,
to the standing orders, like a project with no web estate at all.

**"Complete" depends on what is being asked for.** `katana` follows
what the application links to and `gobuster` asks for paths nothing
links to; neither subsumes the other. So a URL crawled with katana
still owes a gobuster run when the operator asks for both, and the
owed set -- not a single scanned/unscanned flag -- is what this
reports.
"""
from __future__ import annotations

from sqlalchemy import and_, func, not_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Service, Target, WebAddress
from .tasking import tasked_subjects
from .weburl import BadUrl
from .weburl import parse as parse_url

#: Which task kinds each web policy queues.
#:
#: `katana` follows what the application links to; `gobuster` asks for
#: paths nothing links to. Different questions, which is why `both`
#: runs both rather than one being a superset of the other.
WEB_KINDS: dict[str, tuple[str, ...]] = {
    "crawl": ("katana",),
    "gobuster": ("gobuster",),
    "both": ("katana", "gobuster"),
}

#: Tools that find a URL by FOLLOWING a link to it, as they spell
#: themselves in `WebAddress.sources`.
#:
#: `sources` is a comma-joined list because one URL is routinely found
#: more than once, and the importer merges rather than duplicating: a
#: path both a crawl and content discovery turned up is ONE row saying
#: `katana,gobuster`. That merge is why "delete the gobuster row once
#: the crawl has run" has nothing to delete -- the duplicate never
#: existed -- and why the split below is a filter instead.
CRAWLER_SOURCES: tuple[str, ...] = ("katana", "gospider", "burp")

#: Tools that find a URL by GUESSING it against a wordlist.
#:
#: What separates the two is not quality, it is reachability. A
#: crawler can only reach what the application links to; content
#: discovery is the only thing that finds what it does not. On the
#: production estate that distinction is 50,657 addresses no crawl
#: ever saw, 29,032 of them answering 401 or 403 -- paths that exist
#: and are protected, which is usually the more interesting answer
#: than a 200 and is unreachable by any amount of crawling.
DISCOVERY_SOURCES: tuple[str, ...] = ("gobuster", "ffuf", "dirb", "dirsearch")


def source_clause(found_by: str, col=None):
    """`found_by` -> a WHERE clause over `WebAddress.sources`, or None.

    `col` overrides which column to read, so the same definition can be
    applied to a subquery's `sources` when counting. The counts and the
    listing MUST come from one definition or the dropdown will promise
    a number of rows the table then does not show.

    Three answers, and the third is the one worth naming:

    * `crawl`     -- a crawler saw it, whoever else did too.
    * `discovery` -- content discovery found it and no crawler did.
    * anything else, including None -- no clause; show everything.

    The two are DISJOINT but are not a partition, and the difference
    matters to anyone reading the counts. A URL that only httpx or
    nuclei ever reported was neither crawled to nor guessed at: it was
    probed directly, and it belongs to neither slice. So
    `crawl + discovery <= all`, with equality only on an estate whose
    web inventory came from crawling and content discovery alone --
    which the production one happens to be, and which is why the
    assumption is easy to make and worth writing down.

    Substring matching on a comma-joined column, which is ordinarily a
    bug waiting to happen. It is safe here only because these are
    fixed tool names from a closed list, never user input, and no name
    in either list is a substring of another. A new tool whose name
    contains an existing one would break that, so it is asserted
    below rather than left to be noticed later.
    """
    sources = WebAddress.sources if col is None else col
    crawled = or_(*(sources.ilike(f"%{t}%") for t in CRAWLER_SOURCES))
    if found_by == "crawl":
        return crawled
    if found_by == "discovery":
        # Found by a discovery tool AND by no crawler. The second half
        # is what makes this "only": without it the 2,006 rows that
        # BOTH tools found would appear under each filter, and the two
        # views would not add up to the total.
        return and_(
            or_(*(sources.ilike(f"%{t}%") for t in DISCOVERY_SOURCES)),
            ~crawled)
    return None


# No tool name may contain another, or the substring match above would
# quietly fold two sources into one.
assert not any(
    a != b and a in b
    for a in (*CRAWLER_SOURCES, *DISCOVERY_SOURCES)
    for b in (*CRAWLER_SOURCES, *DISCOVERY_SOURCES))

#: The web discovery kinds, derived rather than written again.
#:
#: These are the kinds that dedupe on "has this URL EVER been tasked"
#: rather than on "is it in flight". A crawl of a site that has been
#: crawled is the same requests to the same client for the same
#: answer, so repeating it is something the operator has to ask for by
#: name -- see `queue_per_host`'s `rescan`, and `owed`'s
#: `kitchen_sink`, which are the same decision at two different
#: layers.
WEB_TASK_KINDS: tuple[str, ...] = tuple(
    sorted({k for kinds in WEB_KINDS.values() for k in kinds}))

#: `WEB_CHOICES` and `NMAP_CHOICES` live in models.py, where
#: schemas.py can validate against them without importing this
#: module. They have to agree, and the test asserts that rather than
#: trusting two lists.

#: Service names and ports that mean "there is a web server here".
#: Deliberately not just the names: a scanner that could not identify
#: the service still tells you something by the port it answered on.
#:
#: Lives here, and `routers/web.py` imports it, so that "is this a web
#: service" has one answer. The Web view's own applicability check and
#: this both ask it, and the two disagreeing would mean a project whose
#: Web tab is visible but which offers nothing to crawl.
WEB_NAMES = {"http", "https", "http-alt", "https-alt", "http-proxy",
             "httpd", "www", "ssl/http", "http-mgmt", "websocket"}
WEB_PORTS = {80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9443, 3000, 5000}

#: Ports that are https even when nothing said so. A service on 8443
#: with no name and no `tunnel` is far more likely to be TLS than
#: cleartext, and guessing http there produces a URL that fails to
#: connect rather than one that is merely imperfect.
TLS_PORTS = {443, 8443, 9443}

#: Protocols that are definitely not HTTP, however they are reached.
#:
#: `tunnel == "ssl"` in the clause below says a service speaks TLS.
#: That is not the same claim as "speaks HTTP over TLS", and it was
#: being read as one. nmap reports POP3S as `ssl/pop3` -- name `pop3`,
#: tunnel `ssl` -- so every mail, database and remote-desktop port
#: wrapped in TLS was classified as a web server, given a derived
#: `https://host:995/`, and handed to content discovery. On the
#: production estate that was 52 services across POP3, IMAP, MySQL,
#: RDP, VNC, FTP, NetBIOS, MSRPC, XMPP and SMTP, and the resulting
#: gobuster failures ("malformed HTTP status code \"Hello\"" -- a
#: POP3 greeting) sat in the task table looking like coverage gaps.
#:
#: Matched on the NAME, not the port. A web server really can listen
#: on 995; what it cannot do is answer to `pop3`. Both the bare and
#: the `ssl/`-prefixed spellings are listed because importers differ
#: on which they record.
_NOT_HTTP = (
    "pop3", "pop3s", "imap", "imaps", "imap-proxy", "smtp", "smtps",
    "submission", "ftp", "ftps", "ftp-data", "ssh", "telnet", "telnets",
    "ldap", "ldaps", "nntp", "nntps", "irc", "ircs", "xmpp", "xmpp-client",
    "xmpp-server", "mysql", "postgresql", "ms-sql-s", "oracle-tns",
    "mongodb", "redis", "memcached", "ms-wbt-server", "vnc", "rdp",
    "netbios-ssn", "microsoft-ds", "msrpc", "smb", "domain", "dns",
    "ntp", "snmp", "kerberos-sec", "rsync", "nfs", "rpcbind", "sip",
    "sip-tls", "tcpwrapped",
)
NON_WEB_NAMES = frozenset(_NOT_HTTP) | frozenset(f"ssl/{n}" for n in _NOT_HTTP)


def web_service_clause():
    """The SQL for "this service is a web server".

    Named evidence that a service is something else beats every
    positive signal here, including the port: a service nmap
    identified as `pop3` is POP3 whatever port it is on and whatever
    it is wrapped in.
    """
    positive = or_(func.lower(Service.name).in_(WEB_NAMES),
                   Service.port.in_(WEB_PORTS),
                   Service.tunnel == "ssl")
    # Only a name nmap actually PROBED counts as evidence of another
    # protocol. `method="table"` means it never spoke to the port and
    # read the name out of nmap-services by number -- "pop3" there is
    # the number 110 restated, not a finding, and excluding on it is
    # the same mistake this clause was fixing: treating a guess as an
    # answer.
    #
    # It matters because of CDN fronting. A WAF in front of a host
    # answers HTTP on every port it fronts, so `cdn1.acme.example`
    # serves the application's real pages on 21, 110, 135, 139 and
    # 143 -- while nmap, having never probed them, calls them ftp,
    # pop3, msrpc, netbios-ssn and imap from the port numbers alone.
    # A name-only exclusion drops a live application on five ports.
    # Measured on one estate: of 62 services such a rule excluded, 41
    # were table guesses and only 21 were probed.
    #
    # coalesce on both sides on purpose. With a bare comparison a
    # NULL `method` or `name` makes the AND null, `not_()` of null is
    # null, and a WHERE reads that as false -- so the rows we know
    # least about would be the ones silently dropped.
    proved_other = and_(
        func.coalesce(Service.method, "") == "probed",
        func.coalesce(func.lower(Service.name), "").in_(NON_WEB_NAMES))
    return and_(positive, not_(proved_other))


def scheme_for(port: int, name: str | None, tunnel: str | None) -> str:
    n = (name or "").lower()
    if (tunnel or "").lower() == "ssl" or port in TLS_PORTS or "https" in n:
        return "https"
    return "http"


def derive_url(host: str, port: int, name: str | None,
               tunnel: str | None) -> str | None:
    """A URL to start from, normalised the way recorded ones are.

    Normalised through the same parser the recorded URLs went through,
    so a derived `https://host/` and a recorded one are the same
    string. If they were not, every derived URL would look unscanned
    for ever -- the comparison against what has been tasked is a string
    comparison, and two spellings of one URL defeat it silently.
    """
    try:
        return parse_url(f"{scheme_for(port, name, tunnel)}://{host}:{port}/").url
    except BadUrl:
        # A host that will not parse is not a crawl target. Reported
        # nowhere because there is nothing an operator could do about
        # it that fixing the target record would not do better.
        return None


def origin_of(url: str) -> str | None:
    """`https://h.example:8443/a/b?c` -> `https://h.example:8443/`.

    **This is what makes web discovery terminate.** Both tools start
    at a URL and walk outwards from it: katana follows every link it
    finds, gobuster asks for every path in a wordlist. Pointing either
    at `/a/b` rather than at `/` buys nothing -- the crawl reaches the
    same pages and the wordlist is applied from the root regardless --
    and pointing them at *each URL the last run discovered* is a loop
    that multiplies.

    It did exactly that: a crawl of one site returned several hundred
    URLs, each was imported, each then looked like somewhere to crawl,
    and one project went from 1,109 queued tasks to 97,959 in under an
    hour before it was stopped. Collapsing to the origin makes the set
    closed under crawling -- everything a crawl of an origin finds
    collapses back to that same origin -- so the policy has a fixed
    point instead of an exponent.

    Lowercased, because the comparison against what has already been
    tasked is made on lowercased strings. Scheme and host are already
    lowercased by `weburl.parse`; the port is numeric; nothing here
    carries a path, so this cannot lose information the way
    lowercasing a full URL would.
    """
    try:
        u = parse_url(url)
    except BadUrl:
        return None
    default = 443 if u.scheme == "https" else 80
    netloc = u.host if u.port == default else f"{u.host}:{u.port}"
    return f"{u.scheme}://{netloc}/".lower()


async def discoverable(session: AsyncSession, project_id: int,
                       ) -> dict[str, str]:
    """-> {origin: the host it belongs to}, for the whole project.

    ORIGINS, not URLs -- see `origin_of` for why that is the whole
    design and not a tidying. Two sources: open web services, and the
    origins of every URL already recorded. Both collapse to the same
    strings, so a site known from both ways is one entry.
    """
    out: dict[str, str] = {}

    rows = (await session.execute(
        select(Target.host, Service.port, Service.name, Service.tunnel)
        .join(Service, Service.target_id == Target.id)
        .where(Target.project_id == project_id,
               Service.state == "open",
               web_service_clause()))).all()
    for host, port, name, tunnel in rows:
        if not host:
            continue
        u = derive_url(host, int(port), name, tunnel)
        if u and (o := origin_of(u)):
            out.setdefault(o, host)

    recorded = (await session.execute(
        select(WebAddress.url, Target.host)
        .join(Target, Target.id == WebAddress.target_id)
        .where(Target.project_id == project_id))).all()
    for url, host in recorded:
        if url and (o := origin_of(url)):
            out.setdefault(o, host or "")

    return out


async def owed(session: AsyncSession, project_id: int, mode: str,
               kitchen_sink: bool = False) -> dict[str, list[str]]:
    """-> {url: kinds this mode still owes it}.

    With `kitchen_sink`, every URL owes every kind the mode names,
    whether or not it has been run before. That is a re-run, and the
    caller is expected to have said so in the UI: content discovery
    against a site already walked is a real thing to want when paths
    have been added since, and wasted traffic at a client when they
    have not.

    A URL that owes nothing is absent rather than present with an
    empty list, so `len()` is the count of work to do.
    """
    kinds = WEB_KINDS.get(mode)
    if not kinds:
        return {}
    urls = await discoverable(session, project_id)
    if kitchen_sink:
        return {u: list(kinds) for u in urls}

    done = await tasked_subjects(session, project_id, tuple(kinds))
    out: dict[str, list[str]] = {}
    for u in urls:
        # `tasked_subjects` lowercases its subjects. The URLs here are
        # already normalised to a lowercase scheme and host, but the
        # path is case-sensitive and is not touched, so the comparison
        # is made on the same footing rather than assuming.
        missing = [k for k in kinds if (k, u.lower()) not in done]
        if missing:
            out[u] = missing
    return out


#: Statuses that mean "there is a page here worth walking out from".
#:
#: A 200 is content. A 401 or a 403 says the path exists and is
#: protected -- a genuine finding, and the bulk of what content
#: discovery returns -- but there is nothing behind it to crawl
#: without credentials, and pointing a crawler at it spends requests
#: to re-learn the status gobuster already recorded.
CRAWLABLE_STATUS = (200,)

#: Statuses worth fetching ONCE even though there is nothing to crawl.
#:
#: A 401 or 403 is the most valuable thing content discovery finds --
#: the path exists and is protected -- and content discovery is the
#: only thing that can find it, because nothing links to it. But
#: gobuster reports a status and keeps no packet: on the production
#: estate 52,663 addresses came from gobuster and 1,967 had a
#: response body, and every one of those 1,967 got it from a crawl
#: that happened to reach the same URL.
#:
#: So the evidence for 29,032 findings was a bare number. The headers
#: are the finding here -- which WAF answered, what realm the 401
#: names, whether the 403 is the application or the edge -- and none
#: of it was kept.
#:
#: Seeded like a crawl because that reuses the one path that captures
#: a raw exchange properly: the agent fetches it, `redactAuth` strips
#: credentials, and the importer stores request and response. It is
#: one GET to a path gobuster already requested, so it adds no
#: exposure that the content-discovery run did not already have.
PACKET_STATUS = (401, 403)

#: Per origin. A crawl seeded with the ten unlinked entry points
#: gobuster found is a different crawl; one seeded with two hundred
#: is a catch-all host that answered to everything, and the cap is
#: what stops that host from turning one task into a sweep.
MAX_SEEDS = 25

#: Extensions a crawl has nothing to do with. `backup.zip` answering
#: 200 is a real finding and it belongs in the inventory -- it is just
#: not somewhere a crawler can go, and seeding it spends a request
#: downloading an archive to find no links in it.
#:
#: Deliberately NOT a list of what is allowed. `.js` and `.json` stay
#: crawlable because katana scrapes JS responses for endpoints, and an
#: unknown extension is something we have not seen rather than
#: something we know is inert.
NOT_CRAWLABLE = frozenset((
    "7z", "avi", "bin", "bmp", "bz2", "dll", "dmg", "doc", "docx", "exe",
    "flv", "gif", "gz", "ico", "iso", "jar", "jpeg", "jpg", "mp3", "mp4",
    "msi", "odt", "pdf", "png", "ppt", "pptx", "rar", "svg", "tar", "tgz",
    "ttf", "wav", "webp", "woff", "woff2", "xls", "xlsx", "zip",
))

#: The same judgement from the other direction, for the paths that
#: carry no extension. A deny list again, and for the same reason: a
#: content type we do not recognise is one we have not seen before,
#: which is not the same as one we know holds no links.
NOT_CRAWLABLE_TYPES = ("image/", "video/", "audio/", "font/",
                       "application/zip", "application/octet-stream",
                       "application/pdf", "application/x-")


async def crawl_seeds(session: AsyncSession, project_id: int,
                      ) -> dict[str, list[str]]:
    """-> {origin: [url, ...]}, the paths a crawl has not started from.

    **Content discovery feeds crawling, and the edge runs one way.**
    gobuster finds what nothing links to; katana follows links. A path
    nothing links to is precisely the one a crawl cannot reach on its
    own, and it is frequently the entry point to a whole unlinked
    subtree -- an admin app, a staging build, an old deploy. Handing
    those back to the crawler is the one case where pointing it at
    something other than an origin earns its requests.

    It is also the case that has to be built carefully, because
    pointing a crawler at each URL the last run discovered is exactly
    what took one project from 1,109 queued tasks to 97,959 in under
    an hour. The difference is that this source does not feed itself:

      * The seeds come from `gobuster` rows only. A crawl's own
        output is never a seed, so a crawl cannot produce more
        crawling.
      * gobuster is queued per origin and bounded by its wordlist, so
        the set of seeds a project can ever have is finite and known
        before any of this runs.
      * Seeds already handed to a crawl are excluded, and because
        `tasked_subjects` records EVERY entry of `args["targets"]`,
        a seeded crawl marks its own seeds as done by running.

    The result is one task per origin rather than one per path --
    a crawl of one site from several entry points is one crawl --
    which keeps "a single web crawl is a single request" true.
    """
    # `sources ILIKE '%gobuster%'` is the one-way edge, in SQL. A crawl
    # writes `sources` of `katana`, so a crawl's output cannot match
    # here however many times it runs. That is the property the whole
    # design rests on, so it is a WHERE clause rather than a
    # convention somebody could later be tempted to relax.
    #
    # The content-type half of "is this somewhere a crawler can go".
    # A NULL passes: gobuster's older output shape carried no content
    # type at all, and not knowing what a thing is is not grounds for
    # deciding it is a zip file.
    rows = (await session.execute(
        select(WebAddress.url)
        .join(Target, Target.id == WebAddress.target_id)
        .where(Target.project_id == project_id,
               WebAddress.sources.ilike("%gobuster%"),
               # Two reasons to send the agent at a path, and they are
               # not the same reason.
               #
               # A 200 is seeded to be CRAWLED -- it is an unlinked
               # entry point and there may be a whole subtree behind
               # it. A 401 or 403 is seeded to be FETCHED once, purely
               # so the exchange is on the record; there is nothing
               # behind it to walk. The second is gated on having no
               # response yet, because once the packet is captured the
               # reason to go back is gone -- without that it would
               # re-fetch every protected path on every cycle, for
               # ever, against the client.
               or_(WebAddress.status_code.in_(CRAWLABLE_STATUS),
                   and_(WebAddress.status_code.in_(PACKET_STATUS),
                        or_(WebAddress.response.is_(None),
                            WebAddress.response == ""))),
               or_(WebAddress.content_type.is_(None),
                   and_(*(~WebAddress.content_type.ilike(f"{t}%")
                          for t in NOT_CRAWLABLE_TYPES)))))).scalars().all()
    if not rows:
        return {}

    # Narrowed to the one kind here rather than inside `group_seeds`,
    # which is a set comprehension per row otherwise -- and a project
    # with a real web estate has tens of thousands of both.
    crawled = {s for k, s in await tasked_subjects(
        session, project_id, ("katana",)) if k == "katana"}
    return group_seeds(rows, crawled)


def group_seeds(urls: list[str] | tuple[str, ...],
                crawled: set[str]) -> dict[str, list[str]]:
    """The grouping half of `crawl_seeds`, with no database.

    Separate so the rules that matter can be asserted directly: that
    an origin never seeds itself, that a path already handed to a
    crawl is dropped, and that one catch-all host cannot turn a seed
    list into a sweep.
    """
    # Grouped by `origin_of(url)`, which is what makes every seed in a
    # group provably on that group's origin. The scope gate is given
    # the origin, so a group containing a URL from anywhere else would
    # be scanning a host nobody cleared.
    by_origin: dict[str, list[str]] = {}
    for url in urls:
        if not url or not (o := origin_of(url)):
            continue
        if url.lower() in crawled:
            continue
        # The origin itself is not a seed. It has its own crawl, and
        # adding it here would re-crawl the whole site every time one
        # new path turned up.
        if url.lower().rstrip("/") == o.rstrip("/"):
            continue
        if not crawlable_path(url):
            continue
        by_origin.setdefault(o, []).append(url)

    return {o: sorted(set(urls))[:MAX_SEEDS]
            for o, urls in by_origin.items()}


def crawlable_path(url: str) -> bool:
    """Is this somewhere a crawler could find a link?

    Extension only -- the content-type half of the same question is a
    WHERE clause in `crawl_seeds`, because the two cover for each
    other: a `.zip` served as `text/html` is caught here, and a
    download endpoint with no extension at all is caught there.

    Note this governs SEEDING ONLY. Every hit gobuster returns is
    imported as a web address regardless; `backup.zip` answering 200
    is one of the more interesting things content discovery can find
    and it belongs in the inventory. It is just not a place to start
    a crawl from.
    """
    last = url.split("?")[0].split("#")[0].rstrip("/").rsplit("/", 1)[-1]
    if "." not in last:
        return True
    return last.rsplit(".", 1)[-1].lower() not in NOT_CRAWLABLE


# ------------------------------------------------- probe and template
#
# `httpx` and `nuclei` are the two tools this app has been able to
# run, import and store since before any of the web discovery work,
# and which nothing has ever launched: zero tasks, on every install,
# because `GHOST_KINDS` in the frontend listed them and no component
# ever read that list. The agent runners exist, `TASK_KINDS` maps
# both to importers, and `httpx_json`/`nuclei` parse the output.
#
# Kept out of `WEB_KINDS`, which is the `auto_web` POLICY map --
# adding them there would silently widen what a standing order of
# `both` does to a client.

#: What each asks, and what it should therefore be pointed at.
#:
#: httpx probes a HOST to find out whether anything answers on the
#: web ports and what it is. nuclei runs templates against a URL that
#: is already known to be there. Pointing httpx at a URL wastes the
#: discovery it exists for; pointing nuclei at a bare hostname gives
#: it nothing to request.
PROBE_KINDS: dict[str, str] = {
    "httpx": "host",
    "nuclei": "url",
    #: Technology detection. A URL for the same reason as `nuclei`:
    #: the templates request a page and read what comes back.
    "nuclei_tech": "url",
}


async def probe_owed(session: AsyncSession, project_id: int, kind: str,
                     kitchen_sink: bool = False) -> list[str]:
    """-> the subjects `kind` has not been pointed at yet.

    Same shape of answer as `owed`, and the same `kitchen_sink`
    meaning: everything again, which is a re-run the caller is
    expected to have asked for in as many words.
    """
    if kind not in PROBE_KINDS:
        return []

    if PROBE_KINDS[kind] == "url":
        subjects = sorted(await discoverable(session, project_id))
    else:
        # Every host, not only the ones already known to serve web.
        # Finding that out is what httpx is FOR, so restricting it to
        # hosts with a recorded web service would only ever re-probe
        # what another tool had already found.
        subjects = sorted({
            h for h in (await session.execute(
                select(Target.host).where(
                    Target.project_id == project_id))).scalars().all() if h})

    if kitchen_sink:
        return subjects
    done = {s for k, s in await tasked_subjects(session, project_id, (kind,))
            if k == kind}
    return [s for s in subjects if s.lower() not in done]
