"""Subdomain takeover candidates: a name pointing somewhere unclaimed.

A dangling CNAME is the cheapest serious finding on an external
engagement. `shop.acme.example` was pointed at a Heroku app or an S3
bucket, the app was deleted, and the DNS record was not. Anyone who
registers that name on that provider now serves content on the
client's domain, with the client's TLS story and the client's
cookies.

This finds them from data already collected rather than by asking a
third party. The agent passes `-cname` to httpx, the importer records
the chain, and the match below is a string comparison against a table
of providers that hand out subdomains on a first-come basis.

**Three answers, not two.** A name that matches a provider is not a
takeover, it is a candidate. `dangling` means the chain reached a
name that does not resolve, which is the strong case. `fingerprint`
means the provider served its own "nothing is here" page, which is
the other strong case. `candidate` means the CNAME points at such a
provider and neither check could be run -- that is "could not
determine", and reporting it as a finding is how a tester wastes a
morning on a live Shopify store that simply belongs to the client.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

#: How sure we are, strongest first. `Takeover.verdict` holds one.
VERDICTS = ("dangling", "fingerprint", "candidate")


@dataclass(frozen=True)
class Provider:
    """One service that hands out subdomains to whoever asks first."""
    name: str
    #: CNAME suffixes that put a name on this provider. Plain
    #: `endswith` matching.
    suffixes: tuple[str, ...]
    #: What the provider serves when the name is NOT claimed. Matched
    #: against a response body. Empty means the provider has no stable
    #: unclaimed page, so only a dangling chain can convict it.
    fingerprints: tuple[str, ...] = ()
    #: For the names a suffix cannot express, because the provider
    #: puts the region in the MIDDLE. Matched against the whole
    #: normalised name. This started as three hardcoded `startswith`
    #: checks against S3 spellings inside the matcher, which worked
    #: and could not be extended without adding a fourth.
    patterns: tuple[re.Pattern[str], ...] = ()
    #: False when registering the name again is not actually open to
    #: anyone -- the record still dangles and is still worth removing,
    #: but it is a hygiene finding and not a hostile-takeover one.
    claimable: bool = True


#: Kept deliberately short and accurate rather than exhaustive. Every
#: entry here has been a real takeover; a long list copied wholesale
#: from a public repo brings along providers that closed the hole
#: years ago, and a false positive on this check costs an operator a
#: morning proving a live site belongs to the client.
PROVIDERS: tuple[Provider, ...] = (
    Provider("AWS S3", (".s3.amazonaws.com",),
             ("NoSuchBucket", "The specified bucket does not exist"),
             patterns=(
                 # The region sits between the marker and the domain:
                 # `.s3-website-eu-west-1.amazonaws.com`.
                 re.compile(r"\.s3-website[.-]"),
                 re.compile(r"\.s3\.dualstack\."),
                 re.compile(r"\.s3-external-"),
             )),
    Provider("GitHub Pages", (".github.io",),
             ("There isn't a GitHub Pages site here",
              "For root URLs (like http://example.com/) you must provide an index.html file")),
    Provider("Heroku", (".herokuapp.com", ".herokudns.com", ".herokussl.com"),
             ("No such app", "herokucdn.com/error-pages/no-such-app.html")),
    Provider("Azure", (".azurewebsites.net", ".cloudapp.azure.com",
                       ".cloudapp.net", ".trafficmanager.net",
                       ".blob.core.windows.net", ".azureedge.net",
                       ".azurefd.net"),
             ("404 Web Site not found", "Error 404 - Web app not found")),
    Provider("Shopify", (".myshopify.com",),
             ("Sorry, this shop is currently unavailable",
              "Only one step left!")),
    Provider("Fastly", (".fastly.net", ".fastlylb.net"),
             ("Fastly error: unknown domain",)),
    Provider("Pantheon", (".pantheonsite.io",),
             ("The gods are wise",)),
    Provider("Zendesk", (".zendesk.com",),
             ("Help Center Closed",)),
    Provider("Tumblr", (".tumblr.com",),
             ("Whatever you were looking for doesn't currently exist at this address",)),
    Provider("WordPress", (".wordpress.com",),
             ("Do you want to register",)),
    Provider("Ghost", (".ghost.io",),
             ("The thing you were looking for is no longer here",)),
    Provider("Netlify", (".netlify.app", ".netlify.com"),
             ("Not Found - Request ID",)),
    Provider("Surge", (".surge.sh",),
             ("project not found",)),
    Provider("Bitbucket", (".bitbucket.io",),
             ("Repository not found",)),
    Provider("Webflow", (".webflow.io",),
             ("The page you are looking for doesn't exist or has been moved",)),
    Provider("Readme", (".readme.io", ".readmessl.com"),
             ("Project doesnt exist... yet!",)),
    Provider("Statuspage", (".statuspage.io",),
             ("You are being <a href=\"https://www.statuspage.io\">redirected",)),
    Provider("Unbounce", (".unbouncepages.com",),
             ("The requested URL was not found on this server",)),
    Provider("Helpjuice", (".helpjuice.com",), ("We could not find what you're looking for",)),
    Provider("Help Scout", (".helpscoutdocs.com",), ("No settings were found for this company",)),
    Provider("Cargo", (".cargocollective.com",), ("404 Not Found",)),
    Provider("Acquia", (".acquia-sites.com",),
             ("The site you are looking for could not be found",)),
    Provider("Campaign Monitor", (".createsend.com",),
             ("Trying to access your account?",)),
    Provider("Desk", (".desk.com",), ("Sorry, We Couldn't Find That Page",)),
    Provider("Teamwork", (".teamwork.com",), ("Oops - We didn't find your site",)),
    # AWS Elastic Beanstalk and CloudFront dangle often, but the name
    # is not freely re-registerable the way an S3 bucket is: you have
    # to win a region-wide race or control the distribution. Recorded
    # so the record gets cleaned up, flagged so nobody writes it up as
    # an exploitable takeover without checking.
    # Added after a live sweep: the first real CNAME chain collected
    # on an engagement ended at
    # `...elb.ap-southeast-1.amazonaws.com` and matched nothing,
    # because AWS spells load balancers two ways and BOTH put the
    # region where a suffix cannot see it:
    #
    #   name-123.eu-west-1.elb.amazonaws.com   (current)
    #   name-123.elb.eu-west-1.amazonaws.com   (also in the wild)
    #
    # Not claimable. An ELB name carries an AWS-assigned random
    # suffix, so nobody can re-register that exact name -- the record
    # still dangles and should still go, but calling it an
    # exploitable takeover would overstate it.
    Provider("AWS ELB", (),
             patterns=(re.compile(r"\.elb\.[a-z0-9-]+\.amazonaws\.com$"),
                       re.compile(r"\.[a-z0-9-]+\.elb\.amazonaws\.com$"),
                       re.compile(r"\.elb\.amazonaws\.com$")),
             claimable=False),
    Provider("AWS Elastic Beanstalk",
             (".elasticbeanstalk.com",), (), claimable=False),
    Provider("AWS CloudFront", (".cloudfront.net",),
             ("ERROR: The request could not be satisfied",), claimable=False),
)


def provider_for(cname: str) -> Provider | None:
    """Which provider a CNAME lands on, or None.

    Suffix match on a normalised name. A CNAME is compared with its
    trailing dot stripped and lowercased, because resolvers and tools
    disagree about both and `shop.myshopify.com.` is the same answer
    as `shop.myshopify.com`.
    """
    c = (cname or "").strip().lower().rstrip(".")
    if not c:
        return None
    for p in PROVIDERS:
        if any(c.endswith(suf) for suf in p.suffixes):
            return p
        if any(rx.search(c) for rx in p.patterns):
            return p
    return None


def fingerprint_hit(provider: Provider, body: str | None) -> str | None:
    """The provider's unclaimed-page marker found in a body, or None.

    Returns the marker that matched so the finding can say which one
    it was. An operator reading "fingerprint" with no quote has to go
    and fetch the page again to learn anything.
    """
    if not body or not provider.fingerprints:
        return None
    for f in provider.fingerprints:
        if f.lower() in body.lower():
            return f
    return None


#: A CNAME chain httpx reports as a list; the last hop is the one that
#: decides the provider, but an intermediate hop can be the dangling
#: one. Both are checked, nearest-to-the-target first.
def chain(value) -> list[str]:
    """Normalise whatever the importer stored into a list of names."""
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    out: list[str] = []
    for v in value:
        s = str(v).strip().lower().rstrip(".")
        if s and s not in out:
            out.append(s)
    return out


_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def resolvable_name(n: str) -> bool:
    """Whether a string is shaped like something worth resolving.

    Guards the resolver against the junk that reaches this path --
    empty strings, bare dots, and the `.` root some tools emit for "no
    CNAME" -- so a lookup failure means the name really did not
    resolve rather than that it was never a name.
    """
    n = (n or "").strip().lower().rstrip(".")
    if not n or "." not in n or len(n) > 253:
        return False
    return all(_LABEL.match(part) for part in n.split("."))


# ---------------------------------------------------------------- detect
# Everything below touches the database. The matching above does not,
# so the decision that matters stays a pure function and is tested as
# one.

@dataclass
class Candidate:
    """One decided row, before it meets the table."""
    hostname: str
    cname: str
    chain: list[str]
    provider: str
    claimable: bool
    verdict: str
    evidence: str | None


def decide(hostname: str, cnames, bodies: list[str] | None = None,
           unresolved: set[str] | None = None) -> Candidate | None:
    """Rule on one host's CNAME chain.

    Pure. `bodies` are responses already captured from this host and
    `unresolved` is the set of names a lookup has reported as
    answering nothing. Both are evidence we happen to hold -- neither
    is fetched here, because the server does no network work on an
    engagement's behalf; the ghosts do, and this reads what they
    brought back.

    Returns None when no hop lands on a provider at all, which is the
    overwhelmingly common case and not a finding.
    """
    hops = chain(cnames)
    if not hops:
        return None
    unresolved = unresolved or set()

    for hop in hops:
        p = provider_for(hop)
        if p is None:
            continue
        # Strongest first. A chain that reached a name nothing
        # resolves is the one case where the record is provably
        # pointing at nothing, whoever owns it.
        if hop in unresolved:
            return Candidate(hostname, hop, hops, p.name, p.claimable,
                             "dangling", f"{hop} did not resolve")
        for body in (bodies or []):
            if hit := fingerprint_hit(p, body):
                return Candidate(hostname, hop, hops, p.name, p.claimable,
                                 "fingerprint", hit)
        return Candidate(hostname, hop, hops, p.name, p.claimable,
                         "candidate", None)
    return None


#: Which rows become a finding, and at what severity.
#:
#: Keyed on `claimable`, because that is the question a reader of the
#: report is actually asking. A record pointing at a provider surface
#: nobody can re-register is a cleanup job; one pointing at a surface
#: anyone can claim is somebody else's foothold on the client's
#: domain, and the two must not arrive in a report wearing the same
#: colour.
SEVERITY_BY_CLAIMABLE: dict[bool, str] = {
    False: "low",
    True: "high",
}

#: Which verdicts are worth raising at all.
#:
#: **This is the dial.** Set to `VERDICTS` and every row becomes a
#: finding, including `candidate` -- which on a real estate means a
#: Low for every host whose CNAME points at a load balancer, i.e. for
#: normal, healthy infrastructure. Narrowed to the two evidenced
#: verdicts it raises only records something actually showed to be
#: dangling or unclaimed.
#:
#: Currently all three, because the operator asked for the rows they
#: were looking at -- which were `candidate` -- to be raised. The
#: noise that implies is the reason this is one named constant and
#: not a condition buried in the loop below.
RAISE_VERDICTS: tuple[str, ...] = VERDICTS

#: `external_id` prefix. Vulns are matched on this, so a refresh
#: updates a finding in place instead of forking a duplicate every
#: time it runs -- which, for something that re-derives on every
#: pass, is the difference between a findings list and a pile.
VULN_PREFIX = "takeover:"


def vuln_title(c: Candidate) -> str:
    return f"Dangling DNS record pointing at {c.provider}: {c.hostname}"


def vuln_description(c: Candidate) -> str:
    """What the row claims, in the words the verdict actually supports."""
    chain = " -> ".join(c.chain) if c.chain else c.cname
    why = {
        "dangling": f"The chain reached a name that does not resolve "
                    f"({c.evidence}). The record points at nothing.",
        "fingerprint": f"{c.provider} served its own unclaimed-resource page "
                       f"(matched: {c.evidence!r}).",
        "candidate": "Neither check could be run against this host, so this "
                     "is a record to go and look at rather than a confirmed "
                     "dangling one. It is reported because the name it "
                     "points at is a provider surface, not because anything "
                     "showed it to be unclaimed.",
    }[c.verdict]
    claim = (
        "The name this points at is assigned by the provider and cannot be "
        "re-registered by anyone else, so this is a hygiene finding: the "
        "record should be removed, but it is not an exploitable takeover."
        if not c.claimable else
        "The name this points at can be registered by whoever asks for it "
        "first. If it is unclaimed, somebody else can serve content on this "
        "hostname, with this domain's TLS story and its cookies."
    )
    return (f"{c.hostname} resolves through {chain}.\n\n{why}\n\n{claim}\n\n"
            f"Verdict: {c.verdict}. Provider: {c.provider}. "
            f"Claimable: {c.claimable}.")


REMEDIATION = (
    "Remove the DNS record if the resource behind it is gone. If it is still "
    "wanted, re-create the resource at the provider and confirm it answers "
    "before leaving the record in place."
)


async def _sync_vulns(session, project_id: int,
                      decided: dict[str, tuple[int, Candidate]]) -> int:
    """Raise a finding for each takeover worth one. -> how many are open.

    Idempotent on `external_id`, so running the detector hourly does
    not produce a finding per hour. An operator's `triage` and
    `status` are never overwritten: the detector reports what DNS
    says, and what a person concluded about it is theirs.

    A record that has since been cleaned up has its finding CLOSED
    rather than deleted. Deleting it would erase the evidence that it
    was ever there, and "we found this and it was fixed" is a thing a
    report should be able to say.
    """
    from sqlalchemy import select as _select

    from .models import Vuln

    wanted = {h: c for h, (_, c) in decided.items()
              if c.verdict in RAISE_VERDICTS}

    existing = {v.external_id: v for v in (await session.execute(
        _select(Vuln).join(Vuln.target)
        .where(Vuln.external_id.like(f"{VULN_PREFIX}%"))
        .where(Vuln.target.has(project_id=project_id)))).scalars().all()}

    open_now = 0
    for host, c in wanted.items():
        tid = decided[host][0]
        key = f"{VULN_PREFIX}{host}"
        sev = SEVERITY_BY_CLAIMABLE[bool(c.claimable)]
        v = existing.get(key)
        if v is None:
            session.add(Vuln(
                target_id=tid, title=vuln_title(c), severity=sev,
                status="open", description=vuln_description(c),
                remediation=REMEDIATION, remediation_source="scanner",
                external_id=key))
        else:
            # Facts about DNS are refreshed. `triage` and `status` are
            # not: those are the operator's.
            v.target_id = tid
            v.title = vuln_title(c)
            v.severity = sev
            v.description = vuln_description(c)
            v.remediation = REMEDIATION
        open_now += 1

    # Gone from DNS: close, do not delete.
    for key, v in existing.items():
        if key[len(VULN_PREFIX):] not in wanted and v.status == "open":
            v.status = "closed"
    await session.flush()
    return open_now


@dataclass
class Refreshed:
    """What one detector pass did.

    The vuln count is a FIELD and not another entry in `counts`. It
    lived in there briefly and the endpoint's `sum(counts.values())`
    promptly reported eight takeovers when there were four -- a
    number nobody could have checked without reading this function,
    which is the sort of wrong a findings page should not be able to
    show.
    """
    #: {verdict: how many rows}. Verdicts only.
    counts: dict[str, int] = field(default_factory=dict)
    #: How many findings are open as a result.
    vulns: int = 0

    @property
    def total(self) -> int:
        return sum(self.counts.values())


async def refresh(session, project_id: int) -> Refreshed:
    """Re-derive this project's takeover rows.

    Re-derived rather than accumulated, because a dangling record that
    somebody finally deleted should stop being a finding. The operator
    decisions that must survive that -- `state` and `note` -- are read
    back and reapplied; everything else is whatever DNS says today.
    """
    import json as _json

    from sqlalchemy import delete as _delete
    from sqlalchemy import select as _select

    from .lookuphistory import answered_empty
    from .models import Takeover, Target, WebAddress

    rows = (await session.execute(
        _select(Target.id, Target.host, Target.extra)
        .where(Target.project_id == project_id,
               Target.extra.isnot(None)))).all()

    # Pass one: who points at a provider at all. Cheap, and it decides
    # which hosts are worth gathering bodies for -- an engagement
    # holds hundreds of thousands of captured responses and loading
    # them for every host to check a handful would be the expensive
    # mistake here.
    interesting: list[tuple[int, str, list[str]]] = []
    for tid, host, extra in rows:
        if not host:
            continue
        try:
            ex = _json.loads(extra) or {}
        except (ValueError, TypeError):
            continue
        hops = chain((ex.get("httpx") or {}).get("cname"))
        if hops and any(provider_for(h) for h in hops):
            interesting.append((tid, host.strip().lower(), hops))

    if not interesting:
        await session.execute(
            _delete(Takeover).where(Takeover.project_id == project_id))
        # Still syncs: a project whose last dangling record was fixed
        # must have its findings closed, not merely stop gaining new
        # ones.
        return Refreshed(counts={},
                         vulns=await _sync_vulns(session, project_id, {}))

    # The two evidence sources, fetched once for the whole set.
    every_hop = sorted({h for _, _, hops in interesting for h in hops})
    empty = await answered_empty(session, project_id, "nslookup", every_hop)
    unresolved = set(empty)

    tids = [t for t, _, _ in interesting]
    bodies: dict[int, list[str]] = {}
    for tid, body in (await session.execute(
            _select(WebAddress.target_id, WebAddress.response)
            .where(WebAddress.target_id.in_(tids),
                   WebAddress.response.isnot(None)))).all():
        # Only the head of each response. A provider's "nothing is
        # here" page says so in the first screenful, and these rows
        # run to two megabytes apiece.
        bodies.setdefault(tid, []).append(str(body)[:8000])

    decided: dict[str, tuple[int, Candidate]] = {}
    for tid, host, hops in interesting:
        c = decide(host, hops, bodies.get(tid), unresolved)
        if c is not None:
            decided[host] = (tid, c)

    # Operator decisions survive the rebuild; DNS facts do not.
    keep = {h: (s, n) for h, s, n in (await session.execute(
        _select(Takeover.hostname, Takeover.state, Takeover.note)
        .where(Takeover.project_id == project_id))).all()}

    await session.execute(
        _delete(Takeover).where(Takeover.project_id == project_id))

    now = datetime.now(UTC)
    counts: dict[str, int] = {}
    for host, (tid, c) in decided.items():
        state, note = keep.get(host, ("needs_investigating", None))
        session.add(Takeover(
            project_id=project_id, target_id=tid, hostname=c.hostname,
            cname=c.cname, cname_chain="\n".join(c.chain),
            provider=c.provider, claimable=c.claimable,
            verdict=c.verdict, evidence=c.evidence,
            state=state, note=note, seen_at=now))
        counts[c.verdict] = counts.get(c.verdict, 0) + 1
    await session.flush()
    # Findings are part of the same pass deliberately. A detector that
    # writes its own table and leaves raising the finding to somebody
    # else is a detector whose output nobody reads.
    return Refreshed(counts=counts,
                     vulns=await _sync_vulns(session, project_id, decided))
