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

#: How strong the evidence is, strongest first -- NOT how bad the
#: finding is, and not all in the same direction. `dangling` and
#: `fingerprint` are evidence a name is unclaimed; `live` is evidence
#: it is claimed and serving, which is just as conclusive and is the
#: answer most of the time; `candidate` is the absence of any of the
#: three. `Takeover.verdict` holds one.
VERDICTS = ("dangling", "fingerprint", "live", "candidate")


#: How hard it is to ACTUALLY take the name, easiest first.
#:
#: This is a property of the PROVIDER's claim process, not of how
#: certain we are -- those are two different questions and the second
#: one caps the first (see `difficulty_for`).
#:
#: **Judged, not measured, and deliberately so.** Measuring it would
#: mean attempting the registration: creating the bucket, claiming the
#: repo, pointing the service at a client's hostname. That is taking
#: control of a name in somebody else's namespace, which is a
#: different act from assessing it and is not something a scanner
#: should do unattended on the strength of a DNS record. So each
#: provider carries a documented judgement and the steps an operator
#: would follow to do it deliberately, which is `Provider.steps`.
DIFFICULTIES = ("easy", "medium", "hard", "impossible")

#: What a difficulty means for the finding's severity.
#:
#: The mapping the operator asked for. It is one named constant
#: because the ratio of report noise to signal lives here: moving
#: `hard` from medium to low would quieten a report by a third.
DIFFICULTY_SEVERITY: dict[str, str] = {
    "easy": "critical",
    "medium": "high",
    "hard": "medium",
    "impossible": "low",
}


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
    #: What the provider serves when the resource IS claimed and
    #: running. The opposite of `fingerprints`, and the reason this
    #: exists: without it, "the page was not the unclaimed one" is the
    #: only thing we can say, which reads as doubt when it is often a
    #: clear negative. A WAF block or a 405 from a CDN is served BY
    #: the distribution, so the distribution exists.
    live: tuple[str, ...] = ()
    #: Only believe `fingerprints` on a response fetched over TLS.
    #:
    #: Measured, not assumed. On a live engagement every one of the
    #: thirteen CloudFront "unclaimed" hits came from a plaintext
    #: request, and the SAME hostname over https returned the
    #: distribution's WAF page -- i.e. the distribution existed and
    #: was serving. Port 80 to CloudFront answers `Bad request.` for
    #: reasons that have nothing to do with whether the name is
    #: claimed, so a plaintext body cannot convict a provider that
    #: routes on SNI.
    tls_only: bool = False
    #: How hard the claim is on THIS provider, before evidence is
    #: considered. `impossible` is not a synonym for `claimable=False`
    #: -- it is what that flag means in this vocabulary, and the two
    #: are kept consistent by `__post_init__` rather than by hand.
    difficulty: str = "medium"
    #: What an operator would actually do, in order. Shown whatever
    #: the difficulty, including `impossible`, because "why can I not
    #: take this" is the question an impossible row raises and a row
    #: that only says "impossible" does not answer it.
    steps: tuple[str, ...] = ()
    #: A string the body must contain before ANY fingerprint of this
    #: provider counts. Keeps a short marker -- `Bad request.` is four
    #: words that appear on a thousand error pages -- from matching a
    #: page this provider did not serve.
    guard: str = ""


#: Kept deliberately short and accurate rather than exhaustive. Every
#: entry here has been a real takeover; a long list copied wholesale
#: from a public repo brings along providers that closed the hole
#: years ago, and a false positive on this check costs an operator a
#: morning proving a live site belongs to the client.
PROVIDERS: tuple[Provider, ...] = (
    # Easiest of the lot: a bucket name is global, free and
    # first-come, and the console will take it the moment it is free.
    Provider("AWS S3", (".s3.amazonaws.com",),
             ("NoSuchBucket", "The specified bucket does not exist"),
             difficulty="easy",
             steps=("Confirm the bucket is gone: `aws s3api head-bucket "
                    "--bucket <name>` returns 404, not 403.",
                    "Create a bucket with the EXACT name from the CNAME, "
                    "in the region the hostname encodes.",
                    "Enable static website hosting and upload an index.html.",
                    "The client's hostname now serves your content over "
                    "http. https needs their certificate, so TLS is the "
                    "limit of the impact here."),
             patterns=(
                 # The region sits between the marker and the domain:
                 # `.s3-website-eu-west-1.amazonaws.com`.
                 re.compile(r"\.s3-website[.-]"),
                 re.compile(r"\.s3\.dualstack\."),
                 re.compile(r"\.s3-external-"),
             )),
    # Free, instant, and GitHub will serve TLS for the custom domain
    # once it is claimed -- which makes this worse than S3, not better.
    Provider("GitHub Pages", (".github.io",),
             ("There isn't a GitHub Pages site here",
              "For root URLs (like http://example.com/) you must provide an index.html file"),
             difficulty="easy",
             steps=("Create any repository and enable GitHub Pages on it.",
                    "Add the client's hostname as the Pages custom domain, "
                    "or commit it to a CNAME file at the repo root.",
                    "GitHub matches on the CNAME target, so no DNS change "
                    "of yours is needed -- theirs already points here.",
                    "Let GitHub issue a Let's Encrypt certificate for the "
                    "name. The result is a trusted-TLS site on the "
                    "client's domain.")),
    # App names are global and free to claim, but Heroku ended free
    # dynos: serving anything needs a paid plan and a verified card.
    Provider("Heroku", (".herokuapp.com", ".herokudns.com", ".herokussl.com"),
             ("No such app", "herokucdn.com/error-pages/no-such-app.html"),
             difficulty="medium",
             steps=("Create the app under the EXACT name in the CNAME: "
                    "`heroku apps:create <name>`.",
                    "Add a verified payment method -- free dynos are gone, "
                    "so nothing serves without a paid plan.",
                    "`heroku domains:add <client-hostname>`.",
                    "Deploy anything. The client's record already points "
                    "at the app you now own.")),
    # Seven very different surfaces under one name, and they are not
    # equally takeable: an App Service name is global and free to
    # claim, while a Front Door or Traffic Manager profile needs the
    # subscription and in some cases domain validation. Rated for the
    # harder end on purpose -- overstating difficulty costs a check,
    # understating it puts a critical in a report that cannot be
    # demonstrated.
    Provider("Azure", (".azurewebsites.net", ".cloudapp.azure.com",
                       ".cloudapp.net", ".trafficmanager.net",
                       ".blob.core.windows.net", ".azureedge.net",
                       ".azurefd.net"),
             ("404 Web Site not found", "Error 404 - Web app not found"),
             difficulty="hard",
             steps=("Identify WHICH Azure surface the CNAME lands on -- "
                    "App Service, Storage, CDN, Front Door and Traffic "
                    "Manager all end up under this provider and differ.",
                    "For App Service or Storage: create a resource with the "
                    "exact name from the CNAME in any subscription.",
                    "For Front Door or Traffic Manager: the profile name "
                    "must be free AND recent Azure requires a DNS TXT "
                    "validation record, which the client controls -- that "
                    "is usually what makes this fail.",
                    "Add the client's hostname as a custom domain on the "
                    "resource.")),
    # The store name is claimable on a trial, but attaching a custom
    # domain needs a paid plan -- and Shopify checks the DNS.
    Provider("Shopify", (".myshopify.com",),
             ("Sorry, this shop is currently unavailable",
              "Only one step left!"),
             difficulty="medium",
             steps=("Start a Shopify trial and take the store handle from "
                    "the CNAME target.",
                    "A paid plan is required before a custom domain can be "
                    "connected.",
                    "Settings -> Domains -> Connect existing domain, and "
                    "enter the client's hostname.")),
    # A Fastly service will happily answer for any domain added to
    # it, but getting an account that can is not a self-serve minute:
    # billing details, and in practice a sales conversation.
    Provider("Fastly", (".fastly.net", ".fastlylb.net"),
             ("Fastly error: unknown domain",),
             difficulty="hard",
             steps=("Obtain a Fastly account with service-creation rights.",
                    "Create a service and add the client's hostname as a "
                    "domain on it.",
                    "Point the service at an origin you control and "
                    "activate the version.",
                    "No DNS change is needed -- the client's CNAME already "
                    "resolves into Fastly's network.")),
    Provider("Pantheon", (".pantheonsite.io",),
             ("The gods are wise",),
             difficulty="medium",
             steps=("Create a Pantheon sandbox site.",
                    "The platform domain is assigned per environment, so "
                    "the site name has to match the CNAME target.",
                    "Add the client's hostname under Domains/HTTPS, which "
                    "requires a paid plan on most tiers.")),
    Provider("Zendesk", (".zendesk.com",),
             ("Help Center Closed",),
             difficulty="medium",
             steps=("Register a Zendesk trial on the subdomain named in "
                    "the CNAME, if it is free.",
                    "Enable Guide (the help centre) so something is served.",
                    "Host mapping for a custom domain is a paid feature, "
                    "and Zendesk verifies the CNAME.")),
    Provider("Tumblr", (".tumblr.com",),
             ("Whatever you were looking for doesn't currently exist at this address",),
             difficulty="easy",
             steps=("Register a free Tumblr blog.",
                    "Blog Settings -> Custom domain -> enter the client's "
                    "hostname.",
                    "Tumblr checks the CNAME points at Tumblr, which it "
                    "already does, and accepts it.")),
    Provider("WordPress", (".wordpress.com",),
             ("Do you want to register",),
             difficulty="medium",
             steps=("Register the free blog at the CNAME target's name.",
                    "Mapping a custom domain onto it needs a paid plan.",
                    "Add the client's hostname as a mapped domain.")),
    Provider("Ghost", (".ghost.io",),
             ("The thing you were looking for is no longer here",)),
    Provider("Netlify", (".netlify.app", ".netlify.com"),
             ("Not Found - Request ID",),
             difficulty="easy",
             steps=("Create a free Netlify site.",
                    "Domain management -> add the client's hostname as a "
                    "custom domain. Netlify accepts it when the CNAME "
                    "already resolves to Netlify.",
                    "Netlify provisions TLS for it automatically.")),
    # `npm i -g surge && surge ./dir <hostname>` and it is done. No
    # web console, no verification, no payment.
    Provider("Surge", (".surge.sh",),
             ("project not found",),
             difficulty="easy",
             steps=("`npm install -g surge`",
                    "Put an index.html in a directory.",
                    "`surge ./that-directory <client-hostname>` -- surge "
                    "claims any domain whose CNAME already points at it.")),
    Provider("Bitbucket", (".bitbucket.io",),
             ("Repository not found",),
             difficulty="easy",
             steps=("Create a free Bitbucket account and a repository "
                    "named exactly for the CNAME target.",
                    "Publish static content to it.",
                    "Bitbucket serves the repo at that name, which is "
                    "where the client's record points.")),
    Provider("Webflow", (".webflow.io",),
             ("The page you are looking for doesn't exist or has been moved",)),
    Provider("Readme", (".readme.io", ".readmessl.com"),
             ("Project doesnt exist... yet!",)),
    Provider("Statuspage", (".statuspage.io",),
             ("You are being <a href=\"https://www.statuspage.io\">redirected",),
             difficulty="medium",
             steps=("Create a Statuspage account and take the page "
                    "subdomain from the CNAME target.",
                    "A custom domain is a paid feature.",
                    "Add the client's hostname; Statuspage verifies the "
                    "CNAME already points at it.")),
    Provider("Unbounce", (".unbouncepages.com",),
             ("The requested URL was not found on this server",)),
    Provider("Helpjuice", (".helpjuice.com",), ("We could not find what you're looking for",)),
    Provider("Help Scout", (".helpscoutdocs.com",), ("No settings were found for this company",)),
    Provider("Cargo", (".cargocollective.com",), ("404 Not Found",)),
    Provider("Acquia", (".acquia-sites.com",),
             ("The site you are looking for could not be found",),
             difficulty="hard",
             steps=("Acquia Cloud is enterprise-onboarded; there is no "
                    "self-serve path to a matching site name.",
                    "A takeover here realistically needs an existing "
                    "Acquia subscription.",
                    "Treat the dangling record as hygiene unless you "
                    "already hold such an account.")),
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
             claimable=False, difficulty="impossible",
             steps=("You cannot take this name. AWS assigns the random "
                    "suffix in an ELB hostname, so the exact name cannot "
                    "be re-registered by anyone.",
                    "It is still a real defect: the record points at "
                    "nothing and should be removed, and until it is, it "
                    "misleads anyone reading the client's DNS.",
                    "Report as DNS hygiene, not as an exploitable "
                    "takeover. Writing it up as the latter is the error "
                    "this rating exists to prevent.")),
    Provider("AWS Elastic Beanstalk",
             (".elasticbeanstalk.com",), (), claimable=False,
             difficulty="impossible",
             steps=("Beanstalk CNAMEs are allocated per region and are "
                    "not freely re-registerable by an outsider.",
                    "Remove the dangling record; do not report it as an "
                    "exploitable takeover.")),
    # CloudFront says "ERROR: The request could not be satisfied" for
    # at least four unrelated reasons, and that string was this
    # table's fingerprint until a live engagement showed what it
    # actually catches. Thirteen hostnames matched it. Reading the
    # bodies back:
    #
    #   17 captures  Request blocked.                     (WAF)
    #    5 captures  Bad request.                         (no distribution)
    #    4 captures  ...does not allow the HTTP method    (live, 405)
    #    3 captures  ...blocked access from your country  (live, geo)
    #
    # Three of those four are served BY a distribution, so they prove
    # the opposite of a takeover. And every single `Bad request.`
    # came over http://, while the same hostname over https://
    # returned the WAF page -- so even the one discriminating string
    # was, in this data, an artefact of asking port 80.
    #
    # Hence all three guards at once: match only the sentence that
    # means "no distribution has this name", only on a body that
    # CloudFront visibly generated, and only over TLS.
    Provider("AWS CloudFront", (".cloudfront.net",),
             ("Bad request.",),
             live=("Request blocked.",
                   "not configured to allow the HTTP request method",
                   "configured to block access from your country",
                   "CloudFront attempted to establish a connection with the "
                   "origin"),
             tls_only=True, guard="Generated by cloudfront",
             claimable=False, difficulty="impossible",
             steps=("A CloudFront distribution domain is assigned by AWS. "
                    "Nobody can create a distribution with an existing "
                    "name, so the name itself cannot be taken.",
                    "Adding the client's hostname as an alternate domain "
                    "name on YOUR distribution requires a certificate "
                    "covering it, which means control of the client's "
                    "domain -- i.e. this is not a path in.",
                    "Remove the record. Report as hygiene.")),
)


#: `claimable=False` and `difficulty="impossible"` say the same thing
#: in two vocabularies, and a provider added later will set one and
#: forget the other. Checked at import rather than trusted: a table
#: that disagrees with itself would rate a name both unclaimable and
#: easy, and one of those would reach a report.
#: By name, for looking a decided row's provider back up. The
#: Candidate carries the NAME rather than the object, because it is
#: serialised into the database and a dataclass is not.
_BY_NAME: dict[str, Provider] = {p.name: p for p in PROVIDERS}


def _check_provider_table() -> None:
    for p in PROVIDERS:
        if p.difficulty not in DIFFICULTIES:
            raise ValueError(
                f"{p.name}: difficulty {p.difficulty!r} is not one of "
                f"{DIFFICULTIES}")
        if not p.claimable and p.difficulty != "impossible":
            raise ValueError(
                f"{p.name}: claimable=False but difficulty="
                f"{p.difficulty!r} -- a name nobody can register is not "
                f"takeable at any difficulty")
        if p.claimable and p.difficulty == "impossible":
            raise ValueError(
                f"{p.name}: difficulty=impossible but claimable=True")


_check_provider_table()


def difficulty_for(c: Candidate) -> str:
    """How hard it would actually be to take this name.

    Two inputs, and as with `severity_for` the ORDER is the point.

    The provider's claim process sets the baseline: an S3 bucket is a
    free global name anyone can create, a CloudFront distribution
    domain is assigned by AWS and cannot be created at all.

    **Evidence caps it.** A `candidate` is a name whose CNAME points
    at a takeable provider and which nothing has checked -- we do not
    know it is unclaimed. Taking it would mean first establishing
    that, and an unverified row must not outrank a proven one, which
    is the same inversion `SEVERITY` was rewritten to remove. So a
    candidate is never better than `hard`, however easy the provider.

    `live` is the finished answer in the other direction: the name
    resolves and the provider is serving it, so there is nothing to
    take.
    """
    if not c.claimable:
        return "impossible"
    if c.verdict == "live":
        return "impossible"
    p = _BY_NAME.get(c.provider)
    base = p.difficulty if p else "medium"
    # Only an EVIDENCED verdict earns the provider's own difficulty.
    # `candidate` is the absence of evidence; so is any verdict this
    # module has not met, and treating the latter as evidence is how
    # an unexamined row reaches the top of a report. Asserted in
    # webtest, which is where this came from: keyed on `candidate`
    # alone, a verdict of "something-new" on AWS S3 scored critical.
    if c.verdict not in ("dangling", "fingerprint"):
        # Not "set to hard" -- take the WORSE of the two, so a
        # provider already rated impossible is not promoted by having
        # been checked less.
        return max(base, "hard", key=DIFFICULTIES.index)
    return base


def steps_for(c: Candidate) -> list[str]:
    """What an operator would do, in order.

    Shown whatever the difficulty. "Impossible" raises the question
    "why not", and a row that only says impossible does not answer
    it -- so those providers carry the reason and what to do instead.
    """
    p = _BY_NAME.get(c.provider)
    steps = list(p.steps) if p and p.steps else []
    if not steps:
        steps = [
            f"No claim procedure is recorded for {c.provider} in "
            f"app/takeover.py. Treat the difficulty as unverified and "
            f"check the provider's own documentation before reporting "
            f"this as exploitable.",
        ]
    # Same rule as `difficulty_for`: anything that is not an evidenced
    # verdict is unevidenced, including one this module has not met.
    if c.verdict not in ("dangling", "fingerprint"):
        # First, because it is the step that has to happen before any
        # of the others mean anything.
        steps = [
            "FIRST establish the name is actually unclaimed. Nothing here "
            "has shown that it is: neither the dangling check nor the "
            "provider fingerprint could be run, so the CNAME pointing at "
            "this provider is all that is known.",
        ] + steps
    return steps


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


@dataclass(frozen=True)
class Capture:
    """One response body, and whether it came back over TLS.

    The scheme is here because it changes what a body is allowed to
    prove. A provider that routes on SNI -- CloudFront, Azure Front
    Door, Fastly -- cannot tell which name a plaintext request was
    for beyond the Host header, and answers some of them with the
    same page it serves for a name nobody has claimed. Reading a
    takeover out of that is reading a property of port 80.

    `secure=None` means the caller did not say. It is treated as "not
    known to be TLS", which is the conservative reading: an unmarked
    body cannot convict a `tls_only` provider.
    """
    text: str
    secure: bool | None = None


def captures(bodies) -> list[Capture]:
    """Normalise whatever a caller passed into `Capture`s.

    Plain strings are accepted and marked scheme-unknown, because
    most providers do not care and a test that says `bodies=["No
    such app"]` should keep meaning what it meant.
    """
    out: list[Capture] = []
    for b in bodies or []:
        if isinstance(b, Capture):
            out.append(b)
        elif isinstance(b, str):
            out.append(Capture(b))
        elif isinstance(b, (tuple, list)) and len(b) == 2:
            # (secure, text), the shape `refresh` builds.
            out.append(Capture(str(b[1]), bool(b[0])))
    return out


def _marker_in(markers: tuple[str, ...], text: str) -> str | None:
    low = text.lower()
    for m in markers:
        if m.lower() in low:
            return m
    return None


def fingerprint_hit(provider: Provider, body) -> str | None:
    """The provider's unclaimed-page marker found in a body, or None.

    Returns the marker that matched so the finding can say which one
    it was. An operator reading "fingerprint" with no quote has to go
    and fetch the page again to learn anything.

    Two things can stop a match that the string alone would make:
    `tls_only`, when the body did not come back over TLS, and
    `guard`, when the body does not carry the provider's own
    signature. Both were added after a sweep in which this function
    returned thirteen matches and every one of them was a live site.
    """
    c = body if isinstance(body, Capture) else Capture(body or "")
    if not c.text or not provider.fingerprints:
        return None
    if provider.tls_only and c.secure is not True:
        return None
    if provider.guard and provider.guard.lower() not in c.text.lower():
        return None
    return _marker_in(provider.fingerprints, c.text)


def live_hit(provider: Provider, body) -> str | None:
    """A marker proving the resource IS claimed and serving, or None.

    Not scheme-gated. A WAF page or a 405 is generated by the
    resource itself, so receiving one over plaintext proves the
    resource exists just as well as receiving it over TLS -- the
    asymmetry with `fingerprint_hit` is the point, because absence of
    a thing is what plaintext cannot establish.
    """
    c = body if isinstance(body, Capture) else Capture(body or "")
    if not c.text or not provider.live:
        return None
    if provider.guard and provider.guard.lower() not in c.text.lower():
        return None
    return _marker_in(provider.live, c.text)


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
           unresolved: set[str] | None = None,
           resolved: set[str] | None = None) -> Candidate | None:
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
    resolved = resolved or set()
    caps = captures(bodies)

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

        fp = next((h for c in caps if (h := fingerprint_hit(p, c))), None)
        lv = next((h for c in caps if (h := live_hit(p, c))), None)

        # Both. One capture says the resource is gone and another
        # says it is serving, which is not a verdict -- it is two
        # observations that cannot both be describing the same
        # moment. Reported as undetermined, saying so, because
        # picking the louder one here is how the thirteen false
        # positives got written in the first place.
        if fp and lv:
            return Candidate(
                hostname, hop, hops, p.name, p.claimable, "candidate",
                f"the evidence disagrees with itself: one response from "
                f"this host matched {p.name}'s unclaimed page "
                f"({fp!r}) and another showed it serving ({lv!r}). "
                f"Re-fetch over https and run a DNS lookup against {hop}.")
        if fp:
            return Candidate(hostname, hop, hops, p.name, p.claimable,
                             "fingerprint", fp)
        # A clear negative, and worth saying so. Most names on this
        # table are healthy infrastructure, and a row that reads
        # "could not determine" for a host we watched answer is a row
        # that wastes somebody's morning.
        if lv:
            return Candidate(
                hostname, hop, hops, p.name, p.claimable, "live",
                f"{p.name} served {lv!r}, which only a resource that "
                f"exists can serve. The name is claimed.")
        return Candidate(hostname, hop, hops, p.name, p.claimable,
                         "candidate", undetermined(p, hop, caps,
                                                   hop in resolved))
    return None


def undetermined(p: Provider, hop: str, caps: list[Capture],
                 hop_resolves: bool = False) -> str:
    """Why neither check could convict, in terms of what is missing.

    "Could not determine" on its own tells a reader that a
    conclusion is absent without telling them what is absent, which
    is the one thing they need to know to go and settle it. Each of
    these sentences implies a different next action, and they are
    genuinely different situations rather than shades of one.
    """
    had_bodies = bool(caps)
    # What the DNS half actually knows, in the reader's words.
    #
    # Three states, and the middle one used to be written as the
    # first: "no lookup has reported this as empty" is true BOTH of a
    # name nobody has looked up and of a name that resolved an hour
    # ago. Telling a reader the check has not happened when it has is
    # the same mistake this whole file exists to avoid.
    #
    # A hop that resolves is not proof the resource is claimed --
    # several of these providers answer for names nobody has taken,
    # which is the entire reason subdomain takeover works -- so this
    # says what was observed and stops there.
    dns = (f"a DNS lookup of {hop} answered with addresses, so the "
           f"chain does not end in a name that fails to resolve"
           if hop_resolves else
           f"no lookup has reported {hop} as empty")
    # The case `tls_only` created: we hold pages from this host, but
    # every one of them came over plaintext and plaintext cannot
    # settle a provider that routes on SNI. Saying "nothing was
    # fetched" would be false and saying "the page was not the
    # unclaimed one" would be worse -- it would imply we looked.
    if (p.tls_only and p.fingerprints and had_bodies
            and not any(c.secure for c in caps)):
        return (f"every response held from this host came over http, and "
                f"{p.name} routes on the TLS name — a plaintext answer "
                f"from it says nothing about whether {hop} is claimed. "
                f"Fetch this host over https and re-run, or run a DNS "
                f"lookup against {hop}.")
    if not p.fingerprints:
        # Beanstalk, ELB, CloudFront. Nothing to match against, ever
        # -- so no amount of fetching the page will decide this one
        # and only the resolver can.
        return (f"{p.name} serves no distinctive unclaimed page, so only a "
                f"chain that fails to resolve can settle this — and {dns}."
                + ("" if hop_resolves else
                   f" Run a DNS lookup against {hop}."))
    if not had_bodies:
        return (f"nothing has been fetched from this host, so there is no "
                f"page to match against {p.name}'s unclaimed one, and "
                f"{dns}. Run httpx against it"
                + ("." if hop_resolves else " or a DNS lookup."))
    # We looked at a page and it was not the provider's "nothing is
    # here" page. Weak evidence the resource IS claimed and live,
    # which is worth saying rather than leaving as silence.
    return (f"the page fetched from this host is not {p.name}'s unclaimed "
            f"one, which suggests the resource is live, and {dns}"
            + (". Both point the same way without proving it: a name that "
               "resolves can still belong to somebody else."
               if hop_resolves else
               ", so it is not proven either way."))


#: Which rows become a finding, and at what severity.
#:
#: Two inputs, and the ORDER they apply in is the whole point.
#:
#: `claimable` answers "how bad if true": a record pointing at a
#: provider surface nobody can re-register is a cleanup job, one
#: pointing at a first-come surface is somebody else's foothold on
#: the client's domain.
#:
#: The verdict answers "do we know it is true at all", and it caps
#: the answer. **An unevidenced row never outranks an evidenced
#: one.** The first version keyed on `claimable` alone and produced
#: exactly that inversion on the live engagement: a CloudFront
#: distribution caught serving its own unclaimed-resource page --
#: evidence, on a client hostname -- ranked Low, while a Heroku name
#: nothing had checked would have ranked High. A report where a
#: proven misconfiguration sits below a guess teaches its reader to
#: distrust the severities, which is worse than having none.
#:
#: So: evidence sets the floor, `claimable` sets the ceiling.
#:
#:                     claimable=False   claimable=True
#:     dangling              low              high
#:     fingerprint           low              high
#:     candidate             low              low
#:
#: `claimable=False -> low` throughout is the rule as specified. The
#: change is that `candidate` no longer borrows the severity of a
#: finding it has not earned.
SEVERITY: dict[tuple[str, bool], str] = {
    ("dangling", False): "low",
    ("dangling", True): "high",
    ("fingerprint", False): "low",
    ("fingerprint", True): "high",
    # Not determined. Reported so somebody goes and looks, ranked so
    # nobody reads it as a finding.
    ("candidate", False): "low",
    ("candidate", True): "low",
    # Determined, in the other direction. Never raised at all -- see
    # RAISE_VERDICTS -- but present so the table has no hole for
    # `severity_for` to fall through.
    ("live", False): "low",
    ("live", True): "low",
}


def severity_for(c: Candidate) -> str:
    """Severity of one takeover, from how hard it is to actually take.

    **Severity now follows `difficulty_for`**, per
    `DIFFICULTY_SEVERITY`: easy -> critical, medium -> high, hard ->
    medium, impossible -> low. Asked for, and it is the better
    question: "how bad is this" on a dangling record IS "can somebody
    actually get it", and a free S3 bucket and an unregisterable ELB
    name were both High under the old table.

    The property the old `SEVERITY` table existed to protect is kept,
    and it is kept in `difficulty_for` rather than here: evidence
    caps difficulty, so a `candidate` can never be `easy` and
    therefore never critical. Without that, pointing a CNAME at
    GitHub Pages would be enough to produce a critical on a name
    nothing had checked -- which is the inversion that table was
    rewritten to remove, arriving by a different route.

    `SEVERITY` is kept below for the migration note and for anything
    still reading it; it is no longer what decides.
    """
    return DIFFICULTY_SEVERITY.get(difficulty_for(c), "low")


#: Which verdicts are worth raising at all.
#:
#: **This is the dial.** Set to `VERDICTS` and every row becomes a
#: finding, including `candidate` -- which on a real estate means a
#: Low for every host whose CNAME points at a load balancer, i.e. for
#: normal, healthy infrastructure. Narrowed to the two evidenced
#: verdicts it raises only records something actually showed to be
#: dangling or unclaimed.
#:
#: Currently all of them except `live`, because the operator asked
#: for the rows they were looking at -- which were `candidate` -- to
#: be raised. The noise that implies is the reason this is one named
#: constant and not a condition buried in the loop below.
#:
#: `live` is excluded on purpose, and it is not the same exclusion as
#: a threshold. The other three verdicts range from "proven" to "not
#: established"; `live` is the answer "we looked and there is nothing
#: here", which is a finished question. Raising a Low for it would
#: put a row in a client's report whose entire content is that we
#: checked.
RAISE_VERDICTS: tuple[str, ...] = ("dangling", "fingerprint", "candidate")

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
        # The reason, not the bare fact of its absence. A finding
        # that says "could not determine" without saying what is
        # missing gives its reader nothing to act on -- and this one
        # names the check that could not run and what to run instead.
        "live": f"The resource is claimed and serving ({c.evidence}). "
                f"This is not a takeover.",
        "candidate": (
            f"Not confirmed: {c.evidence}" if c.evidence else
            "Neither check could be run against this host, so this is a "
            "record to go and look at rather than a confirmed dangling "
            "one."),
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
        sev = severity_for(c)
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

    from .lookuphistory import answered_empty, answered_with_data
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
    # The other half. Without it a row cannot tell "nobody looked" from
    # "it was looked up and it resolves", and says the first when the
    # second is true.
    resolved = await answered_with_data(session, project_id, "nslookup",
                                        every_hop)

    tids = [t for t, _, _ in interesting]
    bodies: dict[int, list[Capture]] = {}
    for tid, scheme, body in (await session.execute(
            _select(WebAddress.target_id, WebAddress.scheme,
                    WebAddress.response)
            .where(WebAddress.target_id.in_(tids),
                   WebAddress.response.isnot(None)))).all():
        # Only the head of each response. A provider's "nothing is
        # here" page says so in the first screenful, and these rows
        # run to two megabytes apiece.
        #
        # The scheme rides along because for a provider that routes
        # on SNI it decides whether the body may be believed at all.
        bodies.setdefault(tid, []).append(
            Capture(str(body)[:8000],
                    secure=str(scheme or "").lower() == "https"))

    decided: dict[str, tuple[int, Candidate]] = {}
    for tid, host, hops in interesting:
        c = decide(host, hops, bodies.get(tid), unresolved, resolved)
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
