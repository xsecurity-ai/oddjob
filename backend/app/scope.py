"""Classify a scope entry, and decide whether a host is inside the scope.

Two halves, deliberately in one module. Classification derives the kind of
an entry; matching consumes those kinds. Split across two files they drift —
a kind added to one and not the other is a scope list that silently stops
enforcing part of itself, which is the worst bug this file could have.

**Classification.** The kind is derived, never asked for. A scope document
arrives as a pasted block of a few hundred lines mixing ranges, addresses,
names and wildcards; making a human tag each one is both tedious and the
reason a /24 ends up recorded as a hostname.

Ambiguity is resolved in the only safe direction: anything that does not
parse cleanly is REJECTED and named back to the caller, rather than being
filed as an FQDN because that is the loosest bucket. A scope list silently
containing a typo'd range is worse than one that refused to load.

**Matching.** `ScopeIndex` answers one question — may this project do
something new with this host — with three outcomes, never two:

    ALLOWED   it is in the in-list, or no in-list was declared
    BARRED    it matched the out-list. Nothing may touch it, ever
    OUTSIDE   an in-list exists and this is not in it. Nothing NEW

BARRED and OUTSIDE are different claims and the callers treat them
differently: BARRED stops work on a host the project already has, OUTSIDE
only stops the project acquiring new ones. Collapsing them would either
let a barred host keep being scanned or retroactively freeze an engagement
the day someone typed a scope list into it.

Out always trumps in. An entry on both lists is barred.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from .hosts import InvalidHost, normalise_host, validate_host


@dataclass
class Entry:
    kind: str          # cidr | ipv4 | ipv6 | fqdn | wildcard
    value: str
    included: bool
    #: Only ever true on an `fqdn`. See `classify` for why it is dropped
    #: rather than carried on the other kinds.
    include_subdomains: bool = False


def entry_label(kind: str, value: str, include_subdomains: bool = False) -> str:
    """How an entry is written wherever a person reads it back.

    One function because the string appears in three places that have to
    agree: the sentence in a `Ruling` that explains a refusal, the scope
    section of a report, and the Slack welcome post. A row that silently
    covers a whole zone must not print as the bare apex in a deliverable
    the client reads — that is the client being told a narrower scope
    than the one that was enforced.
    """
    if include_subdomains and kind == "fqdn":
        return f"{value} (+subdomains)"
    return value


def classify(raw: str, include_subdomains: bool = False) -> Entry:
    """-> Entry, or raise ValueError naming what is wrong with it.

    A leading '!' or '-' marks an exclusion, which is how scope documents are
    usually written.

    `include_subdomains` is the operator's answer to "does the zone come
    with it", asked once for a pasted batch rather than per line — the
    same shape as `included` and the country tag, and for the same
    reason: the kinds are derived here, so the person pasting cannot be
    asked to answer it only for the lines that turn out to be names.

    It is DROPPED on every kind but `fqdn`, never an error. `*.a.example`
    already covers its subdomains, and a CIDR has none; carrying the flag
    on them would make the stored row claim a rule it does not have, and
    refusing those lines would make a mixed paste — which is the normal
    case — unusable with the box ticked. Dropping only ever narrows, so
    it is safe in the direction this file cares about.
    """
    s = (raw or "").strip()
    if not s:
        raise ValueError("empty entry")

    included = True
    if s[0] in "!-" and len(s) > 1:
        included, s = False, s[1:].strip()

    # Strip a protocol and path if somebody pasted a URL; the scope is the
    # host, and rejecting https://x.com for not being a hostname is pedantry.
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0] if ("/" in s and not _looks_like_cidr(s)) else s
    s = s.strip().rstrip(".")
    if not s:
        raise ValueError(f"{raw!r} has no host part")

    if "/" in s:
        try:
            net = ipaddress.ip_network(s, strict=False)
        except ValueError as e:
            raise ValueError(f"{raw!r} looks like a range but is not valid: {e}") from e
        # Same stdlib variance as the bare-address branch below: the
        # network address of an IPv4-mapped prefix prints as
        # `::ffff:0.0.0.0` on some CPython patch releases and
        # `::ffff:0:0` on others. Pinned for the same reason — the
        # stored value must not depend on the host's interpreter.
        na = net.network_address
        if na.version == 6 and na.ipv4_mapped is not None:
            return Entry("cidr", f"::ffff:{na.ipv4_mapped}/{net.prefixlen}",
                         included)
        return Entry("cidr", str(net), included)

    # Bare address?
    try:
        ip = ipaddress.ip_address(s)
        # An IPv4-mapped IPv6 address is spelled explicitly rather than
        # left to `str()`. CPython renders `::ffff:cb00:7101` as the hex
        # form on some patch releases and the dotted `::ffff:203.0.113.1`
        # on others, so `str()` makes the stored value depend on which
        # Python the host happens to run. Two installs would then
        # normalise the same scope line differently, and a value written
        # by one would not match a lookup from the other.
        #
        # Caught by a differential fixture that pins this function's
        # answers for the browser: CI is on Ubuntu's 3.12.3 and recorded
        # the other form. The fixture found a real portability bug rather
        # than a disagreement between client and server.
        # The zone id is carried through rather than dropped: it is part
        # of which interface the address is on, and `ipv4_mapped` does not
        # keep it. Losing it here would silently rewrite a scoped address
        # into a different one — which is how the first version of this
        # fix turned `::ffff:203.0.113.1%eth0` into `::ffff:203.0.113.1`,
        # caught by the fixture rather than by reading.
        if ip.version == 6 and ip.ipv4_mapped is not None:
            zone = f"%{ip.scope_id}" if ip.scope_id else ""
            return Entry("ipv6", f"::ffff:{ip.ipv4_mapped}{zone}", included)
        return Entry("ipv4" if ip.version == 4 else "ipv6", str(ip), included)
    except ValueError:
        pass

    # A wildcard is not a host — you cannot scan one — but it is a
    # perfectly good scope entry, and it is how scope documents are
    # written. Only the leading-label form is accepted: `*.acme.example`
    # reads unambiguously, while `a.*.example` and `*acme.example` do
    # not, and a pattern an operator has to squint at is one that bars
    # the wrong thing.
    if s.startswith("*."):
        rest = s[2:]
        try:
            base = validate_host(rest)
        except InvalidHost as e:
            raise ValueError(f"{raw!r} is not a usable wildcard: {e}") from e
        if "." not in base:
            raise ValueError(
                f"{raw!r} wildcards a single label, which would cover an "
                f"entire TLD")
        return Entry("wildcard", f"*.{base}", included)
    if "*" in s:
        raise ValueError(
            f"{raw!r} has a '*' somewhere other than the first label; "
            f"only `*.name.example` is understood")

    # Otherwise it must be a well-formed hostname.
    try:
        host = validate_host(s)
    except InvalidHost as e:
        raise ValueError(str(e)) from e
    if "." not in host:
        raise ValueError(f"{raw!r} is a single label, not a fully-qualified name")
    return Entry("fqdn", host, included, include_subdomains)


def classify_many(lines: list[str],
                  include_subdomains: bool = False) -> tuple[list[Entry], list[str]]:
    """-> (entries, errors). Deduplicates on value, keeping the first.

    Returns both rather than raising: a 400-line paste with two bad lines
    should import the 398 and tell you about the two, not refuse everything.
    """
    out: list[Entry] = []
    errors: list[str] = []
    seen: set[str] = set()
    for raw in lines:
        if not raw.strip():
            continue
        try:
            e = classify(raw, include_subdomains)
        except ValueError as err:
            errors.append(str(err))
            continue
        if e.value in seen:
            continue
        seen.add(e.value)
        out.append(e)
    return out, errors


def _looks_like_cidr(s: str) -> bool:
    head, _, tail = s.partition("/")
    return tail.isdigit() and (":" in head or head.replace(".", "").isdigit())


# ============================================================== countries
#: ISO 3166-1 alpha-2, so a typo is refused at the door rather than
#: becoming a list entry that silently matches nothing. On an out-of-scope
#: list that failure is invisible and dangerous: "CN is barred" spelled
#: `cm` bars Cameroon and tests China.
ISO_3166_1 = frozenset(
    "ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh "
    "bi bj bl bm bn bo bq br bs bt bv bw by bz ca cc cd cf cg ch ci ck cl "
    "cm cn co cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg eh er es et "
    "fi fj fk fm fo fr ga gb gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu "
    "gw gy hk hm hn hr ht hu id ie il im in io iq ir is it je jm jo jp ke "
    "kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc "
    "md me mf mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc "
    "ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl pm pn pr ps pt "
    "pw py qa re ro rs ru rw sa sb sc sd se sg sh si sj sk sl sm sn so sr "
    "ss st sv sx sy sz tc td tf tg th tj tk tl tm tn to tr tt tv tw tz ua "
    "ug um us uy uz va vc ve vg vi vn vu wf ws ye yt za zm zw"
    .split()
)


def classify_country(raw: str) -> str:
    """-> a lowercase alpha-2 code, or raise ValueError saying why not.

    Deliberately not a name lookup. "United Kingdom" has four common
    spellings and two plausible codes, and a scope list is not the place
    to be lenient about which one was meant.
    """
    c = (raw or "").strip().lower()
    if not c:
        raise ValueError("empty country")
    if len(c) != 2 or not c.isalpha():
        raise ValueError(
            f"{raw!r} is not an ISO 3166-1 alpha-2 code (two letters, e.g. 'jp')")
    if c not in ISO_3166_1:
        raise ValueError(f"{raw!r} is not an assigned ISO 3166-1 alpha-2 code")
    return c


# =============================================================== matching
ALLOWED = "allowed"
BARRED = "barred"
OUTSIDE = "outside"

#: The kinds that describe an address or a name, as opposed to a country.
#: An in-list made only of countries must not also act as an allowlist of
#: hosts, and vice versa — the two questions are answered separately.
HOST_KINDS = ("cidr", "ipv4", "ipv6", "fqdn", "wildcard")


@dataclass(frozen=True)
class Ruling:
    """A decision and the sentence that explains it.

    The reason is not decoration. It is what the operator reads when a
    scan is refused, and "out of scope" without naming the entry that
    barred it means editing the list by trial and error.
    """
    verdict: str
    reason: str

    @property
    def allowed(self) -> bool:
        return self.verdict == ALLOWED


#: Deliberately no __bool__: `if ruling:` on a security decision reads
#: fine and is wrong the one time somebody returns the wrong object.


@dataclass
class _Side:
    """One list — in or out — indexed so a lookup is not a scan.

    Networks are bucketed by prefix length: masking the address once per
    distinct length and hitting a set is a few dozen operations whatever
    the list holds, where walking every network is linear in it. A real
    scope document runs to a few hundred ranges and is consulted once per
    host in an import of thousands.
    """
    names: set[str] = field(default_factory=set)
    #: ".acme.example" for an entry of "*.acme.example".
    suffixes: dict[str, str] = field(default_factory=dict)
    addrs: dict[str, str] = field(default_factory=dict)
    #: version -> prefixlen -> {masked network int: the entry as written}
    nets: dict[int, dict[int, dict[int, str]]] = field(default_factory=dict)
    countries: set[str] = field(default_factory=set)

    @property
    def has_hosts(self) -> bool:
        return bool(self.names or self.suffixes or self.addrs or self.nets)

    def add(self, kind: str, value: str,
            include_subdomains: bool = False) -> None:
        if kind == "country":
            self.countries.add(value.lower())
            return
        if kind == "wildcard":
            self.suffixes[value[1:].lower()] = value     # "*.x.y" -> ".x.y"
            return
        if kind == "fqdn":
            name = normalise_host(value)
            self.names.add(name)
            if include_subdomains:
                # One row, expanded here into the two things it means:
                # the apex in `names`, and the zone in `suffixes`. The
                # expansion is deliberately in the INDEX and not in
                # `match_name` — the matcher is the hot path and the part
                # that must stay obviously correct, and this way it is
                # byte-for-byte the function it was before the feature
                # existed. Whatever is wrong with "+subdomains" can only
                # be wrong in these three lines.
                #
                # `setdefault`, so an explicit `*.x.y` row already on
                # this side keeps its own label in a ruling. Which of the
                # two gets named changes no verdict; it changes which
                # rule the operator is sent to go and edit, and the one
                # they literally typed is the better answer.
                self.suffixes.setdefault(
                    f".{name}", entry_label(kind, value, True))
            return
        if kind in ("ipv4", "ipv6"):
            try:
                ip = ipaddress.ip_address(value)
            except ValueError:
                return          # a row that cannot be parsed matches nothing
            self.addrs[ip.compressed] = value
            return
        if kind == "cidr":
            try:
                net = ipaddress.ip_network(value, strict=False)
            except ValueError:
                return
            (self.nets.setdefault(net.version, {})
                 .setdefault(net.prefixlen, {})[int(net.network_address)]) = value

    def match_name(self, host: str) -> str | None:
        """-> the entry that covers this name, or None."""
        if host in self.names:
            return host
        # Walk the parents rather than every wildcard: a name has a
        # handful of labels and the list may have hundreds of patterns.
        #
        # `*.acme.example` covers a.acme.example and a.b.acme.example but
        # NOT acme.example itself, which is how certificates and DNS both
        # read it. An operator who wants the apex adds it as its own
        # line, or writes `acme.example` with "include subdomains" — see
        # models.ProjectScope.include_subdomains, which `_Side.add`
        # expands into an entry in BOTH of the dicts this reads. Nothing
        # about the walk below changed when that arrived, on purpose.
        i = host.find(".")
        while i != -1:
            hit = self.suffixes.get(host[i:])
            if hit:
                return hit
            i = host.find(".", i + 1)
        return None

    def match_ip(self, ip) -> str | None:
        hit = self.addrs.get(ip.compressed)
        if hit:
            return hit
        for plen, bucket in (self.nets.get(ip.version) or {}).items():
            masked = int(ip) & (((1 << plen) - 1) << (ip.max_prefixlen - plen))
            hit = bucket.get(masked)
            if hit:
                return hit
        return None


@dataclass(frozen=True)
class _Attribution:
    """An operator's statement that some part of the estate is in a country.

    See `ScopeIndex.country_of` for why this is declared rather than
    looked up.
    """
    kind: str
    value: str
    country: str
    #: Higher wins when several entries cover the same host. An exact
    #: name or address beats a range; a longer prefix beats a shorter one.
    rank: int


def _parse_host(host: str):
    """-> an ip_address object, or None if it is a name (or unusable)."""
    try:
        return ipaddress.ip_address((host or "").strip().split("%", 1)[0])
    except ValueError:
        return None


class ScopeIndex:
    """The two lists of one project, ready to answer questions.

    Built once and reused: an import asks per host, and rebuilding from
    the rows each time would make a 4,000-host file 4,000 queries.
    """

    def __init__(self, entries=()) -> None:
        self.inc = _Side()
        self.out = _Side()
        self.attributions: list[_Attribution] = []
        # host <-> address pairs this project has already recorded, both
        # directions. Scope travels along them: an address an in-scope
        # name resolves to is in scope, and a name recorded at an
        # in-scope address is too.
        #
        # Populated from the TARGET table by `index_for`, never from a
        # live lookup — resolving here would send traffic and make the
        # answer depend on what a resolver said this second. So the link
        # exists only once something has actually observed it.
        self.links: dict[str, set[str]] = {}
        for e in entries:
            self.add(e.kind, e.value, e.included,
                     getattr(e, "country", None),
                     bool(getattr(e, "include_subdomains", False)))

    def add(self, kind: str, value: str, included: bool,
            country: str | None = None,
            include_subdomains: bool = False) -> None:
        subs = bool(include_subdomains) and kind == "fqdn"
        (self.inc if included else self.out).add(kind, value, subs)
        if country and kind in HOST_KINDS:
            self.attributions.append(
                _Attribution(kind, value, country.lower(),
                             _rank(kind, value)))
            if subs:
                # The country has to travel with the rule, or the two
                # halves of one row disagree about where its hosts are.
                # That is not cosmetic: an out-of-scope COUNTRY list bars
                # on a declared country, so a zone whose subdomains carry
                # no attribution would leave `a.x.example` unplaced and
                # therefore unbarred, while the apex it was written with
                # is barred. The row would be half-enforced.
                #
                # Ranked as the wildcard it stands in for, so an exact
                # entry for a subdomain still beats it.
                self.attributions.append(
                    _Attribution("wildcard", f"*.{value}", country.lower(),
                                 _rank("wildcard", f"*.{value}")))

    def link(self, host: str, ip: str | None) -> None:
        """Record that `host` was observed at `ip`."""
        h = normalise_host(host)
        a = normalise_host(ip or "")
        if not h or not a or h == a:
            return
        self.links.setdefault(h, set()).add(a)
        self.links.setdefault(a, set()).add(h)

    @property
    def defined(self) -> bool:
        """Is there anything here that could refuse anything?"""
        return bool(self.inc.has_hosts or self.inc.countries
                    or self.out.has_hosts or self.out.countries)

    # ------------------------------------------------------- geolocation
    def country_of(self, host: str, ip: str | None = None) -> str | None:
        """Which country this host is in, or None for "not determined".

        **Nothing here performs a lookup, and nothing here may.** Resolving
        an address to a country means handing a client's target list to a
        third-party geolocation service, which is a disclosure of the
        engagement itself — see the same decision for Drone `geo` routing in
        models.Agent.regions. So the attribution is operator-declared: a
        country written onto a scope entry says "this range is in JP", and
        that statement, held locally, is what resolves every address it
        covers.

        None is a third answer and not a synonym for "nowhere". The caller
        must not read it as "not in a barred country" — see `check`.

        Linear because the entries that CARRY a country are the few the
        operator bothered to annotate, not the whole list.
        """
        if not self.attributions:
            return None
        h = normalise_host(host)
        addr = _parse_host(h) or (_parse_host(ip) if ip else None)
        best: _Attribution | None = None
        for a in self.attributions:
            if not _covers(a, h, addr):
                continue
            if best is None or a.rank > best.rank:
                best = a
        return best.country if best else None

    # ------------------------------------------------------- the decision
    def check_zone(self, zone: str) -> Ruling:
        """May the project enumerate this ZONE — ask who exists under it?

        A different question from `check`, which asks whether the
        project may do something to the host of that name, and the two
        genuinely have different answers for exactly one input.

        `*.acme.example` does not put `acme.example` in scope. That is
        deliberate and stays: the apex is a different machine from the
        names under it, and a wildcard is not permission to scan it.
        But "enumerate the zone acme.example" is the single operation
        that wildcard most clearly DOES authorise — every name it can
        return is `*.acme.example`, which is precisely what was
        written down. Refusing it meant Kitchen Sink walking a known
        host queued amass for the leaf name and never for the zone,
        so a project scoped the normal way could not enumerate itself.

        So: allowed if `check` already allows it, or if an included
        wildcard names this exact zone. Nothing else is widened —
        a parent of the wildcard is still refused, and the out-list
        still wins, because this defers to `check` for both.

        This must not be used to decide whether to touch a host. It
        answers one question, for the enumerate path, and the name
        says which.
        """
        direct = self.check(zone)
        if direct.allowed:
            return direct
        # BARRED is a decision, not an absence: an excluded zone stays
        # excluded however it was named. Only OUTSIDE -- "nothing in
        # the allowlist matched" -- can be reconsidered here.
        if direct.verdict == BARRED:
            return direct
        h = normalise_host(zone)
        if h and _parse_host(h) is None and ("." + h) in self.inc.suffixes:
            entry = self.inc.suffixes["." + h]
            return Ruling(ALLOWED,
                          f"{h} is the zone named by the in-scope entry {entry}")
        return direct

    def check(self, host: str, ip=None) -> Ruling:
        """May the project do something new with this host?

        `ip` is the address already recorded for it, where one is known.
        It is used, and a DNS lookup is not: resolving the name here would
        both send traffic and make the answer depend on what a resolver
        said this second.

        A host may have several addresses, so `ip` takes a string or a
        list of them. The two lists read the list differently and both
        readings are the cautious one: ANY address on the out-list bars
        the host — a machine is not partly out of scope — while ANY
        address on the in-list admits it, because a multi-homed host
        that the scope document names at one of its addresses is the
        same machine at the others.
        """
        h = normalise_host(host)
        if not h:
            return Ruling(BARRED, "an empty host is not a scope decision "
                                  "anyone can make")
        addr = _parse_host(h)
        raw_ips = ([ip] if isinstance(ip, str)
                   else list(ip) if ip is not None else [])
        others = [(_parse_host(x), x) for x in raw_ips if x]
        others = [(a, x) for a, x in others if a is not None]

        # ---- out first, and out always wins -----------------------------
        hit = self.out.match_name(h) if addr is None else None
        if hit:
            return Ruling(BARRED, f"{h} matches the out-of-scope entry {hit}")
        for a, why in ([(addr, h)] if addr is not None else []) + \
                      [(a, f"{h} (recorded as {x})") for a, x in others]:
            hit = self.out.match_ip(a)
            if hit:
                return Ruling(BARRED, f"{why} matches the out-of-scope "
                                      f"entry {hit}")

        country = self.country_of(h, raw_ips[0] if raw_ips else None)
        if country and country in self.out.countries:
            return Ruling(BARRED, f"{h} is declared to be in {country.upper()}, "
                                  f"which is out of scope")

        # ---- then the allowlist, if one was declared --------------------
        if self.inc.has_hosts:
            ok = (self.inc.match_name(h) if addr is None
                  else self.inc.match_ip(addr))
            # A name is let in by its recorded address too. An operator
            # whose scope document is a list of ranges expects the hosts
            # living in them to be in scope, and refusing every name
            # because it is not literally written down would make a
            # CIDR-only scope reject the whole engagement.
            if not ok:
                for a, _x in others:
                    if self.inc.match_ip(a):
                        ok = True
                        break
            via = None
            if not ok:
                # Nothing matched this host directly. Scope travels
                # along an observed host/address pair, so an address an
                # in-scope name resolves to is in scope and vice versa.
                #
                # **Exactly one step, and the partner must match the
                # scope document ITSELF.** Not `self.check(partner)`,
                # which would recurse and make scope transitive: an
                # in-scope name would vouch for its CDN address, that
                # address would then vouch for every other tenant
                # sharing it, and a two-line scope document would
                # quietly cover a hosting provider. With the
                # many-to-many address model that is no longer a
                # hypothetical — one address row really does link to
                # every name recorded at it — so the direct-match-only
                # rule is the thing standing between an in-scope name
                # and its neighbours. `tests/scopetest.py` asserts it.
                #
                # The partner is NAMED in the ruling. An address that is
                # in scope only because something else is should never
                # read the same as one somebody wrote on the scope
                # document — that difference is the whole audit trail
                # when a CDN address turns out to be shared with another
                # tenant.
                for partner in sorted(self.links.get(h, ())):
                    pa = _parse_host(partner)
                    hit = (self.inc.match_ip(pa) if pa is not None
                           else self.inc.match_name(partner))
                    if hit:
                        ok, via = True, partner
                        break
            if not ok:
                return Ruling(OUTSIDE,
                              f"{h} is not in this project's in-scope list")
            if via:
                return Ruling(ALLOWED,
                              f"{h} is in scope via {via}, which this "
                              f"project has recorded it alongside")

        if self.inc.countries:
            # Undetermined is refused here, and only here. An in-scope
            # country list is a statement that work happens in named
            # places; "we cannot say where this is" does not satisfy it.
            # The out-list above takes the opposite reading of the same
            # unknown, because a barred-country list that refused
            # everything unattributed would bar the entire project.
            if country is None:
                return Ruling(OUTSIDE,
                              f"no country is declared for {h}; this project "
                              f"restricts work to "
                              f"{', '.join(sorted(c.upper() for c in self.inc.countries))}. "
                              f"Declare one on a scope entry that covers it.")
            if country not in self.inc.countries:
                return Ruling(OUTSIDE, f"{h} is declared to be in "
                                       f"{country.upper()}, which is not in "
                                       f"this project's in-scope countries")

        return Ruling(ALLOWED, f"{h} is in scope")


def _rank(kind: str, value: str) -> int:
    """How specific a country attribution is. Bigger wins."""
    if kind in ("fqdn", "ipv4", "ipv6"):
        return 1_000_000
    if kind == "wildcard":
        # A longer suffix is a narrower claim.
        return 1000 + len(value)
    try:
        return ipaddress.ip_network(value, strict=False).prefixlen
    except ValueError:
        return 0


def _covers(a: _Attribution, host: str, addr) -> bool:
    if a.kind == "fqdn":
        return addr is None and host == normalise_host(a.value)
    if a.kind == "wildcard":
        if addr is not None:
            return False
        suffix = a.value[1:].lower()
        return host.endswith(suffix) and host != suffix.lstrip(".")
    if addr is None:
        return False
    if a.kind in ("ipv4", "ipv6"):
        try:
            return addr == ipaddress.ip_address(a.value)
        except ValueError:
            return False
    try:
        net = ipaddress.ip_network(a.value, strict=False)
    except ValueError:
        return False
    return addr.version == net.version and addr in net
