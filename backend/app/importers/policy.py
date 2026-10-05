"""Deciding which hosts an import is allowed to create.

Every importer feeds one ingest path, so this sits there rather than in
any one parser — it applies equally to nmap, Burp, a C2 session list and
everything else.

The problem it solves is concrete: a Burp HTTP history exported from one
engagement, imported into another by mistake, silently created fourteen
targets belonging to a different client. Nothing was wrong with the file
or the parser. The import simply believed that a hostname it had never
seen was a new asset, which is the right assumption exactly half the
time.

So in `strict` mode an import writes only for hosts the project already
knows, and anything else comes back as a question. The operator answers
once, for all of them at once, and an unanswered host is **rejected** —
not quietly created. Defaulting the unanswered case to "skip" rather than
"add" is the whole point: the failure that actually happens is importing
into the wrong place, and the cost of that is polluted client data, while
the cost of over-caution is one more click.
"""
from __future__ import annotations

from dataclasses import dataclass, field

#: strict  only known hosts; unknown ones need a decision
#: open    create whatever the file names (the old behaviour)
MODES = ("strict", "open")

#: What the operator chose for an unknown host.
ADD = "add"           # create it as a new target
MAP = "map"           # attach its data to an existing target
REJECT = "reject"     # drop everything for it


@dataclass
class Decision:
    action: str
    #: For MAP, the existing target to attach to.
    target: str | None = None


@dataclass
class UnknownHost:
    """A host the file names that the project has never heard of.

    Carries the counts so the modal can show what is at stake. "Add this
    host?" is unanswerable; "add this host, which brings 431 URLs and 17
    services?" is not.
    """
    host: str
    services: int = 0
    web: int = 0
    vulns: int = 0
    credentials: int = 0
    implants: int = 0
    notes: int = 0
    ip: str | None = None

    @property
    def total(self) -> int:
        return (self.services + self.web + self.vulns
                + self.credentials + self.implants + self.notes)


@dataclass
class Policy:
    mode: str = "strict"
    #: Hosts the project already has, lowercased.
    known: set[str] = field(default_factory=set)
    #: host -> Decision, from the operator.
    decisions: dict[str, Decision] = field(default_factory=dict)
    #: Filled in as the ingest runs.
    rejected: dict[str, int] = field(default_factory=dict)
    mapped: dict[str, str] = field(default_factory=dict)
    created: list[str] = field(default_factory=list)

    def resolve(self, host: str | None) -> str | None:
        """-> the target name to write against, or None to drop this row.

        A None means "the operator did not ask for this host", and the
        caller must discard the row rather than inventing somewhere to
        put it.
        """
        if not host:
            return None
        h = host.strip().rstrip(".").lower()
        if not h:
            return None
        if h in self.known:
            return h
        if self.mode == "open":
            return h

        d = self.decisions.get(h)
        if d is None or d.action == REJECT:
            self.rejected[h] = self.rejected.get(h, 0) + 1
            return None
        if d.action == MAP and d.target:
            t = d.target.strip().rstrip(".").lower()
            # Mapping onto something that does not exist would recreate
            # the bug by another route.
            if t not in self.known:
                self.rejected[h] = self.rejected.get(h, 0) + 1
                return None
            self.mapped[h] = t
            return t
        if d.action == ADD:
            # Remember it so the second row for the same host does not
            # ask again mid-import.
            self.known.add(h)
            if h not in self.created:
                self.created.append(h)
            return h
        self.rejected[h] = self.rejected.get(h, 0) + 1
        return None


def survey(scan, known: set[str]) -> list[UnknownHost]:
    """Every host in the file the project does not already have.

    Counts what each one would bring, so the operator is choosing with
    the consequences in front of them.
    """
    found: dict[str, UnknownHost] = {}

    def entry(name: str | None) -> UnknownHost | None:
        if not name:
            return None
        h = name.strip().rstrip(".").lower()
        if not h or h in known:
            return None
        return found.setdefault(h, UnknownHost(host=h))

    for ph in scan.hosts:
        u = entry(ph.host)
        if u is not None:
            u.services += len(ph.services)
            u.ip = u.ip or ph.ip_address or ph.ipv6_address
    for pv in scan.vulns:
        u = entry(pv.host)
        if u is not None:
            u.vulns += 1
    for pw in scan.web:
        u = entry(pw.host)
        if u is not None:
            u.web += 1
    for pc in scan.credentials:
        u = entry(pc.host)
        if u is not None:
            u.credentials += 1
    for pi in scan.implants:
        u = entry(pi.host)
        if u is not None:
            u.implants += 1
    for pn in scan.notes:
        u = entry(pn.host)
        if u is not None:
            u.notes += 1

    # Biggest first: the host bringing 431 URLs is the one worth a careful
    # look, and the long tail of one-hit hosts can be dealt with in bulk.
    return sorted(found.values(), key=lambda u: (-u.total, u.host))
