"""The shape every importer produces.

One intermediate representation, so the ingest path, the upsert keys and the
timeline writing are written once rather than per tool. An importer's whole
job is to turn its format into this; it touches no database and performs no
network I/O, which is also what makes each one testable from a fixture.

Everything here is optional except the host, because the tools disagree
wildly about what they know. masscan knows a port and nothing else; Nessus
knows a CVSS vector and a solution paragraph; a C2 callback knows a username
and an integrity level and may never have seen a port at all.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

#: A port that answered but could not be identified. Never an empty string:
#: blank reads as "nobody looked", which is a different and weaker claim.
UNKNOWN = "UNKNOWN"

SEVERITIES = ("critical", "high", "medium", "low", "info")

def scrub(v):
    """Strip NUL bytes out of a string. Returns anything else unchanged.

    A captured HTTP response is arbitrary bytes decoded leniently, so a
    gzip or image body becomes a string containing 0x00. SQLite stores
    that happily; **PostgreSQL refuses it outright** -- "PostgreSQL text
    fields cannot contain NUL (0x00) bytes" -- so the same import that
    worked on a laptop fails against a real deployment, part-way
    through, on whichever response happened to be a PNG.

    U+FFFD is the substitute rather than deletion, to match what the
    lenient decode already did with every other undecodable byte: the
    body stays the same length and still reads as "something was here
    that is not text".
    """
    if isinstance(v, str) and "\x00" in v:
        return v.replace("\x00", "\ufffd")
    return v


@dataclass
class _Scrubbed:
    """Base for the IR records: no field may carry a NUL byte.

    Done here rather than in each importer because every one of them
    reads a file someone else produced, and only some of them think
    about encoding. One `__post_init__` covers the lot, including
    importers not written yet.
    """

    def __post_init__(self):
        for f in self.__dataclass_fields__:
            v = getattr(self, f, None)
            if isinstance(v, str):
                if (c := scrub(v)) is not v:
                    setattr(self, f, c)
            elif isinstance(v, list) and v and isinstance(v[0], str):
                setattr(self, f, [scrub(x) for x in v])




def norm_severity(raw, *, default: str = "info") -> str:
    """Map any tool's scale onto ours.

    Accepts names, numeric levels (Nessus 0-4, Burp's words, Metasploit's
    absence of one) and CVSS scores. Anything unrecognised becomes the
    default rather than being dropped — a finding filed at the wrong
    severity is still a finding; one silently discarded is not.
    """
    if raw is None or raw == "":
        return default
    if isinstance(raw, (int, float)) or str(raw).strip().replace(".", "", 1).isdigit():
        n = float(raw)
        # Nessus and friends use 0-4; CVSS uses 0-10. The ranges overlap at
        # the bottom, so treat <=4 as the ordinal scale and above as CVSS.
        if n <= 4 and float(n).is_integer():
            return ("info", "low", "medium", "high", "critical")[int(n)]
        if n >= 9.0:
            return "critical"
        if n >= 7.0:
            return "high"
        if n >= 4.0:
            return "medium"
        if n > 0:
            return "low"
        return "info"
    s = str(raw).strip().lower()
    if s in SEVERITIES:
        return s
    return {
        "informational": "info", "information": "info", "none": "info",
        "note": "info", "notice": "info", "unknown": "info", "log": "info",
        "moderate": "medium", "med": "medium", "warning": "medium",
        "serious": "high", "important": "high",
        "urgent": "critical", "severe": "critical", "fatal": "critical",
    }.get(s, default)


@dataclass
class ParsedService(_Scrubbed):
    port: int
    protocol: str = "tcp"
    state: str = "open"
    name: str = UNKNOWN
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    tunnel: str | None = None
    method: str | None = None
    confidence: int | None = None
    reason: str | None = None
    cpe: list[str] = field(default_factory=list)
    scripts: dict[str, str] = field(default_factory=dict)
    banner_override: str | None = None

    @property
    def banner(self) -> str:
        """One readable line, the way nmap prints its VERSION column."""
        if self.banner_override:
            return self.banner_override
        bits = [self.product, self.version, self.extrainfo and f"({self.extrainfo})"]
        line = " ".join(b for b in bits if b).strip()
        if self.tunnel and line:
            line = f"{self.tunnel}/{line}"
        return line


@dataclass
class ParsedHost(_Scrubbed):
    host: str                       # best name: a hostname if one was found
    ip_address: str | None = None
    ipv6_address: str | None = None
    mac_address: str | None = None
    mac_vendor: str | None = None
    hostnames: list[str] = field(default_factory=list)
    alive: bool | None = None
    os: str | None = None
    os_accuracy: int | None = None
    hacked: bool | None = None      # only ever set True; never un-sets a flag
    notes: str | None = None
    extra: dict = field(default_factory=dict)
    services: list[ParsedService] = field(default_factory=list)


@dataclass
class ParsedVuln(_Scrubbed):
    host: str
    title: str
    severity: str = "info"
    description: str | None = None
    external_id: str | None = None   # plugin id, template id, msf ref…
    port: int | None = None
    protocol: str | None = None
    status: str = "open"
    #: Kept separate from the description: a report needs them in
    #: different columns, and a remediation folded into prose can never be
    #: pulled back out.
    remediation: str | None = None


@dataclass
class ParsedCredential(_Scrubbed):
    host: str | None = None
    username: str | None = None
    secret: str | None = None
    kind: str = "password"           # password | hash | key | token
    service: str | None = None
    port: int | None = None
    source: str | None = None
    notes: str | None = None
    validated: str = "none"          # none | works | failed


@dataclass
class ParsedImplant(_Scrubbed):
    """A C2 callback: an agent that checked in from a host we control.

    Deliberately framework-neutral. Cobalt Strike calls it a beacon, Mythic a
    callback, Merlin and Sliver an agent/session; the fields that matter to
    an engagement record — which box, as whom, at what integrity, when last
    seen — are the same, and normalising them is what makes a mixed-framework
    operation reportable at all.
    """
    host: str
    framework: str
    implant_id: str | None = None
    listener: str | None = None
    user: str | None = None
    domain: str | None = None
    process: str | None = None
    pid: int | None = None
    arch: str | None = None
    integrity: str | None = None
    internal_ip: str | None = None
    external_ip: str | None = None
    os: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    active: bool | None = None
    note: str | None = None
    extra: dict = field(default_factory=dict)


@dataclass
class ParsedWebAddress(_Scrubbed):
    """A URL seen on an http(s) service.

    `crawled` distinguishes a page something actually fetched from one that
    was merely referenced. A link harvested from HTML is not evidence the
    page exists; an httpx response is.
    """
    url: str
    host: str | None = None          # when the URL is a bare path
    scheme: str = "http"
    port: int | None = None
    method: str | None = None
    status_code: int | None = None
    title: str | None = None
    content_type: str | None = None
    content_length: int | None = None
    webserver: str | None = None
    tech: list[str] = field(default_factory=list)
    crawled: bool = False
    notes: str | None = None
    request: str | None = None
    response: str | None = None
    truncated: bool = False


@dataclass
class ParsedNote(_Scrubbed):
    host: str
    summary: str
    detail: str | None = None
    kind: str = "scan"


@dataclass
class ParsedScan(_Scrubbed):
    tool: str = "import"
    version: str | None = None
    args: str | None = None
    started: datetime | None = None
    summary: str | None = None
    hosts: list[ParsedHost] = field(default_factory=list)
    vulns: list[ParsedVuln] = field(default_factory=list)
    credentials: list[ParsedCredential] = field(default_factory=list)
    implants: list[ParsedImplant] = field(default_factory=list)
    web: list[ParsedWebAddress] = field(default_factory=list)
    notes: list[ParsedNote] = field(default_factory=list)
    #: Lines the importer could not use. Reported, never silently dropped.
    errors: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return f"{self.tool} {self.version}" if self.version else self.tool

    def host_for(self, name: str) -> ParsedHost:
        """Find or create the host entry, so children can be attached by name."""
        for h in self.hosts:
            if h.host == name:
                return h
        h = ParsedHost(host=name)
        self.hosts.append(h)
        return h


class ImportError_(ValueError):
    """Raised when the input is not the format it was claimed to be."""
