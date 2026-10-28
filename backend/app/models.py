"""Oddjob data model.

    Project 1---* Target 1---* Service
                         1---* Vuln
                         1---* Poc

Identity rules the whole app leans on:

  Project  keyed by `code`, a short slug (FALCON-1). Every target belongs to
           exactly one; there is no such thing as a loose target.

  Target   keyed by (project_id, host). Host is an FQDN or a bare IP.
           Uniqueness is PER PROJECT, not global: the same asset legitimately
           recurs across consecutive engagements, and a global unique index
           would make importing a second project impossible. It is deliberately
           not keyed by IP -- one IP serves many vhosts, and a hostname moves
           between addresses mid-engagement.

  Service  keyed by (target_id, port, protocol). A "port" and a "service" are
           one physical fact -- nmap emits port, protocol, state, name and
           banner as a single row -- so they share one table. The Ports view is
           this table filtered to state='open'; the Services view is the same
           rows with the name shown.

Children hang off target_id, not the host string, because host is only unique
within a project. The API still speaks `host` for convenience and resolves it
to a target within the active project.

Vuln and Poc exist because the Targets grid shows live counts of them. Those
counts are aggregated at query time, never stored on Target, so they cannot
drift.
"""
from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Table,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


SEVERITIES = ("critical", "high", "medium", "low", "info")

#: What a person concluded about a finding. See `Vuln.triage`.
#: `needs_investigating` is the default and the only one a scanner
#: can produce; the other two are somebody's judgement.
TRIAGE_STATES = ("needs_investigating", "true_positive", "false_positive")
PROJECT_STATUSES = ("active", "paused", "complete", "archived")

#: What `Project.auto_web` may be.
#:
#: `crawl` follows the application's own links; `gobuster` asks for
#: paths nothing links to. They answer different questions, which is
#: why `both` exists and why neither is the default.
WEB_CHOICES = ("off", "crawl", "gobuster", "both")

#: What `Project.auto_nmap` may be. Here rather than in
#: app/automation.py because `schemas.py` validates against it and
#: importing the worker module into the schemas to read one tuple is
#: how an import cycle starts. The task arguments each choice maps to
#: stay in automation.py, which is behaviour rather than vocabulary.
NMAP_CHOICES = ("off", "top100", "full")

#: What `Project.max_impact` may be, here for the same reason: the
#: schemas validate against it, and importing `app/roe.py` into the
#: schemas to read one tuple is how an import cycle starts. What each
#: value MEANS, and which task kinds fall under it, stays in roe.py —
#: that is behaviour rather than vocabulary.
#:
#: Ordered least to most permissive, which is what "at most" means.
IMPACT_CHOICES = ("read_only", "state_changing", "destructive")

#: What `Project.auto_nuclei` may be, for the same reason as above.
#:
#: Two runs rather than one, because the filters that make each
#: useful are mutually exclusive. The vulnerability run asks for
#: `-severity critical,high`; every technology-detection template is
#: `info`, so that same filter discards all 1,228 of them. They
#: cannot be one task, and pretending otherwise would mean one of
#: the two silently doing nothing.
#:
#:   vuln   CVE templates at critical and high
#:   tech   what the thing IS -- feeds the service, not the findings
#:   both   both, as separate tasks per URL
NUCLEI_CHOICES = ("off", "vuln", "tech", "both",
                  # Confirmation runs: nuclei asked only about the
                  # CVEs the local corpus already matched to a
                  # service on that host. See automation.NUCLEI_KINDS.
                  "confirm", "both+confirm")


class Project(Base, TimestampMixin):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    #: The operation's name, as people actually refer to it — ACME is
    #: FALCON, GLOBEX is KESTREL. Kept separate from `code` because the code
    #: is the client and appears in their deliverables, while the
    #: codename is internal and is what the scan directories, the Slack
    #: channels and the operators are all named after.
    codename: Mapped[str | None] = mapped_column(String(64), index=True)

    #: How work is spread when a project has more than one Ghost.
    #:
    #: mesh    — any online agent takes the next task. Whoever asks
    #:           first gets it, which balances by capacity for free:
    #:           a busy agent is not asking.
    #: primary — one agent does the work and the others stand by. The
    #:           primary is *derived*, not stored: the enabled, online
    #:           agent with the lowest `priority`. So if it stops
    #:           heartbeating the next one takes over on the next poll,
    #:           with no leader record to go stale and no two agents
    #:           able to believe they are primary at once.
    #: geo     — a task is routed to an agent that serves its region.
    #:           Regions are declared by the operator on both sides,
    #:           not looked up: resolving a target address to a country
    #:           would mean sending the client's addresses to a
    #:           third-party geolocation service.
    ghost_mode: Mapped[str] = mapped_column(
        String(16), default="mesh", server_default="mesh")
    #: How many tasks one agent may run at once on this engagement.
    #:
    #: A ceiling, not a target. The agent also decides for itself what
    #: its host can stand — cores, memory, and what masscan can
    #: actually emit — and the lower of the two wins. This is the
    #: operator's half of that: an engagement running against a
    #: fragile estate wants a small number regardless of how much
    #: machine the scanner has under it.
    ghost_max_parallel: Mapped[int] = mapped_column(
        Integer, default=5, server_default="5")

    #: Countries this ENGAGEMENT is authorised to test, as ISO 3166-1
    #: alpha-2 codes, comma-separated. Empty or NULL means everywhere,
    #: which is what every project has until somebody says otherwise —
    #: so adding this column changed no existing behaviour.
    #:
    #: Derived, not declared. The country of a host is
    #: `TargetAddress.geo_country`, filled by a LOCAL GeoLite2 lookup,
    #: which is what makes this feasible at all: the note on
    #: `ghost_mode` above says regions cannot be looked up because it
    #: would mean sending the client's addresses to a third party, and
    #: that was true until geolocation arrived. It no longer is, and
    #: nothing here leaves the machine.
    #:
    #: Needs MaxMind. With no database there is no country to gate on,
    #: so the control is disabled in the UI rather than quietly
    #: ignored — see `app/countrygate.py` and `geoip.enabled()`.
    scan_countries: Mapped[str | None] = mapped_column(String(512))

    # ------------------------------------------------- standing orders
    #: Four policies the operator can leave running, so the obvious
    #: follow-up to "a new host appeared" happens without anyone
    #: remembering to ask for it. All default OFF: each one sends
    #: packets at a client's estate, and a feature that starts scanning
    #: because a row appeared is not something to inherit by upgrading.
    #:
    #: They are standing orders rather than triggers on insert. A
    #: trigger only ever covers what arrives after it is switched on,
    #: which means turning one on does nothing visible and the operator
    #: concludes it is broken. These are evaluated against whatever is
    #: outstanding, so switching one on drains the backlog too — all of
    #: it, in the first cycle. What keeps that off the client's network
    #: is the Ghost's own max_parallel, not a cap on the queue; see the
    #: automation module docstring.
    #:
    #: Every candidate still goes through the scope gate individually.
    #: An automation that could queue one out-of-scope host is worse
    #: than no automation, because nobody is watching it.

    #: Hand every in-scope zone to amass once.
    auto_amass: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false")
    #: Resolve any hostname that has no address recorded.
    auto_resolve_ips: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false")
    #: Find names for any address-named host that has none.
    auto_reverse_dns: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false")
    #: "off" | "top100" | "full". Not a bool, because the difference
    #: between the hundred commonest ports and all 65,535 is hours of
    #: traffic at a client, and that is the operator's call to make
    #: explicitly rather than a default hiding behind a checkbox.
    auto_nmap: Mapped[str] = mapped_column(
        String(16), default="off", server_default="off")

    #: "off" | "crawl" | "gobuster" | "both". Not a bool because the
    #: two do different things and cost different amounts: a crawl
    #: follows what the application links to, content discovery asks
    #: for 4,751 paths it does not. Running both against every web
    #: address in a large estate is a great deal of traffic, so which
    #: of them runs is the operator's call rather than a default.
    auto_web: Mapped[str] = mapped_column(
        String(16), default="off", server_default="off")

    #: "off" | "vuln" | "tech" | "both" | "confirm" | "both+confirm".
    #: See NUCLEI_CHOICES.
    #:
    #: Off by default like the rest, and more deliberately than most:
    #: the vulnerability half runs CVE templates, which means sending
    #: a known exploit's request at a client's production system. The
    #: templates are detection rather than exploitation, but the
    #: traffic is indistinguishable from an attack in a log and the
    #: engagement has to have authorised it.
    auto_nuclei: Mapped[str] = mapped_column(
        String(16), default="off", server_default="off")

    #: Ask each web origin what OTHER names it answers to. A host
    #: serving twelve virtual hosts is twelve applications behind one
    #: address, and eleven of them were invisible to everything else
    #: here: content discovery asks what PATHS exist, and this asks
    #: what SITES do.
    auto_vhost: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false")
    #: Probe every URL the project knows and record what answered.
    #: The cheapest thing in the catalogue and the one that decides
    #: whether anything else is worth queueing against a URL.
    auto_httpx: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false")
    # There is deliberately no `auto_geolocate`. Geolocation already
    # runs for every project this worker touches -- it is a walk of a
    # memory-mapped file on this machine, nothing leaves, and it
    # costs nothing to ask -- so a switch for it would be a switch
    # that does not switch anything, which is worse than none.

    #: Everything on, at its most thorough, and kept that way.
    #:
    #: One switch instead of nine, for the engagement where the answer
    #: to every "should we also..." is yes. It does not COPY values
    #: into the other columns -- it is resolved when the policies are
    #: read, so turning it off returns the project to whatever was set
    #: before rather than to whatever the sink happened to leave
    #: behind.
    #:
    #: **It deliberately does not imply the two policies that send a
    #: client's domain to a third party** -- Certificate Transparency
    #: and archived-URL lookups. Those are gated by an explicit site
    #: decision for a documented reason (see app/ctlogs.py), and a
    #: convenience switch that routed around a vendor-approval gate
    #: would be the gate not existing. They stay separate and stay
    #: off until somebody says.
    kitchen_sink: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false")

    #: Extra paths for content discovery, one per line, APPENDED to
    #: whichever wordlist the agent is using rather than replacing it.
    #:
    #: Engagements accumulate names nothing public knows: an internal
    #: framework's console, a deploy path somebody mentioned in a
    #: ticket, a vendor's admin route seen on a sibling host. Those are
    #: the paths most worth asking for and the least likely to be in
    #: SecLists, and before this the only way to use them was to build
    #: a wordlist by hand and put it on every agent.
    #:
    #: Appended, never substituted. An operator adding three paths
    #: means "also these", and reading it as "only these" would
    #: silently turn a 4,751-entry sweep into a three-request one that
    #: still reports as a content-discovery scan.
    url_wordlist: Mapped[str | None] = mapped_column(Text)

    #: What every tool that sends one should call itself.
    #:
    #: An engagement is usually required to be attributable from the
    #: client's own logs — "who was scanning us at 03:00" should be
    #: answerable without anybody having to ask us — and the string
    #: they want differs per engagement, so it cannot be a constant
    #: baked into the agent.
    #:
    #: NULL means the agent's own default, which is attributable
    #: already. Deliberately not "" -- an empty User-Agent is a choice
    #: some WAFs block outright, and it would be an odd thing to arrive
    #: at by leaving a box blank.
    user_agent: Mapped[str | None] = mapped_column(String(200))

    # ---- the rest of the authorisation letter -----------------------
    #
    # The scope list has been enforced config since the beginning.
    # These two sentences were in the same document and the tool could
    # not read them, so an engagement that ended on the 14th went on
    # scanning on the 20th. See `app/roe.py`.
    #
    #: When testing is authorised from, and until. NULL at either end
    #: means unbounded, which is what every project had before these
    #: existed -- and is why they are nullable rather than defaulted
    #: to anything.
    #:
    #: UTC, like every other timestamp here. A window written in the
    #: client's local time is a conversion the operator makes once
    #: when they type it, not one re-derived per task from a timezone
    #: nobody recorded.
    engagement_starts_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True))
    engagement_ends_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True))
    #: The most intrusive thing this engagement permits:
    #: `read_only`, `state_changing` or `destructive`. "No intrusive
    #: testing" in a letter becomes `read_only` here and the gate
    #: enforces it, including against the operator who forgot.
    #:
    #: server_default, not just default=: a Python-side default
    #: produces `ADD COLUMN ... NOT NULL` with no DDL default, which
    #: neither SQLite nor Postgres accepts against a populated table.
    #:
    #: Defaults to `destructive` -- everything permitted. That is a
    #: decision, not an oversight: this arrived after engagements were
    #: already running, and a default that silently stopped a live
    #: scan would be a worse failure than the one it prevents.
    max_impact: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default="destructive",
        default="destructive")

    name: Mapped[str] = mapped_column(String(255))
    client: Mapped[str | None] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="active", index=True)
    # Per-project Slack override. When set, this engagement's notifications go
    # here instead of the site-wide token — engagements frequently run in the
    # customer's own workspace. Write-only over the API, like every secret.
    slack_token: Mapped[str | None] = mapped_column(Text)
    slack_channel: Mapped[str | None] = mapped_column(String(128))
    # Whether that channel actually exists in the workspace, which a
    # token alone does not tell you — posting to a channel nobody
    # created fails with channel_not_found. Recorded rather than derived
    # because it is a fact about a remote workspace: one listing call
    # per token refreshes every project using it.
    #
    # Three states, not two. An id means it was seen. A checked_at with
    # no id means the workspace answered and the channel was not there.
    # A NULL checked_at means nobody has been able to look, which is not
    # the same as absent and must not render as it.
    slack_channel_id: Mapped[str | None] = mapped_column(String(32))
    slack_channel_checked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True))
    slack_channel_error: Mapped[str | None] = mapped_column(String(300))
    # site | override | both. Only meaningful once an override token exists;
    # "both" is for an engagement that must be visible in the customer's
    # workspace AND stay on the internal record.
    slack_delivery: Mapped[str] = mapped_column(String(16), default="site")
    # Per-project agent credentials. NULL means "use the site setting",
    # which is what makes one customer's engagement able to run on their
    # own account without every other project moving with it.
    agent_provider: Mapped[str | None] = mapped_column(String(16))
    agent_anthropic_token: Mapped[str | None] = mapped_column(Text)
    agent_openai_token: Mapped[str | None] = mapped_column(Text)
    agent_model: Mapped[str | None] = mapped_column(String(128))
    # NULL inherits the site default rather than hard-coding one here, so
    # changing the site policy moves every project that never chose.
    slack_private: Mapped[bool | None] = mapped_column(Boolean, default=None)

    targets: Mapped[list[Target]] = relationship(
        back_populates="project", cascade="all, delete-orphan", passive_deletes=True
    )
    acls: Mapped[list[ProjectACL]] = relationship(
        back_populates="project", cascade="all, delete-orphan", passive_deletes=True
    )
    scope: Mapped[list[ProjectScope]] = relationship(
        back_populates="project", cascade="all, delete-orphan", passive_deletes=True
    )
    contacts: Mapped[list[ProjectContact]] = relationship(
        back_populates="project", cascade="all, delete-orphan", passive_deletes=True
    )


#: Which targets answer at which addresses. One row per (host, address)
#: pair, because the relationship really is many-to-many and nothing
#: smaller expresses it: a CDN or a shared-hosting address serves dozens
#: of names, and a single name routinely has an A record, a AAAA record
#: and several more behind a load balancer.
#:
#: The surrogate `id` is not decoration. It is the only thing that makes
#: "the first address this target was seen at" a stable, answerable
#: question — `Target.addresses` orders by it, so `Target.ip_address`
#: (the one-address view the reports and the grid still need) means
#: "the first one observed" rather than "whichever one the database
#: handed back this time".
target_address_links = Table(
    "target_address_links", Base.metadata,
    Column("id", Integer, primary_key=True),
    Column("target_id", ForeignKey("targets.id", ondelete="CASCADE"),
           nullable=False, index=True),
    Column("address_id", ForeignKey("target_addresses.id", ondelete="CASCADE"),
           nullable=False, index=True),
    UniqueConstraint("target_id", "address_id", name="uq_target_address_link"),
)


class Target(Base, TimestampMixin):
    __tablename__ = "targets"
    __table_args__ = (
        UniqueConstraint("project_id", "host", name="uq_target_project_host"),
        Index("ix_targets_project_host", "project_id", "host"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    #: The identity of this asset, unique per project and ALWAYS
    #: lowercase. A single FQDN, or a single IP literal when no name is
    #: known yet. Never a list and never a pattern — see `app/hosts.py`.
    #:
    #: Lowercasing is not cosmetic either. `host` is the join key the
    #: API speaks, and two rows differing only in case are two buckets
    #: that findings for one machine get split across. Writers go
    #: through `normalise_host`; the uniqueness constraint below then
    #: means something.
    host: Mapped[str] = mapped_column(String(255), index=True)
    #: What kind of asset this is.
    #:
    #:   host    a machine reachable at an address
    #:   mobile  an application, named by its bundle or package id,
    #:           with no IP of its own
    #:   cloud   a managed resource — a bucket, a function, a tenant,
    #:           an account — named by whatever identifies it with the
    #:           provider
    #:
    #: The distinction is not cosmetic. A mobile app has no address to
    #: scan, so an empty `ip_addresses` on one is a fact, not a gap in
    #: coverage, and liveness means nothing for it. A cloud resource is
    #: different again: it often DOES resolve, so its addresses are
    #: kept, but "no open ports" on a storage bucket is not the finding
    #: that the same result on a server would be.
    kind: Mapped[str] = mapped_column(
        String(16), default="host", server_default="host", index=True)
    #: Which cloud, for `kind="cloud"`. Free text rather than an enum
    #: because the list does not end at the big three — Oracle,
    #: DigitalOcean, Cloudflare and a dozen others turn up in scope —
    #: and an unrecognised provider must be recordable, not rejected.
    provider: Mapped[str | None] = mapped_column(String(32), index=True)
    # Three-state on purpose. NULL means "not probed yet", which is not the
    # same claim as "did not respond" -- collapsing the two would record a gap
    # in our coverage as a fact about the asset.
    alive: Mapped[bool | None] = mapped_column(Boolean, default=None, index=True)
    hacked: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    os: Mapped[str | None] = mapped_column(String(255))
    # How confident the OS guess is, and what it was derived from. An nmap
    # fingerprint at 87% and one at 100% are different claims, and a report
    # that prints only the name turns the first into the second.
    os_accuracy: Mapped[int | None] = mapped_column(Integer)
    mac_address: Mapped[str | None] = mapped_column(String(32))
    mac_vendor: Mapped[str | None] = mapped_column(String(128))
    hostnames: Mapped[str | None] = mapped_column(Text)      # JSON list
    # Everything a scanner reported that has no column of its own: OS class
    # rows, uptime, TCP sequence analysis, traceroute, host-level NSE output.
    # Kept whole because discarding it to fit a schema is how you find out
    # six weeks later that the one field you needed was thrown away.
    extra: Mapped[str | None] = mapped_column(Text)          # JSON object

    notes: Mapped[str | None] = mapped_column(Text)
    tags: Mapped[str | None] = mapped_column(Text)

    #: Every address this target answers at, oldest observation first.
    #:
    #: `lazy="selectin"`, not the default. A Target is almost never
    #: rendered without its addresses — the grid, the modal, the report
    #: and `TargetOut` all want them — and a lazy load inside the async
    #: session raises MissingGreenlet rather than quietly issuing a
    #: query, so "load it when touched" is not an option here. One extra
    #: SELECT per page of targets beats a hundred, and beats a crash.
    #:
    #: Writes go through `app/addresses.py`, never by appending a bare
    #: `TargetAddress`: an address row is unique per project and shared
    #: between targets, so attaching one is find-or-create, not create.
    addresses: Mapped[list[TargetAddress]] = relationship(
        secondary=target_address_links,
        order_by=target_address_links.c.id,
        back_populates="targets",
        lazy="selectin",
        passive_deletes=True,
    )
    project: Mapped[Project] = relationship(back_populates="targets")
    events: Mapped[list[Event]] = relationship(
        back_populates="target", cascade="all, delete-orphan", passive_deletes=True,
        order_by="Event.at.desc()",
    )
    implants: Mapped[list[Implant]] = relationship(
        back_populates="target", cascade="all, delete-orphan", passive_deletes=True,
    )
    web_addresses: Mapped[list[WebAddress]] = relationship(
        back_populates="target", cascade="all, delete-orphan", passive_deletes=True,
    )
    services: Mapped[list[Service]] = relationship(
        back_populates="target", cascade="all, delete-orphan", passive_deletes=True
    )
    vulns: Mapped[list[Vuln]] = relationship(
        back_populates="target", cascade="all, delete-orphan", passive_deletes=True
    )
    pocs: Mapped[list[Poc]] = relationship(
        back_populates="target", cascade="all, delete-orphan", passive_deletes=True
    )

    @property
    def ip_addresses(self) -> list[str]:
        """Every address, as plain strings, oldest observation first."""
        return [a.address for a in self.addresses]

    @property
    def ip_address(self) -> str | None:
        """The first address observed, or None.

        **Read-only, and deliberately so.** There used to be a column
        here and a great deal of code still wants one address to print:
        a report table cell, the REST summary, the agent's host list.
        Those are all fine — what is not fine is writing through it,
        because "set the address" has no meaning once a host may have
        four. Assigning raises AttributeError, which is the correct and
        loud failure; `app/addresses.py` is where addresses are written.

        "First observed", not "primary". Nothing here ranks addresses,
        because nothing in the data does: the A record a scanner happened
        to hit first is not more real than the other three. Callers that
        need the whole truth read `ip_addresses`.
        """
        a = self.addresses
        return a[0].address if a else None

    # ------------------------------------------------------- geoip
    # Geolocation is a fact about an ADDRESS (see `TargetAddress`), and
    # these roll it up to the target for the places that show one row
    # per host. They mirror `ip_address`/`ip_addresses` deliberately:
    # one value for a cell, the whole set beside it, and the singular
    # one means "first observed" rather than "primary", because nothing
    # in the data ranks a host's addresses.

    @property
    def geo_countries(self) -> list[str]:
        """Distinct ISO country codes across this target's addresses.

        More than one is not a glitch. A host behind a CDN or an
        anycast front genuinely answers in several countries at once,
        and that is frequently the single most interesting thing on
        the row — flattening it to the first would hide exactly the
        case worth looking at.
        """
        out: list[str] = []
        for a in self.addresses:
            if a.geo_country and a.geo_country not in out:
                out.append(a.geo_country)
        return out

    @property
    def geo_country(self) -> str | None:
        """The first located address's country, for a one-value cell."""
        c = self.geo_countries
        return c[0] if c else None

    @property
    def geo_country_name(self) -> str | None:
        """The long name matching `geo_country`. "JP" -> "Japan"."""
        want = self.geo_country
        if not want:
            return None
        for a in self.addresses:
            if a.geo_country == want and a.geo_country_name:
                return a.geo_country_name
        return None

    @property
    def geo_pending(self) -> int:
        """How many of this target's addresses have never been located.

        The field that keeps the column honest. A blank country can
        mean the address was never looked up or that it was looked up
        and nothing is known, and those are different claims — one is
        a gap in our coverage and the other is a fact about MaxMind's
        data. Without this the UI would have to guess, and it would
        guess the flattering way.
        """
        return sum(1 for a in self.addresses if a.geo_at is None)


class TargetAddress(Base, TimestampMixin):
    """One address, within one project.

    **Scoped per project, never global.** The unique constraint is on
    (project_id, address) rather than on the address alone, and that is
    load-bearing twice over. Engagements legitimately recur against the
    same estate, and a global address row would join two clients' data
    through a shared CDN edge — the same reason `Target` is keyed per
    project and not globally.

    Why a row of its own rather than (target_id, address) pairs in one
    table: "which other names answer here" is the question the shared-
    hosting and CDN cases turn on, and with an address entity it is a
    foreign-key join rather than a string scan over every target in the
    installation. It also means the address is written once and spelled
    one way, so `203.0.113.9` and ` 203.0.113.9 ` cannot become two
    different co-tenancy groups.

    Note what this table does NOT do: carrying an address here says
    nothing about scope. An address is in scope when the scope document
    says so, or when a host that matches the document directly was
    observed at it — see `ScopeIndex.check`. Sharing an address with an
    in-scope name is not inheritance, and must never become it.
    """
    __tablename__ = "target_addresses"
    __table_args__ = (
        UniqueConstraint("project_id", "address",
                         name="uq_target_address_project_addr"),
        Index("ix_target_addresses_project_addr", "project_id", "address"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    #: The compressed, lowercase literal. 45 chars covers the longest
    #: IPv6 form including an embedded IPv4 and a zone id.
    address: Mapped[str] = mapped_column(String(45), index=True)
    #: 4 or 6. Stored rather than re-parsed because the range-coverage
    #: query filters on it per row, and parsing a few thousand strings
    #: per request to answer "is this v4" is work the database can do.
    version: Mapped[int] = mapped_column(Integer, nullable=False,
                                         server_default="4", default=4)

    # ------------------------------------------------------- geoip
    #: Where MaxMind places this address, tagged onto the ADDRESS
    #: rather than onto any target, because that is what it is a fact
    #: about. Every name that answers here shares it, for the same
    #: reason an open port does.
    #:
    #: All nullable: geolocation is optional, often partial, and
    #: absent entirely for private ranges. A null country means "not
    #: looked up or not known", which `geo_at` disambiguates.
    geo_country: Mapped[str | None] = mapped_column(String(2))
    geo_country_name: Mapped[str | None] = mapped_column(String(80))
    geo_subdivision: Mapped[str | None] = mapped_column(String(80))
    geo_city: Mapped[str | None] = mapped_column(String(120))
    geo_latitude: Mapped[float | None] = mapped_column(Float)
    geo_longitude: Mapped[float | None] = mapped_column(Float)
    #: MaxMind's stated precision in km, and the field that stops the
    #: coordinates lying. An address it cannot place answers with the
    #: centroid of its country and a radius near 1000 km; a real city
    #: answers with 20. Without this the two are identical and a map
    #: pins Google's resolvers to a field in Kansas.
    geo_accuracy_km: Mapped[int | None] = mapped_column(Integer)
    geo_asn: Mapped[int | None] = mapped_column(Integer, index=True)
    geo_org: Mapped[str | None] = mapped_column(String(160))
    #: When the lookup ran. Distinguishes "no data for this address"
    #: from "never asked", which otherwise look the same and lead to
    #: re-looking-up every private address on every pass.
    geo_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    targets: Mapped[list[Target]] = relationship(
        secondary=target_address_links,
        back_populates="addresses",
        passive_deletes=True,
    )


class Service(Base, TimestampMixin):
    __tablename__ = "services"
    __table_args__ = (
        UniqueConstraint("target_id", "port", "protocol", name="uq_service_target_port_proto"),
        Index("ix_services_state", "state"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), index=True
    )
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(8), default="tcp")
    state: Mapped[str] = mapped_column(String(16), default="open")
    # Never NULL once a scanner has looked: a port whose service could not be
    # identified is recorded as UNKNOWN, which is a finding. An empty cell
    # reads as "nobody checked" and the two get confused in exactly the
    # situation where it matters.
    name: Mapped[str | None] = mapped_column(String(128))
    product: Mapped[str | None] = mapped_column(String(255))
    version: Mapped[str | None] = mapped_column(String(128))
    extrainfo: Mapped[str | None] = mapped_column(String(255))
    tunnel: Mapped[str | None] = mapped_column(String(32))       # "ssl"
    # nmap's own confidence in the -sV match, and how it got there.
    method: Mapped[str | None] = mapped_column(String(32))       # table | probed
    confidence: Mapped[int | None] = mapped_column(Integer)
    cpe: Mapped[str | None] = mapped_column(Text)                # JSON list
    reason: Mapped[str | None] = mapped_column(String(64))       # syn-ack, reset…
    # Port-level NSE output, {script-id: output}. This is where ssl-cert,
    # http-title, smb-os-discovery and friends land.
    scripts: Mapped[str | None] = mapped_column(Text)            # JSON object
    # What the service said about itself: "Apache 2.4.52", "OpenSSH_9.6p1".
    # NOT a place for commentary — see `notes`.
    banner: Mapped[str | None] = mapped_column(Text)
    # What a person recorded about it. Kept apart from the banner because
    # the two answer different questions, and conflating them put
    # "coverage gap" and "Created by DEADEYE for T138 residue" in a column
    # whose whole job is to say what software is listening.
    notes: Mapped[str | None] = mapped_column(Text)

    target: Mapped[Target] = relationship(back_populates="services")


class PortScanCoverage(Base):
    """Which ports have been scanned with which technique, per target.

    Separate from `services` because the two answer different
    questions. A `Service` row says *something was found here*;
    coverage says *this was looked at*. A scan of 1-65535 that finds
    one open port leaves one service row, and without this table
    "was 8080 ever checked?" cannot be distinguished from "8080 is
    closed" — which is exactly the question the next scan needs
    answered.

    Stored as ranges rather than a row per port: a full TCP sweep of
    one host would otherwise be 65,535 rows for each technique.

    `technique` is one of `app.portcoverage.LEVELS` — syn, connect or
    version, weakest to strongest — and is taken from what the scanner
    reported it actually did, never from what it was asked to do. See
    the module docstring there for why those differ and which way the
    ambiguity is resolved.

    Rows accumulate rather than being updated in place. A host scanned
    `1-1024` with syn and later `80` with version holds both, and the
    stronger one wins on 80 by the ordering, not by having overwritten
    anything. Keeping the weaker row means "when was this last swept
    at all" stays answerable.
    """

    __tablename__ = "port_scan_coverage"
    __table_args__ = (
        Index("ix_pscov_target_proto", "target_id", "protocol"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), index=True
    )
    protocol: Mapped[str] = mapped_column(String(8), default="tcp")
    technique: Mapped[str] = mapped_column(String(16))
    #: Inclusive, both ends.
    port_lo: Mapped[int] = mapped_column(Integer)
    port_hi: Mapped[int] = mapped_column(Integer)
    scanned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    #: What produced this, for "why does it think 80 is covered" — the
    #: tool and version as the importer reported them, e.g. "nmap 7.94".
    #: A string rather than a foreign key: coverage arrives from agent
    #: results and from hand uploads alike, and there is no one table
    #: that both land in to point at.
    source: Mapped[str | None] = mapped_column(String(64))


class Vuln(Base, TimestampMixin):
    __tablename__ = "vulns"
    __table_args__ = (Index("ix_vulns_target_sev", "target_id", "severity"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), index=True
    )
    title: Mapped[str] = mapped_column(String(1000))
    severity: Mapped[str] = mapped_column(String(16), default="info", index=True)
    status: Mapped[str] = mapped_column(String(32), default="open")
    #: Whether a PERSON thinks this is real, as distinct from
    #: `status`, which is what has been done about it. The two are
    #: independent: a confirmed issue can be open and a false
    #: positive can be closed, and one column could not say both.
    #:
    #: Defaults to `needs_investigating` because a scanner has not
    #: decided anything. The field exists to separate what a tool
    #: reported from what somebody concluded, so defaulting to
    #: either verdict would put words in their mouth.
    triage: Mapped[str] = mapped_column(
        String(24), default="needs_investigating",
        server_default="needs_investigating", index=True)
    port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(String(8))
    description: Mapped[str | None] = mapped_column(Text)
    # Kept apart from the description because a report needs them in
    # different columns. Scanners supply it (Nessus `solution`, Faraday
    # `resolution`); folding it into the description, as the first version
    # of the Nessus importer did, means it can never be pulled back out.
    remediation: Mapped[str | None] = mapped_column(Text)
    # scanner | agent | manual. A client reading a report is entitled to
    # know which advice came from a tool, which from a person, and which
    # was written by a model — they do not carry the same weight.
    remediation_source: Mapped[str | None] = mapped_column(String(16), index=True)
    #: How many times the agent has tried and failed. Capped, so one
    #: finding that always errors cannot occupy the queue forever.
    #:
    #: server_default, not just default=0: a Python-side default produces
    #: `ADD COLUMN ... NOT NULL` with no DDL default, which neither SQLite
    #: nor Postgres will accept against a table that already has rows.
    remediation_attempts: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0", default=0)
    remediation_error: Mapped[str | None] = mapped_column(String(500))
    # Stable id from the source system, so a re-import updates in place rather
    # than forking a duplicate. Unique per project, not globally.
    external_id: Mapped[str | None] = mapped_column(String(128), index=True)

    # ---- lifecycle: what happened to this between scans -------------
    #
    # See `app/lifecycle.py`. These three answer "is it still there",
    # which a row that only ever had `created_at` could not: a finding
    # written in March sat at `open` for ever, through nine re-scans
    # that no longer saw it.
    #
    #: Which tool reported it -- the import format (`nmap`, `nuclei`,
    #: `burp`), or the in-process scanner's own name. Matched against
    #: `finding_sweeps.scanner`, so an nmap run cannot resolve a Burp
    #: finding.
    #:
    #: NULL means nobody is responsible for looking again: a finding
    #: somebody typed in, or one from before this existed. Those are
    #: never resolved by a sweep — a person's finding is not something
    #: a tool gets to close.
    #: The web asset this finding came out of, when it came out of
    #: one. NULL for everything else — a port scan finding, a page
    #: finding, something somebody typed in.
    #:
    #: Stored rather than derived. The asset URL has always been in
    #: the description (see `assetwork.origin_block`), and parsing
    #: prose to answer "how many findings does this bundle carry" is
    #: the arrangement that put `codename` and `remediation` in the
    #: database and nowhere else.
    asset_id: Mapped[int | None] = mapped_column(
        ForeignKey("web_assets.id", ondelete="SET NULL"), index=True)
    scanner: Mapped[str | None] = mapped_column(String(64), index=True)
    #: When a scan first reported it, and when one last did. Distinct
    #: from `created_at`/`updated_at`, which move for reasons that have
    #: nothing to do with observation — a triage change, a remediation
    #: being written, a severity edit.
    first_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), index=True)
    #: The manifest of the run that last REPORTED it, so a later
    #: sweep can be checked for being able to find the same thing.
    found_by_manifest: Mapped[str | None] = mapped_column(String(32))

    target: Mapped[Target] = relationship(back_populates="vulns")


class RunManifest(Base):
    """What one scan configuration was, keyed by its hash.

    Stored once per distinct configuration rather than on every
    sweep row: one nuclei profile covers every host in an
    engagement, and copying the same JSON four thousand times would
    be four thousand copies of one sentence.

    Kept at all because a hash that cannot be explained is a hash
    nobody will trust when it says two runs differ. "The
    configuration changed" is only actionable if somebody can see
    which part of it.
    """
    __tablename__ = "run_manifests"

    #: The hash itself is the key. Two runs with identical
    #: configuration ARE the same manifest, so there is nothing for a
    #: surrogate id to distinguish.
    manifest: Mapped[str] = mapped_column(String(32), primary_key=True)
    scanner: Mapped[str] = mapped_column(String(64), index=True)
    #: The selectors that produced the hash, as JSON. Shown to a
    #: person reading why a finding could not be called resolved.
    detail: Mapped[str] = mapped_column(Text)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False)


class FindingSweep(Base):
    """One tool looked at one host, and this is when it last did.

    The positive record that makes `resolved` sayable. Without it,
    the absence of a finding from a new scan means nothing: a nuclei
    run with a narrower template set, a scan that errored half way
    and a host that was down all produce the same silence, and none
    of them is a remediation.

    One row per (target, scanner), holding the LAST time rather than
    every time. An append log over months of recurring scanning
    would be enormous and would answer no question this does not --
    nothing asks "how many times", only "when last".
    """
    __tablename__ = "finding_sweeps"
    __table_args__ = (
        # The lookup is always (target, scanner), and it is also the
        # uniqueness: two rows for one pair would mean two answers to
        # "when did nmap last look at this host".
        Index("ix_finding_sweeps_target_scanner", "target_id", "scanner",
              unique=True),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    #: Denormalised from the target so a project's whole sweep table
    #: loads in one query. A report over 4,000 findings would
    #: otherwise join per finding.
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    target_id: Mapped[int] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    scanner: Mapped[str] = mapped_column(String(64))
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                         nullable=False)
    #: What this run was configured to look FOR. See `app/manifest.py`.
    #:
    #: Without it, `resolved` had a hole in it: a nuclei run with
    #: `-severity critical` does not report the high-severity finding
    #: the previous run found, and nothing about the tool name, the
    #: host or the timestamp says it was configured not to look.
    #:
    #: NULL means the configuration was not recorded — every scan
    #: imported before this, and every file somebody uploads by hand.
    #: That is NOT the same as "configured differently", and
    #: `lifecycle.verdict` treats the two differently.
    manifest: Mapped[str | None] = mapped_column(String(32), index=True)


class FindingSecret(Base, TimestampMixin):
    """The actual credential behind a secret finding.

    Deliberately NOT in `vulns.description`. That field is listed,
    searched, exported into reports and pasted into Slack, and a
    credential in it is a credential in all of those. Here it is
    read by exactly one endpoint, which checks a role and writes an
    audit entry before answering.

    The finding therefore stays shareable while the value stays
    deliberate: somebody who needs to verify or rotate a key can
    see it, and looking leaves a record of who did.
    """
    __tablename__ = "finding_secrets"

    id: Mapped[int] = mapped_column(primary_key=True)
    vuln_id: Mapped[int] = mapped_column(
        ForeignKey("vulns.id", ondelete="CASCADE"), unique=True, index=True)
    secret: Mapped[str] = mapped_column(Text)
    detector: Mapped[str | None] = mapped_column(String(128))
    #: Where it was found. Also formatted into the finding's
    #: description for a human reading one finding; here as columns
    #: so a list of secrets can show origins without parsing prose
    #: back out of a text field.
    #:
    #: NULL means not recorded -- rows written before these columns
    #: existed whose description did not parse. Not the same as "no
    #: URL", and the UI says so rather than showing a blank.
    asset_url: Mapped[str | None] = mapped_column(Text)
    path: Mapped[str | None] = mapped_column(Text)
    line: Mapped[int | None] = mapped_column(Integer)


class Takeover(Base, TimestampMixin):
    """A hostname whose CNAME points at something unclaimed.

    Its own table rather than a `Vuln`, because the lifecycle is
    different: this is re-derived from DNS every time the detector
    runs, and a vuln row is written once and triaged forever. Folding
    them together would mean either re-raising a finding an operator
    has already dismissed, or never noticing that a dangling record
    was finally cleaned up.

    `verdict` carries how it was decided, and the three values are not
    degrees of the same thing -- see `app/takeover.py`. `dangling` and
    `fingerprint` are evidence. `candidate` is the absence of evidence
    either way, and it is kept visible rather than dropped because
    "this points at Heroku and we could not check" is a real state an
    operator should see, not a finding to assert.
    """
    __tablename__ = "takeovers"
    __table_args__ = (
        UniqueConstraint("project_id", "hostname",
                         name="uq_takeover_project_hostname"),
        Index("ix_takeovers_project_verdict", "project_id", "verdict"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    #: Indexed because the detector deletes through it on every pass.
    #: `web_addresses.service_id` had no index and deleting 46,811
    #: services sequentially scanned 294,251 rows per delete; this is
    #: the same shape and gets the index up front.
    target_id: Mapped[int | None] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), index=True)

    hostname: Mapped[str] = mapped_column(String(253))
    #: The hop that landed on the provider, which is not always the
    #: last one in the chain.
    cname: Mapped[str] = mapped_column(String(253))
    #: The whole chain as observed, newline separated, so a reader can
    #: see what pointed at what without re-resolving.
    cname_chain: Mapped[str | None] = mapped_column(Text)
    provider: Mapped[str] = mapped_column(String(64))
    #: False when the name is not freely re-registerable -- the record
    #: still dangles and should still go, but it is hygiene rather
    #: than an exploitable takeover, and conflating the two is how a
    #: report overstates its own findings.
    claimable: Mapped[bool] = mapped_column(Boolean, nullable=False,
                                            server_default="true", default=True)

    #: One of `takeover.VERDICTS`.
    verdict: Mapped[str] = mapped_column(String(16), nullable=False,
                                         server_default="candidate",
                                         default="candidate")
    #: What convicted it: the marker string that matched, or the name
    #: in the chain that failed to resolve. Null for `candidate`,
    #: which is the point of `candidate`.
    evidence: Mapped[str | None] = mapped_column(Text)

    #: One of `TRIAGE_STATES`. Same vocabulary as a vuln so an
    #: operator triages one thing one way.
    state: Mapped[str] = mapped_column(String(32), nullable=False,
                                       server_default="needs_investigating",
                                       default="needs_investigating")
    note: Mapped[str | None] = mapped_column(Text)

    #: When the detector last saw it. Distinguishes "checked today and
    #: still dangling" from a row nothing has confirmed in a month.
    seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Poc(Base, TimestampMixin):
    __tablename__ = "pocs"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), index=True
    )
    title: Mapped[str] = mapped_column(String(500))
    status: Mapped[str] = mapped_column(String(32), default="unconfirmed", index=True)
    path: Mapped[str | None] = mapped_column(String(1000))
    # 0 reproduced | 1 not reproduced | 2 could not test
    exit_code: Mapped[int | None] = mapped_column(Integer)
    notes: Mapped[str | None] = mapped_column(Text)

    target: Mapped[Target] = relationship(back_populates="pocs")


# ===================================================================== auth
# Roles are ordered: readonly < user < admin. An endpoint declares the minimum
# it needs and the check compares ordinals, so adding a role later means
# adding one entry here rather than auditing every route.
ROLES = ("readonly", "user", "admin")
# Site-wide authority is group membership, not a per-user flag -- one
# mechanism instead of two. Membership of this reserved group bypasses every
# per-project ACL. The group cannot be deleted and cannot be emptied, because
# either would permanently lock everyone out of user administration.
SITE_ADMIN_GROUP = "site-admins"
ROLE_ORDER = {r: i for i, r in enumerate(ROLES)}

user_groups = Table(
    "user_groups",
    Base.metadata,
    Column("user_id", ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("group_id", ForeignKey("groups.id", ondelete="CASCADE"), primary_key=True),
)


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    email: Mapped[str | None] = mapped_column(String(255))
    full_name: Mapped[str | None] = mapped_column(String(255))
    # Nullable: a Google-registered account has no local password, and
    # storing an unusable placeholder hash would make "can this user sign in
    # with a password" un-answerable.
    password_hash: Mapped[str | None] = mapped_column(String(255))
    google_sub: Mapped[str | None] = mapped_column(String(64), unique=True, index=True)
    avatar_url: Mapped[str | None] = mapped_column(String(512))
    #: The handle this person uses in Slack, as a default. Offered when
    #: they join an engagement that has Slack, so the common case is
    #: one click rather than typing it again per project -- while
    #: still letting them use a different one, because a consultant
    #: may be in the client's workspace under another name.
    slack_handle: Mapped[str | None] = mapped_column(String(128))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)

    groups: Mapped[list[Group]] = relationship(
        secondary=user_groups, back_populates="users", lazy="selectin")
    acls: Mapped[list[ProjectACL]] = relationship(
        back_populates="user", cascade="all, delete-orphan", passive_deletes=True)

    @property
    def has_password(self) -> bool:
        return bool(self.password_hash)

    @property
    def has_google(self) -> bool:
        return bool(self.google_sub)

    @property
    def is_site_admin(self) -> bool:
        """Site authority is "member of site-admins", nothing else."""
        return any(g.name == SITE_ADMIN_GROUP for g in self.groups)


class Group(Base, TimestampMixin):
    __tablename__ = "groups"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text)

    users: Mapped[list[User]] = relationship(
        secondary=user_groups, back_populates="groups", lazy="selectin")
    acls: Mapped[list[ProjectACL]] = relationship(
        back_populates="group", cascade="all, delete-orphan", passive_deletes=True)


class UserSlackIdentity(Base, TimestampMixin):
    """One person's Slack identity in one workspace.

    The per-project record below answers "did we add them to THIS
    engagement's channel". This answers "who are they in Slack", which
    is a property of the workspace and not of the engagement — someone
    who has already told us their handle for the workspace an
    engagement posts to should not be asked again because a second
    engagement started in the same place.

    Keyed by a digest of the bot token rather than the token itself: it
    is the cheapest stable identifier for "the same Slack", needs no
    extra API call, and storing a second copy of a credential to use as
    a lookup key would be indefensible.
    """
    __tablename__ = "user_slack_identities"
    __table_args__ = (
        UniqueConstraint("user_id", "workspace_key", name="uq_slack_identity"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True)
    #: sha256 of the bot token, truncated. Not reversible to the token.
    workspace_key: Mapped[str] = mapped_column(String(64), index=True)
    handle: Mapped[str | None] = mapped_column(String(128))
    #: Slack's own id. A handle can be changed by its owner; this cannot.
    slack_user_id: Mapped[str | None] = mapped_column(String(32))
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    #: Saying no is per workspace too — someone declining to be added to
    #: a customer's workspace has not declined their own company's.
    declined_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ProjectSlackMember(Base, TimestampMixin):
    """One person's Slack handle for one engagement, and whether we asked.

    Separate from ProjectACL because access can be granted to a group,
    and a group has no Slack handle -- the thing being recorded here is
    about a person on a project, which is not the same shape as a
    grant.

    `declined_at` exists so the prompt is asked once and not on every
    visit. Someone who says no is saying no to this engagement's
    channels, not to being asked ever again about anything.
    """
    __tablename__ = "project_slack_members"
    __table_args__ = (
        UniqueConstraint("project_id", "user_id", name="uq_slack_member"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True)
    #: What they gave for this project. May differ from the profile
    #: default, which is the whole reason it is stored per project.
    handle: Mapped[str | None] = mapped_column(String(128))
    #: Slack's own id, once resolved. Kept because a handle can be
    #: changed by its owner and the id cannot.
    slack_user_id: Mapped[str | None] = mapped_column(String(32))
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    declined_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    #: What happened when we tried to add them, kept verbatim. An
    #: invite that failed should be visible as a failure rather than
    #: looking like it worked.
    invite_result: Mapped[str | None] = mapped_column(Text)


class ProjectACL(Base, TimestampMixin):
    """One grant: a role on a project, to EITHER a user or a group.

    Both subject columns are nullable with exactly one set — enforced by a
    CHECK constraint rather than convention, because an ACL row that grants to
    nobody (or to both) is a silent authorisation hole.
    """
    __tablename__ = "project_acls"
    __table_args__ = (
        CheckConstraint(
            "(user_id IS NOT NULL AND group_id IS NULL) OR "
            "(user_id IS NULL AND group_id IS NOT NULL)",
            name="ck_acl_exactly_one_subject"),
        UniqueConstraint("project_id", "user_id", name="uq_acl_project_user"),
        UniqueConstraint("project_id", "group_id", name="uq_acl_project_group"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True)
    group_id: Mapped[int | None] = mapped_column(
        ForeignKey("groups.id", ondelete="CASCADE"), index=True)
    role: Mapped[str] = mapped_column(String(16), default="readonly")

    project: Mapped[Project] = relationship(back_populates="acls")
    user: Mapped[User | None] = relationship(back_populates="acls")
    group: Mapped[Group | None] = relationship(back_populates="acls")


class ApiKey(Base, TimestampMixin):
    """Long-lived credential for scripts and the MCP server.

    Only a hash is stored; the plaintext is shown once at creation. A prefix is
    kept so a key can be identified in a list without revealing it.
    """
    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(128))
    prefix: Mapped[str] = mapped_column(String(12), index=True)
    key_hash: Mapped[str] = mapped_column(String(255))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, index=True)


# =================================================================== actions
# Statuses. `unavailable` is deliberately distinct from `failed`: "no probe
# backend is configured" is a fact about this deployment, not about the
# target, and collapsing the two would read as though the host refused us.
ACTION_STATUSES = ("pending", "running", "done", "failed", "unavailable")


#: Service states that are evidence the host answered. `open` means
#: something replied on that port, which is proof of life regardless of
#: whether anything pinged it. `filtered` and `open|filtered` are the
#: absence of a reply and prove nothing; `closed` is ambiguous in imported
#: data, where it is often an operator's note about a port learned from a
#: config rather than a probe result, so it is deliberately excluded.
ALIVE_STATES = frozenset({"open"})


def implies_alive(state: str | None) -> bool:
    return (state or "").strip().lower() in ALIVE_STATES


#: Timeline entry kinds. `note` is the only one a human writes directly;
#: everything else is recorded by the code that performed the change.
EVENT_KINDS = (
    "discovered",   # the target first appeared, and from where
    "note",         # written by a person
    "scan",         # a tool ran against it (nmap, dirb, a banner grab)
    "service",      # a port/service appeared, changed or closed
    "vuln",         # a finding was raised, amended or resolved
    "poc",          # a proof-of-concept was attached or its result changed
    "credential",   # a credential for this host was recorded
    "implant",      # a C2 agent checked in from this host
    "web",          # URLs discovered on an http(s) service
    "change",       # a field on the target itself was edited
    "status",       # alive/hacked flipped — the two that change how it is read
)


class Event(Base):
    """One thing that happened to a target, in order.

    Separate from an audit log: this is the engagement narrative for a single
    asset — when it was discovered, what answered on it, what was tried, what
    was found, and every note anyone wrote. The question it exists to answer
    is "what do we know about this host and how did we come to know it",
    which the current-state tables cannot answer because they only hold the
    latest value.

    Append-only by convention. Entries are never rewritten when the
    underlying row changes; a correction is another entry.
    """
    __tablename__ = "events"
    __table_args__ = (
        Index("ix_events_target_at", "target_id", "at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True)
    kind: Mapped[str] = mapped_column(String(16), index=True)
    # One line, written to be read in a list without expanding anything.
    summary: Mapped[str] = mapped_column(Text)
    # Optional long form: the NSE output, the diff, the note body.
    detail: Mapped[str | None] = mapped_column(Text)
    # Who or what did it. A username, or a tool name like "nmap" — the
    # distinction matters when reconstructing who to ask about an entry.
    actor: Mapped[str | None] = mapped_column(String(128))
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"))
    # Free-form provenance: a scan id, a file name, an action id.
    source: Mapped[str | None] = mapped_column(String(255))

    target: Mapped[Target] = relationship(back_populates="events")


class WebAddress(Base, TimestampMixin):
    """One URL seen on an http(s) service.

    Separate from Service because a web server is not one thing: a single
    :443 can carry a login page, an admin console, an API and a forgotten
    status endpoint, and the engagement question is almost always "what is
    reachable" rather than "what port is open". Flattening those into the
    service's banner loses the only list anyone actually wants.

    Keyed on `(target_id, url)`. The URL is stored normalised — scheme and
    host lowercased, the default port dropped — so the same page found by
    httpx, Burp and nuclei is one row with three sources rather than three
    rows, which is what makes "everything we have seen on this host" a
    question the table can answer.
    """
    __tablename__ = "web_addresses"
    # Keyed on (target, METHOD, url). The method is part of the identity
    # because `GET /login` and `POST /login` are different things and a
    # tester needs both; keying on the URL alone silently kept whichever
    # the importer happened to see last.
    #
    # Never NULL — it is a unique key column, and SQL treats NULLs as
    # distinct from each other, so a nullable method would defeat the
    # deduplication it is part of. Unknown is "", not NULL.
    __table_args__ = (
        UniqueConstraint("target_id", "exchange_hash",
                         name="uq_weburl_target_method_url"),
        Index("ix_weburl_target_status", "target_id", "status_code"),
        # The page sweep's queue, and the reason it is PARTIAL: every
        # row starts with `scanned_at` NULL, so an index on the column
        # alone contains the whole table and the planner ignores it.
        # This one holds only the rows still owed, in id order, and
        # shrinks as they are done. Measured on 168,231 rows / 1.7 GB
        # -- see migration 9c2e1f4ab7d3.
        Index("ix_web_addresses_unscanned", "id",
              postgresql_where=text("scanned_at IS NULL"),
              sqlite_where=text("scanned_at IS NULL")),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    #: Indexed because it is a foreign key that rows get deleted
    #: through. Without it, deleting one service makes Postgres scan
    #: every web address to check the constraint — clearing 46,811
    #: services against 294,251 addresses did not finish in ten
    #: minutes. An unindexed FK is a landmine, not a missing nicety.
    service_id: Mapped[int | None] = mapped_column(
        ForeignKey("services.id", ondelete="SET NULL"), index=True)
    #: Unbounded: a real URL in a proxy history reached 8,221 characters,
    #: and SQLite stored it happily because it ignores VARCHAR limits.
    #: Postgres does not, so the declared 2048 was a lie that only
    #: surfaced on the first import against a real database.
    url: Mapped[str] = mapped_column(Text)
    #: sha256 of `url`, which is what the uniqueness and the upsert
    #: lookup are actually keyed on. Postgres btree entries are capped
    #: near 2.7 KB, so a long URL cannot be indexed directly at all —
    #: and comparing a 64-character digest beats comparing kestrelbytes of
    #: query string on every row of an import.
    url_hash: Mapped[str] = mapped_column(String(64), index=True)
    #: sha256 of (method, url, request, response) — what makes one
    #: captured exchange distinct from another.
    #:
    #: Identity used to be (target, method, url), which collapsed every
    #: hit of a URL into one row and kept only the last response. For a
    #: proxy history that is the wrong unit: the same endpoint probed
    #: ten ways is ten pieces of evidence, and the differences between
    #: the responses are usually the finding. The URL is still indexed,
    #: so the UI can group the hits back together under it.
    exchange_hash: Mapped[str] = mapped_column(String(64), index=True)
    scheme: Mapped[str] = mapped_column(String(8), default="http")
    port: Mapped[int | None] = mapped_column(Integer, index=True)
    path: Mapped[str] = mapped_column(String(1024), default="/", index=True)
    method: Mapped[str] = mapped_column(
        String(12), nullable=False, server_default="", default="", index=True)
    status_code: Mapped[int | None] = mapped_column(Integer, index=True)
    title: Mapped[str | None] = mapped_column(String(512))
    content_type: Mapped[str | None] = mapped_column(String(128))
    content_length: Mapped[int | None] = mapped_column(Integer)
    webserver: Mapped[str | None] = mapped_column(String(255))
    tech: Mapped[str | None] = mapped_column(Text)          # JSON list
    # Which tools have reported this URL, comma separated. A URL both httpx
    # and Burp saw is better evidence than one only a wordlist guessed at.
    sources: Mapped[str | None] = mapped_column(String(255))
    #: True once something actually fetched it, as opposed to merely
    #: referencing it. A link harvested from a page is not a visited page.
    crawled: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    notes: Mapped[str | None] = mapped_column(Text)

    # The exchange itself, where the source had it. Capped on the way in —
    # see app/importers/burphistory.py. These are deliberately NOT returned
    # by the list endpoint: a 5,000-row page would be hundreds of
    # megabytes, and they are only wanted one at a time.
    #
    # They routinely contain session cookies, bearer tokens and
    # credentials. The database is already secret material (see
    # Credential) but this raises the stakes, and the packet view says so.
    request: Mapped[str | None] = mapped_column(Text)
    response: Mapped[str | None] = mapped_column(Text)
    #: Whether either side was cut short, so the viewer does not present a
    #: truncated body as the whole exchange.
    #:
    #: server_default again: a Python-side default emits `ADD COLUMN ...
    #: NOT NULL` with no DDL default, which no database accepts against a
    #: populated table. Second time this has bitten; it is in the README.
    truncated: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="0", default=False)
    #: When the asset scanners last read this response body. NULL
    #: means "never", which is what the page sweep queues on -- the
    #: same resume key `WebAssetFile.scanned_at` gives the file
    #: sweep, for the same reason: a run interrupted at 300 of 900
    #: picks up at 301.
    #:
    #: Deliberately not set on a response the scanners failed to
    #: read. A timeout has examined nothing, and stamping the row
    #: would retire it from the queue for ever on the strength of a
    #: failure.
    #: Indexed by `ix_web_addresses_unscanned`, a PARTIAL index on
    #: `id WHERE scanned_at IS NULL` declared in __table_args__ --
    #: not `index=True` here. An index on the column alone contains
    #: every row, which is exactly no help to a query whose whole
    #: job is to find the rows where it is still NULL.
    scanned_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True))

    target: Mapped[Target] = relationship(back_populates="web_addresses")


class WebScreenshot(Base, TimestampMixin):
    """A picture of one URL, as a browser drew it.

    Taken by a ghost (`ghost/internal/tasks/screenshot.go`), because
    the ghost is the thing standing inside the engagement: a capture
    made from this server would come from the wrong egress address
    and might be a photograph of a different front door.

    # One row per URL, not per capture

    `web_addresses` is keyed on the EXCHANGE, because the same
    endpoint probed ten ways is ten pieces of evidence. A picture is
    not evidence of that kind: ten captures of the same URL are ten
    copies of one page, at ~200 KB each, across an estate that has
    reached 51,000 URLs. So this is keyed on `(target_id, url_hash)`
    and a re-shoot REPLACES the image, with `captured_at` saying how
    old the one on file is. Keeping the history would be the single
    biggest thing in the database and would answer a question nobody
    asked.

    # Why the bytes are in the database

    The alternative is a directory on disk, and it loses on every
    count that matters here. This application has no file store: the
    only thing it ever writes outside the database is a spooled
    upload that is deleted when the import finishes. A directory
    would be a second durability story -- another thing to back up,
    another thing to restore in the right order, a path to configure
    per deployment, and orphaned files to reap when a project is
    deleted. In the database, `ON DELETE CASCADE` is the reaper and
    the existing backup is the backup.

    The usual argument against blobs is that they bloat the rows the
    planner walks, and Postgres already answers it: a `bytea` this
    size is TOASTed out of line, so a row here is a few hundred bytes
    plus a pointer, and nothing but the image endpoint ever selects
    the column (it is `deferred`, so an ORM load does not drag it in
    by accident). The precedent is beside it: `web_addresses.response`
    holds up to 2 MB of captured body per row already.

    What keeps the total bounded is the CAP, not the storage choice:
    one image per URL, a hard size limit on the way in (see
    `importers/screenshot.py`), and a task that photographs a page at
    a time by request rather than a standing order that photographs
    an estate nobody asked about.
    """
    __tablename__ = "web_screenshots"
    __table_args__ = (
        # One picture per URL per target. The uniqueness rides on the
        # hash, never on `url`: a Postgres btree entry caps near
        # 2.7 KB and a real URL in this database has reached 8,221
        # characters, so an index on the text itself fails the INSERT
        # rather than the query.
        UniqueConstraint("target_id", "url_hash", name="uq_screenshot_url"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    #: Indexed because rows are deleted THROUGH it. An unindexed FK is
    #: the landmine this codebase has already stepped on once:
    #: clearing 46,811 services scanned 294,251 web addresses per
    #: delete and did not finish in ten minutes.
    target_id: Mapped[int] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    #: The address this is a picture of, where one is on file. SET
    #: NULL rather than CASCADE, and indexed for the same reason as
    #: above: a URL row can be re-keyed or removed by a later import,
    #: and losing the photograph because the exchange beside it
    #: changed would throw away the evidence to keep the bookkeeping
    #: tidy.
    web_address_id: Mapped[int | None] = mapped_column(
        ForeignKey("web_addresses.id", ondelete="SET NULL"), index=True)
    url: Mapped[str] = mapped_column(Text)
    url_hash: Mapped[str] = mapped_column(String(64), index=True)
    #: Where the browser ended up. A page that redirects to an SSO
    #: host is a different answer from one that serves its own login
    #: form, and the picture alone cannot say which happened.
    final_url: Mapped[str | None] = mapped_column(Text)
    #: The main document's status, as the browser saw it. NULL means
    #: the browser never reported one -- a navigation that ended in
    #: its own error page -- which is "could not determine" and not
    #: 200.
    status_code: Mapped[int | None] = mapped_column(Integer)
    title: Mapped[str | None] = mapped_column(String(512))
    #: The image. `image/png` today; a column rather than an
    #: assumption so a later JPEG capture is a value and not a
    #: migration.
    content_type: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default="image/png",
        default="image/png")
    #: Deferred: nothing but the image endpoint should ever pull
    #: megabytes off this table, and a listing that forgets to say so
    #: would pull every one of them.
    image: Mapped[bytes] = mapped_column(LargeBinary, deferred=True)
    #: Carried as its own column so a list can show the size without
    #: loading the bytes to measure them.
    bytes: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0", default=0)
    #: Of the image, not of the page. Two URLs with the same digest
    #: are the same picture -- which is how a wildcard host serving
    #: one holding page to 400 names announces itself.
    sha256: Mapped[str | None] = mapped_column(String(64), index=True)
    width: Mapped[int | None] = mapped_column(Integer)
    height: Mapped[int | None] = mapped_column(Integer)
    #: When the shutter went, not when the row was written. A picture
    #: is only as good as its date and an import can be days later.
    captured_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True))
    #: What took it, for the same reason `web_addresses.sources`
    #: exists: a reader needs to know whether this came from a ghost
    #: inside the estate or from somewhere else.
    sources: Mapped[str | None] = mapped_column(String(255))


class AgentSession(Base, TimestampMixin):
    """One conversation with the project agent, shared by the project.

    **The transcript used to live only in the browser.** That was a
    deliberate choice -- see routers/agent.py -- and the reason to
    change it is equally deliberate: an engagement is worked by
    several people, and "what did we already ask the agent" is a
    fact about the engagement, not about whoever happened to have
    the tab open. Two testers duplicating the same question, or
    losing an answer when a tab closes, is the cost of keeping it
    client-side.

    **Scoped to the project, not the user.** Everyone with a role on
    the engagement reads the same thread. Switching project does not
    carry the conversation across -- a different engagement is a
    different subject and a different client, and a transcript that
    followed you between them would mix two clients' data in one
    scroll-back, which is the one thing this application exists to
    prevent.
    """
    __tablename__ = "agent_sessions"
    __table_args__ = (
        # The common read is "the newest session for this project".
        Index("ix_agent_sessions_project_seen", "project_id", "last_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    #: Who opened it. Not who owns it -- see the class docstring.
    opened_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"))
    #: First question, trimmed, so a list of sessions is readable
    #: without opening each one.
    title: Mapped[str | None] = mapped_column(String(200))
    #: Last activity, which is what the list sorts on. Distinct from
    #: `updated_at`: a title correction is not activity.
    last_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    #: Closed sessions stay readable. The record of what was asked
    #: during an engagement is part of the engagement.
    closed: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="0", default=False)

    turns: Mapped[list[AgentTurn]] = relationship(
        back_populates="session", cascade="all, delete-orphan",
        order_by="AgentTurn.seq")


class AgentTurn(Base, TimestampMixin):
    """One message in an agent conversation.

    `content` is the provider-shaped message, as JSON, because that
    is what has to go back to the model on the next turn and
    re-deriving it from prose would not round-trip.

    **A credential never lands here.** `get_finding_secret` returns
    a value that `reveal_secret` releases only to a `user` role and
    only with an audit entry naming who asked. A transcript readable
    by everyone on the project -- including `readonly`, which exists
    precisely to be handed out more freely -- would be a way around
    both. So the tool RESULT for that one tool is replaced with a
    note before it is stored. The agent still saw it in its own
    turn; the database does not keep it.
    """
    __tablename__ = "agent_turns"
    __table_args__ = (
        UniqueConstraint("session_id", "seq", name="uq_agent_turn_seq"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(
        ForeignKey("agent_sessions.id", ondelete="CASCADE"), index=True)
    #: Order within the session. Explicit rather than relying on id,
    #: because the id sequence is shared across every project.
    seq: Mapped[int] = mapped_column(Integer)
    #: user | assistant — the provider's own vocabulary.
    role: Mapped[str] = mapped_column(String(16))
    #: The provider-shaped message, JSON encoded.
    content: Mapped[str] = mapped_column(Text)
    #: Who typed it, for a `user` turn. Null for the assistant.
    author_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"))
    #: What the UI shows: the assistant's prose, or the question.
    #: Kept beside `content` so rendering a transcript does not mean
    #: parsing provider-specific shapes in the browser.
    text: Mapped[str | None] = mapped_column(Text)
    #: The tool calls made on this turn, JSON, already redacted.
    steps: Mapped[str | None] = mapped_column(Text)

    session: Mapped[AgentSession] = relationship(back_populates="turns")


class WebAsset(Base, TimestampMixin):
    """A script, stylesheet or font a page pulls in, and what it is.

    Separate from `WebAddress`, and the separation is a scope
    decision rather than a modelling preference. A page on the
    client's estate loads jQuery from `cdnjs.cloudflare.com`; that
    host is somebody else's infrastructure, it is barred as a target,
    and writing it as an address would either be refused by the gate
    or -- worse -- quietly admitted and then scanned. What it IS is a
    fact about the client's page: this application depends on that
    file. So it is recorded against the page, never as an asset of
    the estate.

    **Keyed on (project, url).** One copy of jQuery referenced by
    four hundred pages is one row with a count, not four hundred
    rows. `sha256` deduplicates further: two URLs serving identical
    bytes are the same dependency under two names, which is how a
    version-pinned CDN path and a `latest` one get recognised as the
    same thing.

    `version` is what the URL admits to -- `jquery-3.6.0.min.js`,
    `bootstrap@5.3.2`, `?v=1.2.3`. It is absent for a hashed bundle
    like `app.a1b2c3.js`, and absent means UNKNOWN rather than
    current: a fingerprinted bundle is the case where the version
    matters most and the filename helps least.
    """
    __tablename__ = "web_assets"
    __table_args__ = (
        UniqueConstraint("project_id", "url", name="uq_web_asset_project_url"),
        Index("ix_web_assets_sha", "sha256"),
        Index("ix_web_assets_name", "name"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    #: The page it was first seen on. A reference, not an owner: the
    #: same asset is usually on many pages, and `seen_on` counts them.
    target_id: Mapped[int | None] = mapped_column(
        ForeignKey("targets.id", ondelete="SET NULL"), index=True)
    first_page: Mapped[str | None] = mapped_column(Text)

    url: Mapped[str] = mapped_column(Text)
    #: The host serving it, which is the whole point of `third_party`.
    host: Mapped[str | None] = mapped_column(String(255), index=True)
    #: script | stylesheet | font | image | iframe | other
    kind: Mapped[str] = mapped_column(String(16), default="script")
    #: Served from somewhere other than the page's own registrable
    #: domain. Indexed because "what do our pages load from other
    #: people" is the question this table exists to answer.
    third_party: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="0", default=False, index=True)

    #: Inferred from the filename. None means the URL did not say.
    name: Mapped[str | None] = mapped_column(String(128))
    version: Mapped[str | None] = mapped_column(String(64))

    #: Set once the bytes have been fetched. Absent means the asset
    #: is known by reference only -- nothing has retrieved it.
    sha256: Mapped[str | None] = mapped_column(String(64))
    bytes: Mapped[int | None] = mapped_column(Integer)
    content_type: Mapped[str | None] = mapped_column(String(128))
    status_code: Mapped[int | None] = mapped_column(Integer)
    #: The file itself, when it was pulled back. Deduplicated by the
    #: unique key above, so one copy per distinct URL rather than one
    #: per page that loads it.
    body: Mapped[str | None] = mapped_column(Text)

    #: When the bytes were last pulled back, and why not if they were
    #: not. A null body cannot distinguish "never tried", "fetched and
    #: it was empty" and "the server refused" -- three different facts
    #: and only the last is about the asset.
    fetched_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True))
    fetch_error: Mapped[str | None] = mapped_column(String(300))
    #: Whether the body looks machine-generated. None means nothing
    #: has looked.
    minified: Mapped[bool | None] = mapped_column(Boolean)
    #: The source map the file pointed at, if it pointed at one.
    sourcemap_url: Mapped[str | None] = mapped_column(Text)
    #: When the scanners last ran over this asset's files.
    scanned_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True))
    #: How many distinct pages reference it.
    seen_on: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="1", default=1)

    project: Mapped[Project] = relationship()


class WebAssetFile(Base, TimestampMixin):
    """One FILE recovered from a web asset.

    The grain matters. A minified bundle is one URL and, once its
    source map is read, a hundred original files -- and a secret or a
    vulnerable call lives in one of those originals, at a real path.
    A finding that can only say "somewhere in app.min.js" has located
    nothing; one that says `src/auth/session.ts:40` is actionable.

    Three origins, kept apart rather than collapsed:

        raw          exactly what the server returned
        beautified   the raw bytes reformatted, when there is no map
        source       an original file out of a source map

    `beautified` is a rendering WE produced and `source` is what the
    developer wrote. Reporting a line number from the first as though
    it were the second would send somebody to a line that exists only
    in our copy.
    """
    __tablename__ = "web_asset_files"
    __table_args__ = (
        UniqueConstraint("asset_id", "origin", "path", name="uq_asset_file"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(
        ForeignKey("web_assets.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    origin: Mapped[str] = mapped_column(String(16))
    path: Mapped[str] = mapped_column(Text)
    body: Mapped[str | None] = mapped_column(Text)
    sha256: Mapped[str | None] = mapped_column(String(64), index=True)
    bytes: Mapped[int | None] = mapped_column(Integer)
    #: When the scanners last ran over THIS file. Per file, not per
    #: asset, so a map that yields new sources on a later fetch gets
    #: them scanned without re-scanning the ninety that did not change.
    scanned_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True))

    asset: Mapped[WebAsset] = relationship()


class WebAssetEndpoint(Base, TimestampMixin):
    """A route a bundle references, that nothing linked to.

    A crawl finds what the application LINKS to; its JavaScript
    contains what it CALLS. The API routes, the admin paths and the
    pages behind a feature flag are all in the bundle and none of
    them is reachable by following anchors.

    **Deliberately not a `Vuln`.** An endpoint is not a finding, it
    is a place to go and look. Filing hundreds of them as
    vulnerabilities would bury the findings that are real.

    **And deliberately not a `WebAddress`.** Those are things
    observed answering. These are strings out of a bundle that may
    or may not exist -- "we found this referenced" has to stay
    distinguishable from "we requested this and it responded".
    """
    __tablename__ = "web_asset_endpoints"
    __table_args__ = (
        UniqueConstraint("asset_id", "value", name="uq_asset_endpoint"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    asset_id: Mapped[int] = mapped_column(
        ForeignKey("web_assets.id", ondelete="CASCADE"), index=True)
    file_id: Mapped[int | None] = mapped_column(
        ForeignKey("web_asset_files.id", ondelete="CASCADE"), index=True)
    #: path | url
    kind: Mapped[str] = mapped_column(String(8))
    value: Mapped[str] = mapped_column(Text)
    #: The hostname, for URLs. A host found this way may itself be
    #: in scope under the engagement's rules; a path never is.
    host: Mapped[str | None] = mapped_column(String(255), index=True)


class WebAssetRef(Base):
    """One page loading one asset.

    The asset holds the bytes ONCE; this holds the fact that a
    particular page pulls it in. jQuery referenced by four hundred
    pages is one `WebAsset` carrying one copy of the file and four
    hundred of these, each a few dozen bytes — rather than four
    hundred copies of jQuery.

    That is also what makes "what does this page load" answerable at
    all. A count on the asset says how popular a library is; it
    cannot say which page is the one still on the old version.
    """
    __tablename__ = "web_asset_refs"
    __table_args__ = (
        UniqueConstraint("asset_id", "page_url", name="uq_asset_ref_page"),
        Index("ix_web_asset_refs_page", "page_url"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(
        ForeignKey("web_assets.id", ondelete="CASCADE"), index=True)
    #: The target the page belongs to, where one is known. SET NULL
    #: rather than CASCADE: losing the target should not erase the
    #: record that the dependency was observed.
    target_id: Mapped[int | None] = mapped_column(
        ForeignKey("targets.id", ondelete="SET NULL"), index=True)
    page_url: Mapped[str] = mapped_column(Text)

    asset: Mapped[WebAsset] = relationship()


#: How a target came to exist. One value today; the column is here
#: because the question "where did this come from" is asked of every
#: row sooner or later, and only the discovering code can answer it.
ORIGIN_SOURCES = (
    "asset",        # named in the code of a web asset this project fetched
)


class TargetOrigin(Base, TimestampMixin):
    """Where a target was discovered, as recorded by whatever found it.

    A bucket named in a JavaScript bundle is not reachable from any
    CIDR, nothing links to it, and no port scan meets it: the file
    that mentions it is the ONLY reason we know it exists. Without
    this table the target arrives in the list with no account of
    itself, and the first question an operator asks -- "where did
    this come from" -- has no answer anywhere in the system.

    **Absent is not nothing.** A target with no row here was not
    found to come from nowhere; nothing recorded where it came from.
    Rows created before this table existed, and targets typed in by
    hand or loaded from a scan import, all have none, and the UI says
    "not recorded" rather than "none" for exactly that reason.

    **Snapshots beside the foreign keys, deliberately.** `asset_id`
    and `file_id` are `SET NULL`: an asset re-fetched, superseded or
    deleted must not take the provenance with it. The URL and path
    are copied in at discovery time so the answer survives the row it
    came from.
    """
    __tablename__ = "target_origins"
    __table_args__ = (
        # One row per (target, place it was found in). A sweep sees
        # the same bundle every pass; without this the table grows
        # without bound while saying nothing new.
        #
        # Keyed on a digest rather than the URL itself: a Postgres
        # btree entry caps near 2.7 KB and bundle URLs run past it,
        # so the index cannot carry the text. Same reason, and same
        # shape, as `web_addresses.url_hash`.
        UniqueConstraint("target_id", "origin_hash", name="uq_target_origin"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    #: Indexed, and not only for reads: deleting a project deletes its
    #: targets, and every delete goes through this key.
    target_id: Mapped[int] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    #: One of ORIGIN_SOURCES.
    source: Mapped[str] = mapped_column(String(16))

    asset_id: Mapped[int | None] = mapped_column(
        ForeignKey("web_assets.id", ondelete="SET NULL"), index=True)
    file_id: Mapped[int | None] = mapped_column(
        ForeignKey("web_asset_files.id", ondelete="SET NULL"), index=True)
    #: The asset the identifier was read out of, copied in at
    #: discovery so it outlives `asset_id`.
    asset_url: Mapped[str | None] = mapped_column(Text)
    #: Which recovered file inside that asset -- `src/config.ts` in a
    #: source map beats "somewhere in app.min.js".
    file_path: Mapped[str | None] = mapped_column(Text)
    #: The page that loads that asset, where one is known. This is
    #: the "site it came from" an operator means.
    page_url: Mapped[str | None] = mapped_column(Text)
    #: sha256 over (source, asset_url, file_path). See the constraint.
    origin_hash: Mapped[str] = mapped_column(String(64), index=True)


# ======================================================= domain discovery
#: How a candidate hostname was arrived at. Recorded because the reader's
#: first question about a suggested name is always "why do you think so".
CANDIDATE_SOURCES = (
    "sibling",      # another name under the same registrable domain
    "label",        # a first label seen elsewhere in the estate, applied here
    "sequence",     # web01 -> web02
    "environment",  # prod -> uat/dev/staging
    "certificate",  # a SAN from a TLS certificate we already captured
    "reference",    # a hostname appearing in captured content or a CNAME
)

CANDIDATE_STATES = ("new", "accepted", "rejected", "exists")


class DomainSearch(Base, TimestampMixin):
    """A domain this project has already handed to enumeration.

    Written for the offline candidate generator, then orphaned when that
    went and enumeration became amass on a Ghost. It was kept rather than
    dropped — a table drop cannot be undone, and the rows were somebody's
    record of what had been run — and it is in use again: every domain
    `/api/domains/enumerate` queues an amass task for gets a row here,
    and Kitchen Sink Lookup reads them to avoid re-queueing a zone it has
    already enumerated.

    **A row means "handed to amass", not "amass finished".** It is
    written when the task is queued, because the thing being prevented is
    a duplicate task, and a run that fails is still a run somebody has to
    decide to repeat. "Rescan already scanned domains" on the request is
    what repeats it.

    `candidates_found` belongs to the generator and stays 0. Amass files
    what it finds as targets directly, so there are no candidate rows to
    count — the column is left rather than repurposed, because a number
    that silently changed meaning is worse than one that is honestly
    zero.
    """
    __tablename__ = "domain_searches"
    __table_args__ = (
        UniqueConstraint("project_id", "domain", name="uq_domsearch_project_domain"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    domain: Mapped[str] = mapped_column(String(255), index=True)
    runs: Mapped[int] = mapped_column(Integer, default=0)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    candidates_found: Mapped[int] = mapped_column(Integer, default=0)
    #: Names already known at the time of the last run, so a later run can
    #: report what is genuinely new rather than re-listing the estate.
    known_at_last_run: Mapped[int] = mapped_column(Integer, default=0)
    requested_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"))
    note: Mapped[str | None] = mapped_column(Text)


class DomainCandidate(Base, TimestampMixin):
    """A hostname worth trying, and why.

    Generated offline from what the project already holds — no lookups, no
    packets. Promotion to a real Target is a deliberate act, because a
    guessed name is a hypothesis and an inventory row is a claim.
    """
    __tablename__ = "domain_candidates"
    __table_args__ = (
        UniqueConstraint("project_id", "name", name="uq_domcand_project_name"),
        Index("ix_domcand_project_state", "project_id", "state"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    root_domain: Mapped[str] = mapped_column(String(255), index=True)
    source: Mapped[str] = mapped_column(String(16), index=True)
    #: 0-100. A ranking hint only — it is derived from how the name was
    #: reached and how often the pattern recurs, not from any evidence the
    #: host exists.
    score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    reason: Mapped[str | None] = mapped_column(String(500))
    state: Mapped[str] = mapped_column(String(16), default="new", index=True)
    #: How many separate generation runs proposed it. A name three different
    #: patterns agree on is a better bet than one only a sequence produced.
    times_seen: Mapped[int] = mapped_column(Integer, default=1)
    decided_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


#: queued -> running -> ready | failed. Nothing moves backwards.
REPORT_STATUSES = ("queued", "running", "ready", "failed")
REPORT_KINDS = ("executive", "findings", "full")


class ReportRender(Base):
    """One report, rendered to one format, kept.

    Rendering a report is seconds of work over a document that can
    run to twelve megabytes, and the download endpoint used to do it
    on EVERY request -- so the same bytes were built again for every
    click, every retry and every person who opened the link.

    The generator was already rendering the PDF to measure
    `size_bytes` and throwing the result away. This keeps it, and
    renders the other format beside it, so a download is a byte read
    rather than a build.

    `data` is LargeBinary and not Text on purpose: a PDF is binary,
    it contains NUL, and Postgres rejects NUL in a text column while
    SQLite accepts it happily. That difference has bitten this
    project before.

    Rows are disposable. Deleting one costs a re-render on the next
    download and nothing else, which is why there is no migration
    backfilling them -- an old report renders once more, the first
    time somebody asks for it, and is fast from then on.
    """
    __tablename__ = "report_renders"
    __table_args__ = (
        UniqueConstraint("report_id", "fmt", name="uq_report_render"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    report_id: Mapped[int] = mapped_column(
        ForeignKey("reports.id", ondelete="CASCADE"), index=True)
    fmt: Mapped[str] = mapped_column(String(8))
    data: Mapped[bytes] = mapped_column(LargeBinary)
    bytes: Mapped[int] = mapped_column(Integer)
    rendered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False)


class Report(Base, TimestampMixin):
    """A generated report, and the record of generating it.

    The artifact is stored in the row rather than on disk. It is tens of
    kestrelbytes of HTML, it has to survive the same backup as the findings it
    describes, and a file path in a database is a promise about a
    filesystem that a container restart does not keep.

    The row exists from the moment it is requested, in `queued`, so the
    table can show the work in progress. A request that dies mid-generation
    leaves a `running` row rather than silently nothing — which is the
    point: an absent report and a failed one look identical otherwise.
    """
    __tablename__ = "reports"
    __table_args__ = (Index("ix_reports_project_status", "project_id", "status"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(16), index=True)
    fmt: Mapped[str] = mapped_column(String(8), default="html")
    title: Mapped[str] = mapped_column(String(300))
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    requested_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)
    content: Mapped[str | None] = mapped_column(Text)
    size_bytes: Mapped[int | None] = mapped_column(Integer)
    #: What went into it, so a reader six months later knows whether the
    #: numbers in it still mean anything.
    summary: Mapped[str | None] = mapped_column(Text)      # JSON
    #: Whether the requester was told it was ready, and why not if not.
    emailed_to: Mapped[str | None] = mapped_column(String(255))
    email_error: Mapped[str | None] = mapped_column(String(500))


class Implant(Base, TimestampMixin):
    """A C2 callback: an agent running on a host we control.

    Framework-neutral on purpose. Cobalt Strike calls it a beacon, Mythic a
    callback, Merlin and Sliver an agent or session, Havoc a demon. The
    fields an engagement record needs — which box, as whom, at what
    integrity, last seen when — are the same across all of them, and
    normalising is what makes a mixed-framework operation reportable.

    Keyed `(target_id, framework, implant_id)` so re-importing the operator's
    session list updates the rows instead of growing a new one per export.
    A callback with no id from its framework falls back to the process and
    pid, which is the next most stable thing about it.
    """
    __tablename__ = "implants"
    __table_args__ = (
        UniqueConstraint("target_id", "framework", "implant_id",
                         name="uq_implant_target_fw_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    framework: Mapped[str] = mapped_column(String(32), index=True)
    implant_id: Mapped[str] = mapped_column(String(128))
    listener: Mapped[str | None] = mapped_column(String(255))
    user: Mapped[str | None] = mapped_column(String(255))
    domain: Mapped[str | None] = mapped_column(String(255))
    process: Mapped[str | None] = mapped_column(String(255))
    pid: Mapped[int | None] = mapped_column(Integer)
    arch: Mapped[str | None] = mapped_column(String(32))
    # unknown | low | medium | high | system — normalised from whatever the
    # framework reports, because "elevated" and "integrity_level: 3" are the
    # same claim written two ways.
    integrity: Mapped[str | None] = mapped_column(String(16))
    internal_ip: Mapped[str | None] = mapped_column(String(45))
    external_ip: Mapped[str | None] = mapped_column(String(45))
    os: Mapped[str | None] = mapped_column(String(255))
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    active: Mapped[bool | None] = mapped_column(Boolean, default=None)
    note: Mapped[str | None] = mapped_column(Text)
    #: Fields the importer did not recognise, kept verbatim rather than dropped.
    extra: Mapped[str | None] = mapped_column(Text)

    target: Mapped[Target] = relationship(back_populates="implants")


class Action(Base, TimestampMixin):
    """One requested operation against a service, and its outcome.

    Modelled as a job rather than a synchronous call because the real
    implementations (nmap, a TLS handshake, an HTTP fetch) take seconds to
    minutes. Doing it synchronously now would mean rewriting the endpoint and
    the UI the moment nmap lands.

    It is also the audit trail: who asked for an active probe against which
    asset, and when.
    """
    __tablename__ = "actions"
    __table_args__ = (Index("ix_actions_service_status", "service_id", "status"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)
    service_id: Mapped[int] = mapped_column(
        ForeignKey("services.id", ondelete="CASCADE"), index=True)
    requested_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"))
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    result: Mapped[str | None] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(Text)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


# =============================================================== credentials
CREDENTIAL_KINDS = ("password", "hash", "key", "token", "cookie", "other")


class Credential(Base, TimestampMixin):
    """A credential obtained during an engagement.

    STORED IN PLAINTEXT. There is no encryption at rest: doing it properly
    needs a key that does not live beside the database, and a half-built
    scheme would be worse than an honest one because it reads as protection.
    Treat oddjob.db as secret material — file permissions, full-disk
    encryption, and do not copy it around.

    `host` is a free-text reference rather than a FK to Target: credentials
    are routinely found for a system that is not yet an inventory row, and a
    hard FK would mean discarding the find or inventing a target to hang it on.
    """
    __tablename__ = "credentials"
    __table_args__ = (Index("ix_credentials_project_user", "project_id", "username"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    host: Mapped[str | None] = mapped_column(String(255), index=True)
    service: Mapped[str | None] = mapped_column(String(128))
    port: Mapped[int | None] = mapped_column(Integer)
    username: Mapped[str | None] = mapped_column(String(255))
    secret: Mapped[str | None] = mapped_column(Text)
    kind: Mapped[str] = mapped_column(String(16), default="password", index=True)
    source: Mapped[str | None] = mapped_column(String(500))
    # none | works | failed — whether it has actually been tried.
    validated: Mapped[str] = mapped_column(String(16), default="none", index=True)
    notes: Mapped[str | None] = mapped_column(Text)


# ================================================================ settings
class Setting(Base, TimestampMixin):
    """Site-wide configuration, one row per key.

    Key/value rather than a wide table: the set of settings changes far more
    often than the schema should, and a column per toggle means a migration
    for every new switch.

    Secret values (SMTP password, Slack token) are stored here in plaintext —
    the same honest caveat as Credential. They are never returned by the API;
    see SECRET_KEYS in settings.py.
    """
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str | None] = mapped_column(Text)
    updated_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"))


class MagicLink(Base, TimestampMixin):
    """A single-use, short-lived sign-in token sent by email.

    Only a HASH is stored. The plaintext exists in the email and nowhere
    else, so a dump of this table does not let anyone sign in as anybody —
    which matters precisely because these are bearer tokens that skip the
    password entirely.

    Rows are kept after use rather than deleted: `used_at` is what makes the
    link single-use, and keeping it is also the audit trail of who was sent
    one and whether it was redeemed.
    """
    __tablename__ = "magic_links"
    __table_args__ = (Index("ix_magic_user_exp", "user_id", "expires_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(255), index=True)
    # "login" or "invite" — only affects the wording of the email.
    purpose: Mapped[str] = mapped_column(String(16), default="login")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


# ====================================================== scope and contacts
SCOPE_KINDS = ("cidr", "ipv4", "ipv6", "fqdn", "wildcard", "country")


class ProjectScope(Base, TimestampMixin):
    """One scope entry: a CIDR, an address, a name, a wildcard or a country.

    `kind` is DERIVED from the value, not chosen by the person typing it —
    asking someone to classify 400 pasted lines by hand is how a /24 ends up
    filed as an FQDN. See scope.classify(). The exception is `country`,
    which is entered as its own list: a bare "jp" is indistinguishable from
    a single-label hostname, and guessing between the two would put a
    typo'd hostname on the geographic allowlist.

    `included` carries exclusions in the same table. A scope document is
    almost always "this range, except these hosts", and keeping exclusions
    somewhere else is how they get missed. It is also what makes the two
    lists one list: out always trumps in, and a rule that has to compare
    two tables to decide that is a rule that will one day read only one.

    This table is ENFORCED, not merely recorded — see app/scopegate.py for
    every path that consults it.
    """
    __tablename__ = "project_scope"
    __table_args__ = (
        UniqueConstraint("project_id", "value", name="uq_scope_project_value"),
        Index("ix_scope_project_kind", "project_id", "kind"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(16))
    value: Mapped[str] = mapped_column(String(255))
    included: Mapped[bool] = mapped_column(Boolean, default=True)
    #: On an `fqdn`, whether the zone under it comes with it:
    #: `acme.example` with this set covers `a.acme.example` and
    #: `a.b.acme.example` too. Meaningless on every other kind — a
    #: wildcard already says it and a range has no subdomains — and
    #: scope.classify() drops it there rather than storing a claim the
    #: row does not have.
    #:
    #: **Why a column and not two rows.** Ticking the box could instead
    #: have written `acme.example` AND `*.acme.example`, with no schema
    #: change at all. That is the cheaper build and it was rejected,
    #: because a pair of independent rows is not the thing the operator
    #: said:
    #:
    #:   - Untick is then "delete the other one too", and nothing in the
    #:     table records which other one. Half of a pair deleted is a
    #:     rule whose coverage changed with no trace that it ever had a
    #:     second half — the same failure ScopeEntryPatch refuses `value`
    #:     to avoid.
    #:   - `add_scope` decides per VALUE, so a re-paste lands on the two
    #:     rows separately. `acme.example` moving to the out list while
    #:     `*.acme.example` is refused for being there already leaves the
    #:     zone in a state nobody asked for. One row cannot half-apply.
    #:   - The unique key is (project_id, value), so emitting
    #:     `*.acme.example` would silently amend a wildcard row the
    #:     project already had — flipping its list, or stamping this
    #:     batch's country onto it.
    #:
    #: What the column cost instead: one migration, one field on three
    #: schemas, and one more input to the matcher. That last is the real
    #: price and it is paid in `_Side.add`, which expands the row into
    #: the two dicts the matcher already had, so `match_name` itself is
    #: unchanged. Reads are wrong in one place or not at all.
    include_subdomains: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="0", default=False)
    #: Which country this entry's addresses are in, ISO 3166-1 alpha-2,
    #: as DECLARED by the operator. This is the whole of Oddjob's
    #: geolocation: nothing resolves an address to a country, because
    #: doing so means sending the client's target list to a third party.
    #: An entry with no country here contributes nothing to the country
    #: lists, and a host no annotated entry covers has an UNDETERMINED
    #: country, which is not the same as "no country" — scope.check()
    #: treats the two differently on purpose.
    country: Mapped[str | None] = mapped_column(String(2))
    notes: Mapped[str | None] = mapped_column(Text)

    project: Mapped[Project] = relationship(back_populates="scope")


class ProjectContact(Base, TimestampMixin):
    """A point of contact on the customer side."""
    __tablename__ = "project_contacts"

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    email: Mapped[str | None] = mapped_column(String(255))
    phone: Mapped[str | None] = mapped_column(String(64))
    title: Mapped[str | None] = mapped_column(String(255))
    # Who to wake at 3am vs who to cc on the report.
    primary_contact: Mapped[bool] = mapped_column(Boolean, default=False)
    notes: Mapped[str | None] = mapped_column(Text)

    project: Mapped[Project] = relationship(back_populates="contacts")


class ImportJob(Base, TimestampMixin):
    """A background import, and the record of running it.

    An import of a large proxy history takes minutes to an hour. Held
    open as one HTTP request it is hostage to the tab: navigating away
    aborts the upload, and there is nowhere to look afterwards to find
    out what happened. The row is what makes it survivable — it exists
    from the moment the work is queued, so the UI can show progress,
    and it outlives the page that started it.

    The file itself is NOT stored here. It is the spooled upload the
    server is already holding; this row names it while the work runs.
    """
    __tablename__ = "import_jobs"
    __table_args__ = (Index("ix_import_jobs_project_status", "project_id", "status"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    requested_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"))
    filename: Mapped[str] = mapped_column(String(300), default="upload")
    fmt: Mapped[str] = mapped_column(String(32), default="auto")
    mode: Mapped[str] = mapped_column(String(8), default="strict")
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    #: Rows written so far and, where the format can say, the total
    #: expected. A proxy history knows its item count from the cheap
    #: host pass, so the bar is real rather than a spinner with a label.
    rows_done: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    rows_total: Mapped[int | None] = mapped_column(Integer)
    hosts_seen: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)
    #: The ImportResult, as JSON, once it finishes.
    result: Mapped[str | None] = mapped_column(Text)


class Agent(Base, TimestampMixin):
    """A Ghost instance: a scanner the server tasks and talks to.

    Two keys, because the two directions are not the same trust. The
    agent proves itself to the server with `callback_key` on every
    outbound connection; the server proves itself to the agent with
    `call_in_key` when it reaches in. Only the hashes live here — a
    dump of this table must not let anyone impersonate either side, and
    the plaintext is shown exactly once, when the agent is enrolled.

    The agent dials out and holds the connection open, so it works from
    behind NAT with nothing exposed. `call_in_url` is the optional
    reverse path, set by the agent itself when it is reachable, and is
    a convenience for waking it rather than the channel the system
    depends on.
    """
    __tablename__ = "agents"
    __table_args__ = (Index("ix_agents_project_status", "project_id", "status"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    #: An agent belongs to one engagement. Tasking is scoped to it, so
    #: a scanner enrolled for one client cannot be pointed at another.
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(128), index=True)
    callback_key_hash: Mapped[str] = mapped_column(String(128))
    call_in_key_hash: Mapped[str | None] = mapped_column(String(128))
    call_in_url: Mapped[str | None] = mapped_column(String(300))

    #: Whether this Ghost will relay a SOCKS5 proxy stream.
    #:
    #: Off, and the default is the point. A proxy is a live socket
    #: into wherever the Ghost sits, which is a different kind of
    #: thing from a task: a task is queued, scoped and finished, while
    #: this is open for as long as somebody holds it. Switching it on
    #: is a deliberate act per agent, and `proxy_grants` are refused
    #: while it is off even if the credential is otherwise good.
    proxy_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="false", default=False)

    #: The agent's Ed25519 public key, base64 raw. The private half is
    #: made on the agent's own host at enrollment and never sent, so what
    #: is stored here cannot impersonate it -- unlike the key hashes
    #: above, which authenticate a secret that existed in two places.
    #: Null for an agent enrolled before identities existed; those still
    #: authenticate by key. Once this is set, a key alone is refused, so
    #: an attacker cannot strip the signature to get the weaker scheme.
    public_key: Mapped[str | None] = mapped_column(String(64))

    #: The agent's X25519 public half, for sealing the payload.
    #:
    #: Signing proves who sent a thing; it does not hide it. What
    #: travels here is a client's own vulnerability inventory, and the
    #: agent sits inside that client's network where a TLS-terminating
    #: proxy is ordinary corporate furniture. TLS protects it from
    #: everyone except the box reading everything, so the body is
    #: sealed under a key only the two endpoints hold.
    kex_public_key: Mapped[str | None] = mapped_column(String(64))

    #: One-time enrollment. The token is what the operator pastes into
    #: the agent once; the agent exchanges it for an identity and it is
    #: burned. Short-lived, because an unused enrollment token lying in
    #: a terminal history is a way onto the engagement.
    enroll_token_hash: Mapped[str | None] = mapped_column(String(128))
    enroll_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    enroll_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    #: callback | call_in. Which way the connection is made. Callback is
    #: the default and the one that works from inside a client network
    #: with nothing exposed; call_in exists for a host that cannot dial
    #: out but can be reached.
    connection_mode: Mapped[str] = mapped_column(
        String(16), default="callback", server_default="callback")
    #: The OS the operator said they were deploying to, which is how the
    #: UI knows which binary and which install snippet to hand them. The
    #: agent reports `platform` for itself once it connects; this is the
    #: intent, that is the fact, and they are kept apart on purpose.
    target_os: Mapped[str | None] = mapped_column(String(16))

    #: Lower goes first when the project is in `primary` mode. Ties
    #: break on id, so the order is always total and two agents cannot
    #: both consider themselves next.
    priority: Mapped[int] = mapped_column(
        Integer, default=100, server_default="100")
    #: Comma-separated region labels this agent serves, for `geo` mode
    #: — "jp", "eu", "us-east". Free text on purpose: the useful
    #: division is the client's network, not a standard country list.
    regions: Mapped[str | None] = mapped_column(String(255))

    #: Countries whose targets THIS GHOST will accept work against,
    #: ISO 3166-1 alpha-2, comma-separated. Empty or NULL means it
    #: takes work anywhere, which is the default and what every
    #: existing agent keeps.
    #:
    #: Deliberately not `regions` above. Those are free-text labels
    #: the operator declares on both sides and match by string; this
    #: is the country MaxMind resolved the target's address to. One is
    #: a routing hint the operator maintains, the other is a fact
    #: about where the packets are going, and a gate has to be the
    #: second kind.
    scan_countries: Mapped[str | None] = mapped_column(String(512))

    #: What it reported about itself on registration.
    platform: Mapped[str | None] = mapped_column(String(32))     # linux|darwin|windows
    arch: Mapped[str | None] = mapped_column(String(16))
    version: Mapped[str | None] = mapped_column(String(32))
    hostname: Mapped[str | None] = mapped_column(String(255))
    #: Whether it is running with the privileges that SYN scanning and
    #: raw sockets need. Recorded rather than assumed: a task that
    #: silently fell back to a connect scan is a different scan, and a
    #: report that does not say so is wrong.
    privileged: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false")
    #: JSON: {tool: version} for what it actually has installed.
    tools: Mapped[str | None] = mapped_column(Text)
    #: JSON: {tool: why} for what it tried to install and could not.
    #: Reported by the agent at startup. The dispatcher reads it so an
    #: agent is never handed work that needs a tool it does not have —
    #: that task failed three times and told the operator nothing they
    #: could act on.
    missing_tools: Mapped[str | None] = mapped_column(Text)
    #: When this ghost confirmed it had stopped, and what it took with
    #: it. Set by the ghost's own last message, not by the kill: an
    #: operator pressing Kill knows what they asked for, and what they
    #: need to know afterwards is whether it actually happened.
    #:
    #: A ghost killed while its host is off stays unretired here
    #: forever, which is the honest answer — the tools are still on
    #: that host and somebody has to deal with it.
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    retired_reason: Mapped[str | None] = mapped_column(String(300))
    #: JSON {removed: [], kept: [], failed: []}. `failed` is the list
    #: that matters: it is the cleanup still owed on someone's machine.
    retired_cleanup: Mapped[str | None] = mapped_column(Text)

    #: What this agent decided its host can run at once, and why.
    #: Reported by the agent, not assumed here: it is the only side
    #: that can see the cores, the memory and what masscan actually
    #: managed to emit. The project's ceiling is applied on top.
    capacity: Mapped[int | None] = mapped_column(Integer)
    capacity_reason: Mapped[str | None] = mapped_column(String(300))

    #: What an OPERATOR says this one ghost may run at once, overriding
    #: the agent's own assessment. NULL means "let the agent decide",
    #: which is the default and right almost always.
    #:
    #: Separate from `Project.ghost_max_parallel` because they answer
    #: different questions. The project ceiling is about the CLIENT --
    #: a fragile estate wants a small number however much machine is
    #: pointed at it -- so it still applies on top of this. This one is
    #: about the HOST: the operator knows something the agent cannot
    #: see, usually that a container's limit is not what /proc says, or
    #: that the box is quieter than its core count suggests.
    #:
    #: Pushed down to the agent on the next heartbeat rather than only
    #: applied here. The agent reports `slots_free` computed from its
    #: own capacity, so a number the agent has not been told about gets
    #: clamped straight back to what it already believed -- which is
    #: how a setting ends up looking like it does nothing.
    parallel_override: Mapped[int | None] = mapped_column(Integer)

    #: offline | online | busy | lost | disabled. `disabled` is an
    #: operator decision and survives reconnection; the rest are
    #: observations, recomputed from `last_seen`. `lost` is the one
    #: with a consequence attached: past that point the agent leaves
    #: the routing pool and whatever it was holding goes back in the
    #: queue for somebody else.
    status: Mapped[str] = mapped_column(
        String(16), default="offline", server_default="offline", index=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    #: Where the connection arrived from, as the server saw it. This is
    #: the last hop, not the agent: behind NAT it is the gateway,
    #: through a reverse tunnel it is 127.0.0.1.
    last_ip: Mapped[str | None] = mapped_column(String(45))
    #: What the agent says its own internet-facing address is. This is
    #: the one that answers "what will the client see in their logs",
    #: which `last_ip` cannot.
    outbound_ip: Mapped[str | None] = mapped_column(String(45))
    #: How the agent arrived at `outbound_ip`, in its own words:
    #: public-service, host-route, container-host-netns,
    #: container-internal, interface, unknown.
    #:
    #: Stored because the six are not interchangeable and the address
    #: alone cannot be told apart. A ghost in Docker reported
    #: 172.17.0.2 here and it rendered exactly like an egress address —
    #: an operator writing an incident notification would have given
    #: the client a number that appears in nobody's logs.
    outbound_ip_source: Mapped[str | None] = mapped_column(String(32))
    #: What qualifies it: which lookup failed, what the address is not.
    #: Prose from the agent, for a tooltip rather than a column.
    outbound_ip_note: Mapped[str | None] = mapped_column(Text)
    #: JSON list of every usable address on the host. A jump box
    #: usually has one facing us and another facing the target.
    interfaces: Mapped[str | None] = mapped_column(Text)
    #: The OS of the machine underneath, where it differs from
    #: `platform`. A Linux container on WSL2 on Windows Server is
    #: platform=linux, host_platform=windows — both true, answering
    #: different questions: which binary to ship, and which machine
    #: this is.
    #:
    #: NULL means undetermined, which is deliberately distinct from
    #: "linux". Nothing here guesses.
    host_platform: Mapped[str | None] = mapped_column(String(32))
    #: The evidence for `host_platform`, so the claim can be checked
    #: rather than taken: the kernel string, the markers found.
    host_platform_source: Mapped[str | None] = mapped_column(Text)
    #: The container runtime this agent is inside, NULL if none was
    #: detected. Absence of a marker is not proof of absence of a
    #: container, so this says what was found and never that there is
    #: nothing.
    container: Mapped[str | None] = mapped_column(String(32))
    notes: Mapped[str | None] = mapped_column(Text)

    #: Whether this agent ships its own log back.
    #:
    #: Off by default and deliberately not sticky across an
    #: engagement: a ghost's log is the most detailed thing it can
    #: send, it names the hosts it is scanning, and the whole point of
    #: the store is that it is small enough to read. It is turned on
    #: when a ghost is misbehaving and off again afterwards.
    debug: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false", nullable=False)


class ProxyGrant(Base, TimestampMixin):
    """A SOCKS5 credential that routes through one Ghost.

    Its own table and not a reuse of anything a person logs in with.
    SOCKS5 sends the password in clear text on every connection, so
    whatever is typed into a browser's proxy settings must be a
    secret that is worth exactly this one capability and can be taken
    away without touching an account.

    Only the hash is kept, as with `Agent.callback_key_hash`: a dump
    of this table must not hand anybody a route into the engagement.
    The plaintext is shown once, when the grant is made.

    **Scoped to one agent on purpose.** A grant that floated across a
    project would let a credential issued for a lab Ghost be used
    through one sitting inside the client, which is precisely the
    mistake worth making impossible rather than improbable.
    """
    __tablename__ = "proxy_grants"
    __table_args__ = (
        UniqueConstraint("username", name="uq_proxy_grant_username"),
        Index("ix_proxy_grants_agent_revoked", "agent_id", "revoked_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    #: Indexed, and the detector deletes through it when an agent goes.
    agent_id: Mapped[int] = mapped_column(
        ForeignKey("agents.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True)

    #: What goes in the browser's proxy username box. Unique across
    #: the installation so a lookup needs no second field, and so two
    #: engagements cannot collide on one.
    username: Mapped[str] = mapped_column(String(64))
    password_hash: Mapped[str] = mapped_column(String(128))

    #: Who asked for it, for the question that gets asked later.
    created_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"))
    note: Mapped[str | None] = mapped_column(String(300))

    #: Revocation is a timestamp rather than a delete, so the audit
    #: trail still has something to point at. A grant with this set is
    #: refused; nothing reads it back.
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    #: When it stops working regardless. A proxy credential that lives
    #: for ever is one nobody remembers to take away.
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ProxyConnection(Base):
    """One connection the proxy accepted or refused, and where to.

    Written for ACCEPTED and REFUSED alike. A proxy that only records
    what it allowed cannot answer "did anybody try to reach that", and
    a refusal is the more interesting half when somebody asks whether
    a credential was misused.

    No bodies and no byte contents -- just the decision, the
    destination and who held the credential. The traffic itself is the
    client's and does not belong in our database.
    """
    __tablename__ = "proxy_connections"
    __table_args__ = (
        Index("ix_proxy_conn_project_at", "project_id", "at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    #: Nullable, and the NULL means something: a credential that
    #: resolved to nothing has no engagement to be filed against.
    #: This column was NOT NULL and `record` therefore returned
    #: without writing, which made every failed credential attempt
    #: against the internet-facing port invisible -- the one thing
    #: this table exists to be able to answer. A row on the wrong
    #: project would have been worse than no row; a row with no
    #: project is the true one.
    project_id: Mapped[int | None] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    agent_id: Mapped[int | None] = mapped_column(
        ForeignKey("agents.id", ondelete="SET NULL"), index=True)
    grant_id: Mapped[int | None] = mapped_column(
        ForeignKey("proxy_grants.id", ondelete="SET NULL"), index=True)

    #: The destination as the CLIENT asked for it -- a name stays a
    #: name. What the Ghost resolved it to is a different fact and is
    #: not invented here.
    host: Mapped[str] = mapped_column(String(253))
    port: Mapped[int] = mapped_column(Integer)
    #: allowed | refused_scope | refused_auth | refused_command
    outcome: Mapped[str] = mapped_column(String(24), index=True)
    #: The scope gate's own sentence, when it is the one that refused.
    reason: Mapped[str | None] = mapped_column(String(300))
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False)


class AgentDebugLog(Base):
    """One line a ghost logged, kept only while debug is on.

    This exists because diagnosing a ghost meant having an account on
    the box it runs on. The fleet is a GCP VM reached through IAP, a
    Windows host whose docker lives inside WSL2, and a droplet -- so
    the answer to "why did that agent stop" was three different SSH
    procedures, and when the GCP host lost its route there was no way
    in at all. The agent can say what happened; it just had nowhere to
    say it.

    Not the result of a task. A task's output already comes back and
    lands in `agent_tasks.output`; this is what the agent says about
    *itself* -- what it decided, what it could not reach, why it
    thinks it has one slot free rather than six.

    No TimestampMixin: `at` is when the agent logged the line, which
    is the only time that matters here and is not when the row was
    written. A batch arrives seconds late and a spooled one can
    arrive after a reconnect, so a server-side created_at would
    quietly reorder the agent's own log.
    """
    __tablename__ = "agent_debug_logs"
    __table_args__ = (
        Index("ix_agent_debug_logs_agent_at", "agent_id", "at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    agent_id: Mapped[int] = mapped_column(
        ForeignKey("agents.id", ondelete="CASCADE"), index=True)
    #: Carried rather than joined through the agent, so the project
    #: scope filter is one predicate on this table. Debug lines are
    #: read while something is wrong, often across a whole fleet.
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    #: When the AGENT logged it, from the agent's own clock.
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    #: Free text as the agent emitted it. Bounded on the way in: a
    #: single log line is not allowed to be a scan's whole output.
    line: Mapped[str] = mapped_column(Text)


class AgentTask(Base, TimestampMixin):
    """One unit of work handed to an agent.

    `kind` names the runner on the agent side; `args` is its JSON
    input. Output comes back as the tool's own native format —
    nmap -oX, masscan -oX — and is handed to the importer that already
    reads it, so a scan run remotely lands exactly as one run locally.

    Status is a deliberate ladder: queued -> claimed -> running ->
    done|failed|cancelled. `claimed` exists so two agents polling the
    same queue cannot both take the same task.
    """
    __tablename__ = "agent_tasks"
    __table_args__ = (Index("ix_agent_tasks_agent_status", "agent_id", "status"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    #: Null while the task is waiting for the project's routing policy
    #: to pick an agent. A task queued at the project rather than at a
    #: named agent sits unassigned until one asks for work and is
    #: eligible, which is what makes mesh, primary and geo possible
    #: without a scheduler process.
    #:
    #: SET NULL rather than CASCADE: deleting an agent that had claimed
    #: a task should return that task to the pool, not delete the
    #: record of work that may already have run.
    agent_id: Mapped[int | None] = mapped_column(
        ForeignKey("agents.id", ondelete="SET NULL"), index=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    requested_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"))

    #: For `geo` routing: which region this work must run from. Set by
    #: the operator, because the alternative is resolving the target's
    #: address with a third-party service.
    region: Mapped[str | None] = mapped_column(String(32))

    kind: Mapped[str] = mapped_column(String(32), index=True)
    args: Mapped[str | None] = mapped_column(Text)              # JSON
    #: Higher goes first. Zero for everything a scan queues.
    #:
    #: The queue is ordered by age within a kind, which is right for
    #: work nobody is waiting on and wrong for work somebody is. An
    #: operator who presses Send on a replayed request is sitting
    #: looking at the dialog; a project with four thousand queued
    #: crawls would make that a twenty-minute wait for one packet, and
    #: the feature would read as broken rather than as busy.
    #:
    #: Not an index of its own. Every dispatch query already narrows on
    #: (agent_id, status) or (project_id, agent_id IS NULL, status),
    #: all of which are indexed; the ordering then happens over a set
    #: the planner has already cut down, and a second index on a column
    #: that is 0 for almost every row would not be read.
    priority: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0")
    #: How many times an agent has tried and failed this.
    #:
    #: A failure is usually about the agent or the moment, not the
    #: request — a container that died mid-scan, a resolver that timed
    #: out, a host that was unreachable for a minute — so the task goes
    #: back in the queue for somebody else to try. Bounded, because a
    #: request that is simply wrong fails identically on every agent
    #: and an unbounded retry would grind the queue on it forever.
    attempts: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0")
    status: Mapped[str] = mapped_column(
        String(16), default="queued", server_default="queued", index=True)

    #: What the agent sent back. `output` is the raw tool output and is
    #: what gets imported; `summary` is for the UI; `stderr` is kept
    #: because a tool that printed a warning and still succeeded is a
    #: different outcome from one that worked cleanly.
    output: Mapped[str | None] = mapped_column(Text)
    stderr: Mapped[str | None] = mapped_column(Text)
    summary: Mapped[str | None] = mapped_column(Text)
    exit_code: Mapped[int | None] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(Text)
    #: The format the output should be imported as, when it should be.
    import_as: Mapped[str | None] = mapped_column(String(32))
    #: The ImportResult once the output has been ingested.
    import_result: Mapped[str | None] = mapped_column(Text)

    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


# ========================================================== audit trail
#: Where an entry came from. Kept as a small closed set because the log
#: is read by filtering it, and a free-form origin string turns that
#: into guesswork about spelling.
AUDIT_SOURCES = (
    "middleware",   # an HTTP request, recorded by the AuditTrail middleware
    "ui",           # a deliberate action a person took in the SPA
    "ghost",         # a scanner enrolling, calling in, or returning results
    "backend",      # the server acting on its own: retention, workers, startup
)


class AuditEvent(Base):
    """One thing that happened, for the site admin to read later.

    Deliberately NOT `Event`, which is the per-target engagement
    narrative and is scoped to one asset. This answers a different
    question -- "who did what to this installation, and from where" --
    and so it is keyed on time rather than on a target, and survives the
    deletion of everything it refers to.

    **`username` is denormalised on purpose.** `user_id` is a nullable
    FK so a deleted account does not drag its history out of the table,
    but an audit entry that cannot say who acted is not an audit entry.
    The name is therefore copied in at write time and never resolved
    through the relationship afterwards.

    **Nothing secret may be written here.** Site admins can read every
    row, so a token that reaches this table is a token disclosed to all
    of them. `audit.scrub_path` exists because magic-link sign-in
    tokens travel in the URL PATH, and recording a request verbatim
    would hand one admin another user's account. Bodies, headers and
    cookies are never recorded at all.
    """
    __tablename__ = "audit_events"
    __table_args__ = (
        # The log is almost always read newest-first, optionally narrowed
        # to one origin. `id` rides along in the first index so that
        # entries written inside the same clock tick still come back in a
        # stable order rather than shuffling between pages.
        Index("ix_audit_at_id", "at", "id"),
        Index("ix_audit_source_at", "source", "at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True)
    source: Mapped[str] = mapped_column(String(16), index=True)
    #: A short stable verb: `request`, `project.create`, `ghost.enroll`.
    #: Dotted rather than prose so it can be filtered on.
    action: Mapped[str] = mapped_column(String(64), index=True)
    username: Mapped[str | None] = mapped_column(String(128), index=True)
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"))
    ip: Mapped[str | None] = mapped_column(String(64))
    method: Mapped[str | None] = mapped_column(String(8))
    #: Scrubbed before it arrives. Never the query string.
    path: Mapped[str | None] = mapped_column(String(512))
    status: Mapped[int | None] = mapped_column(Integer)
    ms: Mapped[int | None] = mapped_column(Integer)
    #: Which engagement it concerned, when that is knowable. A code
    #: rather than an FK, for the same reason as `username`.
    project_code: Mapped[str | None] = mapped_column(String(64), index=True)
    #: One human-readable line. Never a request body.
    detail: Mapped[str | None] = mapped_column(Text)


# ===================================== vulnerability intelligence
#
# A local copy of public exploit and CVE data, so that "is anything
# known about Apache 2.4.49" can be answered without telling anybody
# that a client is running Apache 2.4.49.
#
# That is the whole reason this is a table and not an API call. Matching
# a version live against NVD means sending a client's software
# inventory to a third party on every lookup, host by host. The data is
# public and the question is not: the question names the target. So the
# database comes here and the matching happens locally.


class Exploit(Base):
    """One entry from Exploit-DB, as `searchsploit` would show it."""
    __tablename__ = "exploits"
    __table_args__ = (
        Index("ix_exploits_search", "platform", "type"),
    )

    #: Exploit-DB's own id, which is stable and is what an operator
    #: quotes. Not a surrogate key: two syncs of the same row are the
    #: same exploit.
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=False)
    title: Mapped[str] = mapped_column(Text, index=True)
    #: Path within the exploitdb tree, e.g. `exploits/linux/remote/1234.rb`.
    path: Mapped[str | None] = mapped_column(String(512))
    author: Mapped[str | None] = mapped_column(String(255))
    published: Mapped[str | None] = mapped_column(String(32))
    #: linux, windows, php, multiple…
    platform: Mapped[str | None] = mapped_column(String(64), index=True)
    #: remote, local, webapps, dos…
    type: Mapped[str | None] = mapped_column(String(32), index=True)
    port: Mapped[int | None] = mapped_column(Integer)
    #: Exploit-DB marks which entries somebody actually ran. An
    #: unverified entry is a lead; a verified one is a lead that worked
    #: once, for somebody, somewhere.
    #:
    #: `server_default` as well as `default`, to match the migration and
    #: because a bulk insert that bypasses the ORM must not be able to
    #: leave this NULL — an unknown here reads as "not verified", which
    #: is the safe direction, but only if the column enforces it.
    verified: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false", nullable=False)
    #: CVE ids this entry cites, comma separated. The join between the
    #: two halves of this table pair.
    cves: Mapped[str | None] = mapped_column(Text, index=True)


class CveRecord(Base):
    """One CVE, enough of it to decide whether to care."""
    __tablename__ = "cve_records"
    __table_args__ = (
        Index("ix_cve_severity_score", "severity", "cvss_score"),
        # The ordering a findings list actually wants: what is being
        # exploited, then what is likely to be, then how bad it would
        # be. See `vulnfeed.triage_order`.
        Index("ix_cve_triage", "kev", "epss", "cvss_score"),
    )

    #: CVE-2021-41773. The natural key, for the same reason as above.
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    published: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    modified: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), index=True)
    summary: Mapped[str | None] = mapped_column(Text)
    cvss_score: Mapped[float | None] = mapped_column(Float, index=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(128))
    severity: Mapped[str | None] = mapped_column(String(16), index=True)
    #: JSON list of CPE match strings. What makes version matching
    #: possible at all, and the reason a CVE row is worth storing rather
    #: than looked up by id on demand.
    cpes: Mapped[str | None] = mapped_column(Text)
    #: Lowercased "vendor product" pairs pulled out of the CPEs, for a
    #: cheap first pass before the expensive one. A LIKE over this is
    #: what keeps matching a 4,000-host project from being a join
    #: against 290,000 rows per service.
    products: Mapped[str | None] = mapped_column(Text, index=True)
    #: On CISA's Known Exploited Vulnerabilities list: somebody has
    #: been seen using this, in the wild, against somebody.
    #:
    #: Columns on the CVE rather than a table of their own, because
    #: both of these are one fact per CVE and the question is always
    #: asked WITH the CVE ("sort these findings"). A join per finding
    #: to answer it would be a join nobody needs.
    #:
    #: Tri-state on purpose. False is "CISA has not listed it";
    #: NULL is "the KEV feed has never been synced here", and a
    #: findings list must not show those the same way -- the whole
    #: reason `status()` exists in vulnfeed.py is that an empty table
    #: is not evidence of absence.
    kev: Mapped[bool | None] = mapped_column(Boolean, index=True)
    #: When CISA added it. Useful on its own: a KEV entry from last
    #: week is a different conversation from one added in 2021.
    kev_added: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True))
    #: The date CISA set for federal agencies to have fixed it. Not
    #: binding on a private client, and worth showing anyway -- it is
    #: the clearest public statement of how urgent somebody
    #: independent thought this was.
    kev_due: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    #: FIRST's EPSS: probability, 0..1, that this CVE will be
    #: exploited in the next 30 days. Answers the question CVSS
    #: cannot -- "a 9.8 nobody has ever used" and "a 7.5 being
    #: exploited this week" sort identically by severity alone.
    epss: Mapped[float | None] = mapped_column(Float, index=True)
    #: Percentile among all scored CVEs. Carried because the raw
    #: probability is small and hard to read: 0.00042 means little,
    #: "higher than 11% of all CVEs" means something.
    epss_percentile: Mapped[float | None] = mapped_column(Float)


class FeedState(Base):
    """Where each feed got to, and whether it is telling the truth.

    Separate from the data so that "we have 290,000 CVEs" and "the last
    sync failed four days ago" are both answerable. A stale feed that
    reports nothing is the failure mode worth designing against: the
    answer "no known exploits" is only worth having if the thing
    answering knows how current it is.
    """
    __tablename__ = "feed_state"

    #: exploitdb | nvd
    source: Mapped[str] = mapped_column(String(32), primary_key=True)
    last_success_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True))
    last_attempt_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True))
    #: For incremental feeds: the high-water mark to resume from.
    cursor: Mapped[str | None] = mapped_column(String(64))
    records: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    #: Why the last attempt did not finish, or NULL when it did.
    error: Mapped[str | None] = mapped_column(String(500))
    #: True while a sync is running, so two do not start at once.
    running: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false")


# ========================================= subsystem health
#
# "Has Slack worked recently?" is not answerable from configuration.
# A token can be present and valid and the workspace can still be
# refusing every message, and the only moment anybody finds out is when
# a finding quietly fails to arrive. The same is true of SMTP: a magic
# link that is never delivered looks, from the server's side, exactly
# like one nobody clicked.
#
# So each subsystem records the outcome of its last real attempt. Not a
# synthetic probe — probes test the probe. This is written from inside
# `slack.post` and `mailer.send_mail` rather than at their call sites,
# because there are fourteen call sites between them and a health page
# that silently misses one is worse than no health page at all.


class ServiceHealth(Base):
    """The last thing a subsystem actually did, and whether it worked."""
    __tablename__ = "service_health"

    #: slack | smtp | ghost | … — the subsystem's own name.
    service: Mapped[str] = mapped_column(String(32), primary_key=True)
    last_ok_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True))
    last_error_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True))
    #: Why the last failure failed. Kept after a later success, so
    #: "working now, but it broke an hour ago" stays visible — that is
    #: usually the more useful of the two facts.
    last_error: Mapped[str | None] = mapped_column(String(500))
    #: What the last attempt was, in a few words. Never a message body,
    #: a recipient or a token: site admins all read this.
    last_detail: Mapped[str | None] = mapped_column(String(300))
    ok_count: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0")
    error_count: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0")


class HealthSample(Base):
    """One moment in a subsystem's history, so a card can draw a line.

    `ServiceHealth` above holds the LAST thing that happened and a
    running total. Both are the wrong shape for the question an
    operator actually asks, which is "is this getting worse". A total
    of 41 Slack errors says nothing about whether forty of them were
    last Tuesday or all of them in the past hour.

    Two kinds of row, distinguished by which column is filled:

      * an ATTEMPT -- `ok` or `errors` is 1, from `servicehealth.note`,
        written once per real send. Not a probe: see that module.
      * a MEASUREMENT -- `latency_ms` is set, from the database check
        on the health page, written at most once a minute however
        often the page is polled.

    Bucketing happens at read time rather than here. A row per attempt
    is the honest record and costs nothing at this volume; deciding at
    write time what size bucket a reader will want is how a series
    ends up unable to answer the question that gets asked later.
    """
    __tablename__ = "health_samples"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    #: db | slack | smtp — matches `ServiceHealth.service` where both
    #: exist. `db` has no row there, because there is no "attempt" to
    #: record: the connection either answers or the page says so.
    service: Mapped[str] = mapped_column(String(32), index=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                         index=True)
    ok: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    errors: Mapped[int] = mapped_column(Integer, default=0,
                                        server_default="0")
    #: Only on a measurement row. Nullable because "we did not measure"
    #: and "we measured zero" are different facts.
    latency_ms: Mapped[float | None] = mapped_column(Float)

    __table_args__ = (
        Index("ix_health_samples_service_at", "service", "at"),
    )
