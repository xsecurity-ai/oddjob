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
    String,
    Table,
    Text,
    UniqueConstraint,
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
PROJECT_STATUSES = ("active", "paused", "complete", "archived")

#: What `Project.auto_nmap` may be. Here rather than in
#: app/automation.py because `schemas.py` validates against it and
#: importing the worker module into the schemas to read one tuple is
#: how an import cycle starts. The task arguments each choice maps to
#: stay in automation.py, which is behaviour rather than vocabulary.
NMAP_CHOICES = ("off", "top100", "full")


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

    target: Mapped[Target] = relationship(back_populates="vulns")


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

    target: Mapped[Target] = relationship(back_populates="web_addresses")


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

    #: offline | online | disabled. `disabled` is an operator decision
    #: and survives reconnection; offline is merely an observation.
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
