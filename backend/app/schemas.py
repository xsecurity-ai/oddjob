"""Pydantic v2 request/response models.

Two flavours of input model exist on purpose:

  *Create  strict. A bad host raises, the request 422s with a precise message.
           Right for a single POST, where the caller made one mistake.
  *In      lenient. `host` is a plain string and is validated per row INSIDE
           the bulk handler, so one wildcard in a 6,000-row scanner export is
           reported and skipped instead of rejecting the whole batch.
"""
from __future__ import annotations

import json

import ipaddress
from datetime import datetime
from typing import Generic, Literal, TypeVar

from pydantic import (BaseModel, ConfigDict, Field, field_validator,
                      model_validator)

from .hosts import InvalidHost, validate_cloud_id, validate_host
from .models import PROJECT_STATUSES, SEVERITIES

T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    """Every list endpoint returns this. `total` is the count BEFORE
    limit/offset, so a client can page without a second request."""
    items: list[T]
    total: int
    limit: int
    offset: int


def norm_sev(v: str | None) -> str:
    v = (v or "info").strip().lower()
    alias = {"informational": "info", "med": "medium", "crit": "critical",
             "unclassified": "info", "none": "info", "": "info"}
    v = alias.get(v, v)
    return v if v in SEVERITIES else "info"


def clean_ip(v: str | None) -> str | None:
    """Coerce anything that is not an IP literal to null.

    Scanner exports routinely put a hostname -- or a marker like
    'SYNTHETIC-...-nonresolving' -- in the IP column. The column means "IP
    address", so a non-IP belongs there as nothing. Widening it to fit a
    hostname would quietly redefine the field as "some string".
    """
    if v is None:
        return None
    v = v.strip()
    if not v:
        return None
    try:
        ipaddress.ip_address(v.split("%", 1)[0])
    except ValueError:
        return None
    return v[:45]


# ------------------------------------------------------------- projects
class ProjectBase(BaseModel):
    code: str = Field(min_length=1, max_length=64,
                      description="Short slug, e.g. FALCON-1. Unique.")
    #: The operation's internal name — a client code is ACME, its operation name FALCON.
    #: Separate from `code` because the code is the client's and shows up
    #: in their deliverables, while the codename is what the scan
    #: directories, the Slack channels and the operators are named after.
    codename: str | None = Field(default=None, max_length=64)
    name: str = Field(min_length=1, max_length=255)
    client: str | None = None
    description: str | None = None
    status: str = "active"

    @field_validator("codename")
    @classmethod
    def _codename(cls, v: str | None) -> str | None:
        v = (v or "").strip().upper().replace(" ", "-")
        return v or None

    @field_validator("code")
    @classmethod
    def _code(cls, v: str) -> str:
        v = v.strip().upper().replace(" ", "-")
        if not v:
            raise ValueError("project code is empty")
        return v

    @field_validator("status")
    @classmethod
    def _status(cls, v: str) -> str:
        v = (v or "active").strip().lower()
        if v not in PROJECT_STATUSES:
            raise ValueError(f"status must be one of {PROJECT_STATUSES}")
        return v


class ProjectCreate(ProjectBase):
    """A new engagement.

    `code` is optional here and required everywhere else. It is the join
    key — it is in every URL, every scan directory and every report
    filename — but it is not something anyone wants to invent twice:
    an engagement has one name, and the code is that name in a form a
    path can hold. Omit it and the server derives it from the name,
    making it unique if it has to.
    """
    code: str | None = Field(
        default=None, max_length=64,
        description="Derived from the name when omitted. Unique.")

    @field_validator("code")
    @classmethod
    def _code(cls, v: str | None) -> str | None:
        # Overrides the base rule, which rejects empty. Here empty means
        # "you choose", and is the ordinary case.
        v = (v or "").strip().upper().replace(" ", "-")
        return v or None


class ProjectUpdate(BaseModel):
    codename: str | None = None
    name: str | None = None
    client: str | None = None
    description: str | None = None
    status: str | None = None
    # Empty string means "leave it alone", same rule as site settings;
    # clearing is an explicit DELETE.
    slack_token: str | None = None
    slack_channel: str | None = None
    slack_delivery: str | None = None
    slack_private: bool | None = None


class ProjectOut(ProjectBase):
    model_config = ConfigDict(from_attributes=True)
    id: int
    # The token itself is never returned — only whether an override exists.
    slack_token_set: bool = False
    # Whether a notification posted now would reach a channel: a token
    # resolves AND the channel has been seen in the workspace. A project
    # on the site-wide bot is active with no override of its own, so
    # this and `slack_token_set` answer genuinely different questions.
    slack_active: bool = False
    # present | missing | unknown | no_token. "unknown" is a real answer
    # and not a synonym for missing — it means Slack could not be asked,
    # and a rate limit must never render as "your channel is gone".
    slack_channel_state: str = "unknown"
    slack_channel_checked_at: datetime | None = None
    #: Why the last check produced no channel. None when it did.
    slack_channel_error: str | None = None
    slack_channel: str | None = None
    slack_delivery: str = "site"
    # None means "inherit the site default"; the resolved value is also given
    # so a caller does not have to fetch site settings to know what happens.
    slack_private: bool | None = None
    slack_private_effective: bool = True
    total_targets: int = 0
    total_services: int = 0
    total_vulns: int = 0
    total_pocs: int = 0
    created_at: datetime
    updated_at: datetime



def _as(v, want):
    """Decode a JSON text column into `want` (list or dict), or an empty one.

    Used wherever a column holds JSON. Never raises: a row with one corrupt
    JSON field should still render, minus that field.
    """
    empty = want()
    if v is None or v == "":
        return empty
    if isinstance(v, want):
        return v
    try:
        out = json.loads(v)
    except (TypeError, ValueError):
        return empty
    return out if isinstance(out, want) else empty


# -------------------------------------------------------------- targets
class _TargetFields(BaseModel):
    kind: Literal["host", "mobile", "cloud"] = Field(
        default="host",
        description="host: a machine at an address. mobile: an application, "
                    "named by its bundle/package id, with no IP of its own. "
                    "cloud: a managed resource — bucket, function, tenant, "
                    "account — named as the provider names it.")
    provider: str | None = Field(
        default=None, max_length=32,
        description="Which cloud, for kind=cloud. aws, azure, gcp, oracle, "
                    "cloudflare, … Free text: the list does not end at three.")
    ip_address: str | None = Field(
        default=None, description="IPv4/IPv6 literal; anything else is coerced to null")
    # Tri-state: None = not probed yet, which is a different claim from
    # False = probed and did not respond.
    alive: bool | None = Field(
        default=None, description="true responding, false no response, null not probed")
    hacked: bool = False
    os: str | None = None
    notes: str | None = None
    tags: str | None = None

    @field_validator("ip_address")
    @classmethod
    def _ip(cls, v: str | None) -> str | None:
        return clean_ip(v)

    @model_validator(mode="after")
    def _kind_implies(self):
        """A mobile app has no IP, and saying so is not the same as
        leaving it blank.

        An empty `ip_address` on a host means "not resolved yet" — a gap
        in coverage. On an application it means there is nothing to
        resolve. Clearing it here keeps an address someone pasted by
        mistake from turning an app into a scannable host, and keeps
        liveness from ever being inferred for one.
        """
        if self.kind == "mobile":
            self.ip_address = None
            self.alive = None
        if self.kind != "cloud":
            # A provider on a host or an app is meaningless and would
            # show up in filters as if it meant something.
            self.provider = None
        elif self.provider:
            self.provider = self.provider.strip().lower() or None
        return self


class TargetCreate(_TargetFields):
    host: str = Field(min_length=1, max_length=255)

    @model_validator(mode="after")
    def _check_host(self):
        """Validated against the rules for its kind.

        A host and a mobile bundle id are both hostname-shaped. A cloud
        resource often is not — `arn:aws:iam::123:role/admin` is a
        perfectly good identifier and fails every DNS rule — so
        refusing it would leave the engagement's cloud findings with
        nowhere to live.
        """
        try:
            self.host = (validate_cloud_id(self.host) if self.kind == "cloud"
                         else validate_host(self.host))
        except InvalidHost as e:
            raise ValueError(str(e)) from e
        return self


class TargetIn(_TargetFields):
    """Bulk variant — host validated per row inside the handler."""
    host: str


class TargetUpdate(BaseModel):
    ip_address: str | None = None
    alive: bool | None = None
    hacked: bool | None = None
    os: str | None = None
    notes: str | None = None
    tags: str | None = None


class TargetOut(_TargetFields):
    model_config = ConfigDict(from_attributes=True)
    id: int
    host: str
    project_id: int
    project_code: str
    # Populated by a scan import; absent on a hand-made target.
    os_accuracy: int | None = None
    mac_address: str | None = None
    mac_vendor: str | None = None
    hostnames: list[str] = []
    extra: dict = {}

    # Both are stored as JSON strings. A column that failed to parse must not
    # sink the whole row — the rest of the target is still worth returning —
    # so each falls back to its own empty value.
    @field_validator("hostnames", mode="before")
    @classmethod
    def _hostnames(cls, v):
        return _as(v, list)

    @field_validator("extra", mode="before")
    @classmethod
    def _extra(cls, v):
        return _as(v, dict)
    total_vulns: int = 0
    total_criticals: int = 0
    total_highs: int = 0
    total_pocs: int = 0
    total_ports: int = 0
    created_at: datetime
    updated_at: datetime


# -------------------------------------------------------------- services
class _ServiceFields(BaseModel):
    port: int = Field(ge=0, le=65535)
    protocol: str = "tcp"
    state: str = "open"
    name: str | None = None
    product: str | None = None
    version: str | None = None
    banner: str | None = None
    notes: str | None = None
    # nmap -sV / NSE detail. All optional: a hand-entered service has none.
    extrainfo: str | None = None
    tunnel: str | None = None
    method: str | None = None
    confidence: int | None = None
    reason: str | None = None

    @field_validator("protocol")
    @classmethod
    def _proto(cls, v: str) -> str:
        return (v or "tcp").strip().lower()

    @field_validator("state")
    @classmethod
    def _state(cls, v: str) -> str:
        return (v or "open").strip().lower()


class ServiceCreate(_ServiceFields):
    host: str

    @field_validator("host")
    @classmethod
    def _host(cls, v: str) -> str:
        return validate_host(v)


class ServiceIn(_ServiceFields):
    host: str


class ServiceUpdate(BaseModel):
    state: str | None = None
    name: str | None = None
    product: str | None = None
    version: str | None = None
    banner: str | None = None


class ServiceOut(_ServiceFields):
    model_config = ConfigDict(from_attributes=True)
    id: int
    target_id: int
    host: str
    project_code: str
    # Read-only: these are produced by a scan importer, which writes the
    # columns directly. Keeping them off the input model stops a JSON value
    # being handed to a TEXT column by anything that posts a service.
    cpe: list[str] = []
    scripts: dict[str, str] = {}

    @field_validator("cpe", mode="before")
    @classmethod
    def _cpe(cls, v):
        return _as(v, list)

    @field_validator("scripts", mode="before")
    @classmethod
    def _scripts(cls, v):
        return _as(v, dict)
    created_at: datetime
    updated_at: datetime


# ----------------------------------------------------------------- vulns
class _VulnFields(BaseModel):
    title: str
    severity: str = "info"
    status: str = "open"
    port: int | None = None
    protocol: str | None = None
    description: str | None = None
    remediation: str | None = None
    external_id: str | None = None

    @field_validator("severity")
    @classmethod
    def _sev(cls, v: str) -> str:
        return norm_sev(v)


class VulnCreate(_VulnFields):
    host: str

    @field_validator("host")
    @classmethod
    def _host(cls, v: str) -> str:
        return validate_host(v)


class VulnIn(_VulnFields):
    host: str


class VulnOut(_VulnFields):
    model_config = ConfigDict(from_attributes=True)
    id: int
    target_id: int
    host: str
    project_code: str
    created_at: datetime
    updated_at: datetime


# ------------------------------------------------------------------ pocs
class _PocFields(BaseModel):
    title: str
    status: Literal["confirmed", "unconfirmed"] = "unconfirmed"
    path: str | None = None
    exit_code: int | None = None
    notes: str | None = None


class PocCreate(_PocFields):
    host: str

    @field_validator("host")
    @classmethod
    def _host(cls, v: str) -> str:
        return validate_host(v)


class PocIn(_PocFields):
    host: str


class PocOut(_PocFields):
    model_config = ConfigDict(from_attributes=True)
    id: int
    target_id: int
    host: str
    project_code: str
    created_at: datetime
    updated_at: datetime


# ------------------------------------------------------------------ bulk
class BulkPayload(BaseModel):
    """Upsert any mix of entities into ONE project, in one transaction.

    Upsert keys (all scoped to the project):
        targets   host
        services  (host, port, protocol)
        vulns     external_id when supplied, else (host, title)
        pocs      (host, title)

    Re-running an unchanged payload creates nothing. Rows whose host is not a
    valid host -- wildcards like `*.acme.example`, regex fragments, anything with
    whitespace -- are skipped and named in `errors`, rather than failing the
    batch.
    """
    project: str = Field(description="Project code, e.g. FALCON-1")
    create_project: bool = Field(
        default=True, description="Create the project if the code is unknown")
    project_name: str | None = Field(
        default=None, description="Name to use if the project is created")
    targets: list[TargetIn] = []
    services: list[ServiceIn] = []
    vulns: list[VulnIn] = []
    pocs: list[PocIn] = []
    autocreate_targets: bool = Field(
        default=True,
        description="Create a bare target for a host referenced only by a child row")

    @field_validator("project")
    @classmethod
    def _proj(cls, v: str) -> str:
        return v.strip().upper().replace(" ", "-")


class BulkResult(BaseModel):
    project: str
    created: dict[str, int]
    updated: dict[str, int]
    skipped: dict[str, int]
    errors: list[str]
    elapsed_ms: int


class Stats(BaseModel):
    projects: int
    targets: int
    hacked: int
    services: int
    open_ports: int
    vulns: int
    by_severity: dict[str, int]
    pocs: int


# ------------------------------------------------------------------ auth
class GroupOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    description: str | None = None


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str
    email: str | None = None
    full_name: str | None = None
    avatar_url: str | None = None
    #: Offered as the default when joining an engagement that uses Slack.
    slack_handle: str | None = None
    # Derived from membership of the site-admins group, not stored per user.
    is_site_admin: bool
    is_active: bool
    # Which sign-in methods actually work for this account.
    has_password: bool = False
    has_google: bool = False
    groups: list[GroupOut] = []
    created_at: datetime


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=8, description="minimum 8 characters")
    email: str | None = None
    full_name: str | None = None

    @field_validator("username")
    @classmethod
    def _u(cls, v: str) -> str:
        v = v.strip().lower()
        if not v.replace("-", "").replace("_", "").replace(".", "").isalnum():
            raise ValueError("username may contain only letters, digits, . _ -")
        return v


class UserUpdate(BaseModel):
    email: str | None = None
    full_name: str | None = None
    password: str | None = Field(default=None, min_length=8)
    is_active: bool | None = None


class GroupCreate(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    description: str | None = None


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserOut


class MeResponse(BaseModel):
    user: UserOut
    # project code -> effective role, so the UI can hide what it cannot use.
    projects: dict[str, str]


class AclGrant(BaseModel):
    role: str
    username: str | None = None
    group: str | None = None

    @field_validator("role")
    @classmethod
    def _r(cls, v: str) -> str:
        v = (v or "").strip().lower()
        if v not in ("readonly", "user", "admin"):
            raise ValueError("role must be readonly, user or admin")
        return v


class AclOut(BaseModel):
    id: int
    project_code: str
    role: str
    username: str | None = None
    group: str | None = None


class ApiKeyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    prefix: str
    revoked: bool
    last_used_at: datetime | None = None
    created_at: datetime


class ApiKeyCreated(ApiKeyOut):
    # Returned exactly once, at creation. Never retrievable afterwards.
    key: str


# ------------------------------------------------------------ web addresses
class WebAddressOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    target_id: int
    service_id: int | None = None
    host: str = ""
    project_code: str = ""
    url: str
    scheme: str = "http"
    port: int | None = None
    path: str = "/"
    method: str = ""
    status_code: int | None = None
    title: str | None = None
    content_type: str | None = None
    content_length: int | None = None
    webserver: str | None = None
    tech: list[str] = []
    sources: str | None = None
    crawled: bool = False
    notes: str | None = None
    created_at: datetime
    updated_at: datetime

    @field_validator("tech", mode="before")
    @classmethod
    def _tech(cls, v):
        return _as(v, list)


class WebPacket(BaseModel):
    """One exchange, fetched on demand.

    Deliberately not part of WebAddressOut: a 5,000-row listing carrying
    every request and response would be hundreds of megabytes, and these
    are only ever wanted one at a time.
    """
    id: int
    url: str
    method: str | None = None
    status_code: int | None = None
    host: str = ""
    request: str | None = None
    response: str | None = None
    truncated: bool = False
    sources: str | None = None
    notes: str | None = None


class WebAddressCreate(BaseModel):
    target_id: int
    url: str = Field(min_length=1, max_length=2048)
    method: str = ""
    status_code: int | None = None
    title: str | None = None
    notes: str | None = None
    crawled: bool = False


class WebAddressUpdate(BaseModel):
    status_code: int | None = None
    title: str | None = None
    notes: str | None = None
    crawled: bool | None = None


# ------------------------------------------------------- domain discovery
class DomainCandidateOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    root_domain: str
    source: str
    score: int
    reason: str | None = None
    state: str
    times_seen: int
    created_at: datetime


class DomainSearchOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    domain: str
    runs: int
    last_run_at: datetime | None = None
    candidates_found: int
    known_at_last_run: int
    note: str | None = None


class DetectRequest(BaseModel):
    """One or more domains. `domain` is kept for existing callers."""
    domain: str | None = Field(None, max_length=255)
    domains: list[str] = Field(default_factory=list, max_length=50)
    limit: int = Field(200, ge=1, le=1000)
    force: bool = Field(
        False, description="Re-run even for domains already searched")

    def wanted(self) -> list[str]:
        out, seen = [], set()
        for d in ([self.domain] if self.domain else []) + list(self.domains):
            v = (d or "").strip().rstrip(".").lower().lstrip("*.")
            if v and v not in seen:
                seen.add(v)
                out.append(v)
        return out


class DetectResult(BaseModel):
    domain: str
    candidates: list[DomainCandidateOut]
    new_candidates: int
    already_known: int = Field(
        0, description="Names skipped because they are already targets")
    previously_suggested: int = Field(
        0, description="Names skipped because an earlier run already proposed them")
    runs: int
    note: str | None = None
    error: str | None = None


class DetectBatch(BaseModel):
    """Per-domain results. One bad domain never costs you the others."""
    results: list[DetectResult]
    new_candidates: int = 0
    domains_run: int = 0
    domains_skipped: int = 0


class AgentOverride(BaseModel):
    """Per-project agent credentials. Blank means 'leave unchanged', the
    same write-only rule the Slack token and SMTP password follow."""
    agent_provider: str | None = None
    agent_anthropic_token: str | None = None
    agent_openai_token: str | None = None
    agent_model: str | None = None

    @field_validator("agent_provider")
    @classmethod
    def _prov(cls, v):
        if v in (None, ""):
            return None
        if v not in ("anthropic", "openai"):
            raise ValueError("provider must be 'anthropic' or 'openai'")
        return v


class PromoteRequest(BaseModel):
    ids: list[int] = Field(min_length=1, max_length=2000)


# -------------------------------------------------------------- implants
class ImplantOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    target_id: int
    host: str = ""
    project_code: str = ""
    framework: str
    implant_id: str
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
    extra: dict = {}
    created_at: datetime
    updated_at: datetime

    @field_validator("extra", mode="before")
    @classmethod
    def _extra_json(cls, v):
        return _as(v, dict)


# -------------------------------------------------------------- timeline
class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    target_id: int
    at: datetime
    kind: str
    summary: str
    detail: str | None = None
    actor: str | None = None
    source: str | None = None


class EventCreate(BaseModel):
    kind: str = "note"
    summary: str = Field(min_length=1, max_length=2000)
    detail: str | None = None
    source: str | None = None


class TargetDetail(BaseModel):
    """Everything about one target, in a single round trip.

    The host modal needs target + services + vulns + PoCs together; four
    separate fetches would mean four loading states and a visibly staggered
    render. The MCP get_target tool composes the same shape.
    """
    target: TargetOut
    services: list[ServiceOut]
    vulns: list[VulnOut]
    pocs: list[PocOut]
    implants: list[ImplantOut] = []


# --------------------------------------------------------------- explore
class NameCount(BaseModel):
    name: str
    count: int


class ExploreHost(BaseModel):
    host: str
    project_code: str
    port: int
    protocol: str
    state: str
    name: str | None = None
    banner: str | None = None
    vulns: int = 0
    criticals: int = 0


class ExploreOut(BaseModel):
    """Aggregate picture of one port, or one service name, across the estate."""
    dimension: str
    value: str
    protocol: str | None = None
    total_services: int
    total_hosts: int
    by_state: dict[str, int]
    service_names: list[NameCount]
    ports: list[NameCount]
    products: list[NameCount]
    banners: list[NameCount]
    vulns_total: int
    vulns_by_severity: dict[str, int]
    hosts: list[ExploreHost]
    truncated: bool = False


# --------------------------------------------------------------- actions
class ActionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    kind: str
    service_id: int
    status: str
    result: str | None = None
    error: str | None = None
    created_at: datetime
    finished_at: datetime | None = None


class ActionRequest(BaseModel):
    kind: str = Field(description="currently: grab_banner")


class ProfileUpdate(BaseModel):
    """Self-service edits. Deliberately excludes is_active and group
    membership: those are administrative, and a user editing their own
    authorisation is the whole problem."""
    full_name: str | None = None
    email: str | None = None
    #: The handle to offer when an engagement with Slack asks. Stored
    #: without the @, so the two spellings do not become two people.
    slack_handle: str | None = Field(default=None, max_length=128)
    new_password: str | None = Field(default=None, min_length=8)
    current_password: str | None = Field(
        default=None, description="required when changing an existing password")


class GoogleStatus(BaseModel):
    enabled: bool
    reason: str | None = None


# ----------------------------------------------------------- credentials
class CredentialBase(BaseModel):
    host: str | None = None
    service: str | None = None
    port: int | None = Field(default=None, ge=0, le=65535)
    username: str | None = None
    kind: str = "password"
    source: str | None = None
    validated: str = "none"
    notes: str | None = None

    @field_validator("kind")
    @classmethod
    def _k(cls, v: str) -> str:
        v = (v or "password").strip().lower()
        if v not in ("password", "hash", "key", "token", "cookie", "other"):
            raise ValueError("kind must be password, hash, key, token, cookie or other")
        return v

    @field_validator("validated")
    @classmethod
    def _v(cls, v: str) -> str:
        v = (v or "none").strip().lower()
        if v not in ("none", "works", "failed"):
            raise ValueError("validated must be none, works or failed")
        return v


class CredentialCreate(CredentialBase):
    secret: str | None = None


class CredentialUpdate(BaseModel):
    host: str | None = None
    service: str | None = None
    port: int | None = None
    username: str | None = None
    secret: str | None = None
    kind: str | None = None
    source: str | None = None
    validated: str | None = None
    notes: str | None = None


class CredentialOut(CredentialBase):
    model_config = ConfigDict(from_attributes=True)
    id: int
    project_id: int
    project_code: str
    # Withheld from readonly callers; `secret_set` still tells them one exists.
    secret: str | None = None
    secret_set: bool = False
    created_at: datetime
    updated_at: datetime


# ------------------------------------------------------- bulk edit/delete
class BulkIds(BaseModel):
    """Operate on many rows by id. `kind` names the table."""
    kind: Literal["targets", "services", "vulns", "pocs", "credentials"]
    ids: list[int] = Field(min_length=1, max_length=10000)


class BulkPatch(BulkIds):
    # Only keys present are written, so a bulk edit that sets one field does
    # not blank the others.
    fields: dict[str, object] = Field(min_length=1)


class BulkOpResult(BaseModel):
    kind: str
    requested: int
    changed: int
    skipped: int
    errors: list[str]


# ------------------------------------------------- project scope/contacts
class ScopeEntryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    kind: str
    value: str
    included: bool
    #: Operator-declared, never looked up. See models.ProjectScope.country.
    country: str | None = None
    notes: str | None = None


class ContactIn(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    email: str | None = None
    phone: str | None = None
    title: str | None = None
    primary_contact: bool = False
    notes: str | None = None


class ContactOut(ContactIn):
    model_config = ConfigDict(from_attributes=True)
    id: int


class MemberIn(BaseModel):
    """A team member and their role on the project.

    'viewer' is accepted as a friendlier spelling of the stored `readonly`
    role — the UI says Viewer, the database has always said readonly, and
    renaming the stored value would invalidate every existing ACL row.
    """
    username: str
    role: str = "readonly"

    @field_validator("role")
    @classmethod
    def _r(cls, v: str) -> str:
        v = (v or "readonly").strip().lower()
        v = {"viewer": "readonly", "read-only": "readonly"}.get(v, v)
        if v not in ("readonly", "user", "admin"):
            raise ValueError("role must be admin, user or viewer")
        return v


class ProjectCreateFull(ProjectCreate):
    """Everything the new-project modal collects, in one transaction."""
    # Free text, one entry per line. Kinds are derived, not supplied.
    scope: list[str] = []
    contacts: list[ContactIn] = []
    members: list[MemberIn] = []
    slack_token: str | None = Field(
        default=None, description="Per-project override; write-only, never returned")
    slack_channel: str | None = Field(
        default=None, description="Defaults to the site prefix plus the codename")
    slack_delivery: str = Field(
        default="site",
        description="site | override | both. 'both' posts to the site workspace "
                    "AND the override. Needs a token for anything but 'site'.")
    slack_private: bool | None = Field(
        default=None, description="None inherits the site default")

    @field_validator("slack_delivery")
    @classmethod
    def _delivery(cls, v: str) -> str:
        v = (v or "site").strip().lower()
        if v not in ("site", "override", "both"):
            raise ValueError("slack_delivery must be site, override or both")
        return v


class ProjectCreated(BaseModel):
    project: ProjectOut
    scope: list[ScopeEntryOut]
    contacts: list[ContactOut]
    members: list[AclOut]
    # Scope lines that could not be classified, named individually.
    scope_errors: list[str]
    member_errors: list[str]
