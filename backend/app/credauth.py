"""Build scanner authentication arguments from a target's credentials.

The operators' ask, in one sentence: if a credential is on file for the
target a task is about to touch, the task should carry it. Everything in
this module exists to make that true in exactly one place, so that the
standing orders and the manual queueing paths cannot disagree about what
"the target's credentials" means.

# What counts as "the target's credential"

The UNION of two facts:

  * a `TargetCredential` row links it to this target by id — the operator
    said so explicitly, whatever either of them is called; and
  * its free-text `host` equals the target's own name — the importer filed
    the find against the name, and the name IS the link.

Both are read together because each one alone misses real cases: a
credential found on `api.acme.example` must apply to the target named
`api.acme.example` without anyone remembering to tick a box, and a
credential whose recorded host is an address or a stale alias must still
apply when the operator has pointed it at the target by hand.

# What the arguments look like

The ghost's task runners already accept these keys — katana reads
`headers` and `cookies`, gobuster reads `username`, `password` and
`cookies`, httpx and nuclei read `-H` via `headerArgs`. Nothing downstream
of this module changes; it only decides what goes in the arguments.

Per credential, by kind:

  * password   user + secret -> Basic auth header, plus username/password
               (gobuster speaks HTTP basic natively and katana does not)
  * token      -> Bearer header
  * cookie     -> appended to `cookies`
  * key        -> Bearer header; a key is the closest thing to a bearer
               secret the catalogue has, and the operator can always say
               "other" and paste an exact header instead
  * other      -> the secret IS a raw "Name: value" header line; anything
               that does not parse as one is skipped rather than guessed
  * hash       -> nothing. A hash cannot be presented as a request
               without a cracking step this pipeline does not perform,
               and sending it somewhere would only leak it.

`extra_headers` on the credential's notes is deliberately NOT parsed: free
text that means different things to different people is not a field. The
"other" kind with a header line in `secret` covers the case where an
operator needs exactly one custom header, and it says so in the UI.

# What does NOT go through here

Non-web tasks (nmap, amass, nslookup) take no headers: adding credentials
to them would be arguments nothing reads. The caller asks only for kinds
that speak HTTP, which is also what keeps a task's arguments small enough
that the scope gate's `task_hosts` walk never sees a secret as a host.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field


@dataclass
class CredAuth:
    """The authentication one task should send, built from credentials."""
    headers: list[str] = field(default_factory=list)
    cookies: str | None = None
    username: str | None = None
    password: str | None = None

    def as_args(self) -> dict:
        """The keys a ghost task runner understands, minus the empties."""
        out: dict = {}
        if self.headers:
            out["headers"] = list(self.headers)
        if self.cookies:
            out["cookies"] = self.cookies
        if self.username is not None:
            out["username"] = self.username
        if self.password is not None:
            out["password"] = self.password
        return out


def _basic(username: str, secret: str) -> str:
    raw = f"{username}:{secret}".encode()
    return "Basic " + base64.b64encode(raw).decode("ascii")


def build_from_credentials(creds) -> CredAuth:
    """Fold a target's credentials into one set of task arguments.

    `creds` is any iterable of `Credential` rows — the caller has already
    done the matching, which keeps this function free of sessions and
    therefore trivially testable. Order matters only for cookies, where
    later entries are appended after earlier ones; a target with two
    session credentials sends both, which is what an operator who assigned
    both meant.
    """
    auth = CredAuth()
    for c in creds:
        kind = (c.kind or "password").lower()
        secret = (c.secret or "").strip()
        user = (c.username or "").strip()

        if not secret and not user:
            continue  # nothing to send; a row with no material is a note

        if kind == "cookie":
            # The whole credential IS the cookie line. `username`, when
            # present, names the cookie rather than an account, so it is
            # folded in as `name=value` — a session captured from Burp has
            # no username at all and this branch is just the secret.
            part = f"{user}={secret}" if user else secret
            auth.cookies = f"{auth.cookies}; {part}" if auth.cookies else part
        elif kind == "other":
            # A raw header line, exactly as pasted. Anything that does not
            # split on a colon is not a header and is skipped rather than
            # guessed: sending `Authorization: <garbage>` is worse than
            # sending nothing.
            if ":" in secret:
                auth.headers.append(secret)
        elif kind == "token" or kind == "key":
            auth.headers.append(f"Authorization: Bearer {secret}")
        else:
            # password (and hash, which still gets presented as basic auth
            # when it is an NTLM-over-HTTP digest the server will ask for —
            # but plain basic is what HTTP servers present first and what
            # katana can send).
            if user and secret:
                auth.headers.append(f"Authorization: {_basic(user, secret)}")
                auth.username = user
                auth.password = secret
            elif secret:
                # No username recorded. A password with no user cannot make
                # a basic-auth header (the base64 of ":secret" is a guess
                # about the account name), so it goes nowhere for now —
                # which is the honest answer rather than an invented one.
                pass
    return auth


def host_of(url: str) -> str | None:
    """The lowercase hostname in a url, or None when there is not one."""
    s = (url or "").strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in s:
        s = s.rsplit("@", 1)[1]
    host = s.split(":", 1)[0]
    return host.lower() or None


async def auth_args_for_host(session, project_id: int, host: str) -> dict:
    """The authentication arguments a task against `host` should carry.

    Reads the project's credentials once and returns the folded set for
    whatever names this host goes by: its own row name and every alternate
    hostname on it. An empty dict means "send nothing", which is the normal
    case and costs the caller one indexed lookup per cycle rather than one
    query per task.

    The `hostnames` column is read here rather than at the call sites
    because it is a JSON list and the matching rule — credential host equals
    ANY of the target's names — is exactly as likely to be implemented
    slightly differently twice as it is to be right once.
    """
    from sqlalchemy import select

    from .models import Credential, Target, TargetCredential

    host = (host or "").strip().lower()
    if not host:
        return {}

    t = (await session.execute(
        select(Target).where(Target.project_id == project_id,
                             Target.host == host))).scalar_one_or_none()
    if t is None:
        return {}

    names = {host}
    for n in (t.hostnames or []):
        n = str(n).strip().lower()
        if n:
            names.add(n)

    rows = (await session.execute(
        select(Credential).where(Credential.project_id == project_id))).scalars().all()

    linked_ids = {r.credential_id for r in (await session.execute(
        select(TargetCredential).where(
            TargetCredential.target_id == t.id))).scalars().all()}

    matched = [c for c in rows
               if c.id in linked_ids or (c.host or "").strip().lower() in names]
    return build_from_credentials(matched).as_args()


async def auth_args_for_hosts(session, project_id: int,
                              hosts: list[str]) -> dict[str, dict]:
    """`auth_args_for_host` for many hosts at once.

    The standing orders plan a whole project in one pass; asking per host
    would be one query pair per web URL, which on an estate with thousands
    of recorded URLs is the difference between a fast cycle and a slow one.
    """
    from sqlalchemy import select

    from .models import Credential, Target, TargetCredential

    hosts = sorted({h.strip().lower() for h in hosts if h and h.strip()})
    if not hosts:
        return {}

    targets = {t.host: t for t in (await session.execute(
        select(Target).where(Target.project_id == project_id,
                             Target.host.in_(hosts)))).scalars().all()}
    if not targets:
        return {}

    linked = (await session.execute(
        select(TargetCredential).where(
            TargetCredential.target_id.in_(t.id for t in targets.values()))
    )).scalars().all()
    linked_by_target: dict[int, set[int]] = {}
    for r in linked:
        linked_by_target.setdefault(r.target_id, set()).add(r.credential_id)

    creds = {c.id: c for c in (await session.execute(
        select(Credential).where(Credential.project_id == project_id))).scalars().all()}

    out: dict[str, dict] = {}
    for host, t in targets.items():
        names = {host}
        for n in (t.hostnames or []):
            n = str(n).strip().lower()
            if n:
                names.add(n)
        linked_ids = linked_by_target.get(t.id, set())
        matched = [c for c in creds.values()
                   if c.id in linked_ids
                   or (c.host or "").strip().lower() in names]
        args = build_from_credentials(matched).as_args()
        if args:
            out[host] = args
    return out

